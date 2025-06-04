const WebSocket = require("ws");

const jwt = require('jsonwebtoken');

function initializeWebSocket(wss, pool, sessionStore) {
  const userConnections = new Map();

  wss.on("connection", async (ws, req) => {
    // 从cookie获取token
    const cookies = req.headers.cookie?.split(';').reduce((acc, cookie) => {
      const [name, value] = cookie.trim().split('=');
      acc[name] = decodeURIComponent(value);
      return acc;
    }, {});

    const token = cookies?.token;
    if (!token) {
      ws.close(1008, '未授权访问');
      return;
    }

    try {
      const decoded = jwt.verify(token, 'your_jwt_secret');
      const userId = decoded.userId;
      userConnections.set(userId, ws);

      ws.userId = userId;
      // 实时查询数据库获取最新用户名
      const [user] = await pool.execute(
        'SELECT username FROM users WHERE user_id = ?',
        [userId]
      );
      ws.username = user[0].username;

      // 通知好友上线状态
      broadcastToFriends(userId, 'online');

      // 消息处理器
      ws.on("message", async (data) => {
        try {
          const msg = JSON.parse(data);

          // 处理好友请求接受
          if (msg.type === 'accept-friend') {
            await pool.execute(
              `UPDATE friends SET status='accepted' 
               WHERE user_id=? AND friend_id=?`,
              [msg.fromId, userId]
            );
            
            // 通知双方
            const [friend] = await pool.execute(
              'SELECT username FROM users WHERE user_id=?',
              [msg.fromId]
            );
            
            sendToUser(msg.fromId, {
              type: 'friend-update',
              status: 'accepted',
              friendId: userId,
              username: user[0].username
            });

            ws.send(JSON.stringify({
              type: 'friend-update',
              status: 'accepted',
              friendId: msg.fromId,
              username: friend[0].username
            }));
            return;
          }

          // 生成会话ID（私聊：排序后的用户ID组合）
          const sessionId = msg.chatType === 'private' 
            ? [msg.targetId, userId].sort().join('_')
            : msg.sessionId;

          // 消息持久化
          const [result] = await pool.execute(
            `INSERT INTO messages 
             (session_id, sender_id, content_type, content) 
             VALUES (?, ?, ?, ?)`,
            [sessionId, userId, msg.type, msg.content]
          );

          // 实时查询最新用户名（使用不同变量名避免作用域冲突）
          const [currentUser] = await pool.execute(
            'SELECT username FROM users WHERE user_id = ?',
            [userId]
          );
          
          // 构造广播消息体
          const broadcastMsg = {
            ...msg,
            sessionId: sessionId,
            messageId: result.insertId,
            sender_name: currentUser[0].username, // 数据库实时用户名
            senderId: userId,
            timestamp: new Date().toISOString(),
            isGroup: msg.chatType === 'group'
          };

          // 消息路由
          if (msg.chatType === 'private') {
            // 私聊发送给双方
            sendToUser(msg.targetId, broadcastMsg);
            ws.send(JSON.stringify(broadcastMsg)); // 回发给发送者
          } else {
            // 群聊广播给所有在线用户
            wss.clients.forEach(client => {
              if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(broadcastMsg));
              }
            });
          }
        } catch (err) {
          console.error("消息处理异常:", err);
          ws.send(JSON.stringify({
            type: "error",
            message: "消息处理失败"
          }));
        }
      });

      // 历史消息加载
      const loadHistory = async () => {
        try {
          // 加载群聊历史
          const [groupMessages] = await pool.execute(
            `SELECT * FROM messages 
             WHERE session_id = 'general'
             ORDER BY created_at DESC 
             LIMIT 50`
          );

          // 加载私聊历史
          const [friends] = await pool.execute(
            `SELECT friend_id FROM friends 
             WHERE user_id = ? AND status = 'accepted'`,
            [userId]
          );

          const privateMessages = await Promise.all(friends.map(async friend => {
            const sessionId = [userId, friend.friend_id].sort().join('_');
          const [messages] = await pool.execute(
            `SELECT m.*, u.username as sender_name 
             FROM messages m
             JOIN users u ON m.sender_id = u.user_id
             WHERE session_id = ?
             ORDER BY created_at DESC 
             LIMIT 20`,
            [sessionId]
          );
            return messages;
          }));

          ws.send(JSON.stringify({
            type: "history",
            group: groupMessages,
            private: privateMessages.flat()
          }));

        } catch (err) {
          console.error("历史记录加载失败:", err);
        }
      };


      // 连接关闭处理
      ws.on("close", () => {
        userConnections.delete(userId);
        broadcastToFriends(userId, 'offline');
        console.log(`用户 ${decoded.username} 断开连接`);
      });

      // 辅助函数
      function sendToUser(targetId, message) {
        const targetWs = userConnections.get(targetId);
        if (targetWs?.readyState === WebSocket.OPEN) {
          targetWs.send(JSON.stringify(message));
        }
      }

      function broadcastToFriends(userId, status) {
        pool.execute(
          `SELECT friend_id FROM friends 
           WHERE user_id=? AND status='accepted'`,
          [userId]
        ).then(([friends]) => {
          friends.forEach(friend => {
            sendToUser(friend.friend_id, {
              type: 'presence',
              userId: userId,
              status: status
            });
          });
        });
      }
    } catch (err) {
      ws.close(1008, '令牌验证失败');
    }
  }); // 关闭connection回调
} // 关闭wss.on

module.exports = { initializeWebSocket };
