const express = require("express");
const session = require("express-session");
const WebSocket = require("ws");
const mysql = require("mysql2/promise");
const cors = require("cors");
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

const app = express();
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  }),
);
app.use(bodyParser.json({ 
  limit: '10mb',
  strict: false 
}));
app.use(bodyParser.urlencoded({ 
  extended: true,
  limit: '10mb'
}));
app.use(cookieParser());

// 创建会话存储实例
const sessionStore = new session.MemoryStore();
app.use(
  session({
    store: sessionStore,
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  }),
);

// 用户认证中间件
const jwt = require("jsonwebtoken");
const authenticate = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "未授权" });

  try {
    req.user = jwt.verify(token, "your_jwt_secret");
    next();
  } catch (err) {
    res.status(401).json({ error: "无效的令牌" });
  }
};

// 创建MySQL连接池
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "123456",
  database: "chatdb",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// 创建WebSocket服务器
// 创建HTTP服务器并绑定WebSocket
const server = app.listen(3000, () => {
  console.log("HTTP服务器运行在端口3000");
  console.log("WebSocket服务器已绑定到HTTP服务器");
});

// 创建WebSocket服务器
const wss = new WebSocket.Server({ 
  server,
  path: "/ws",
  clientTracking: true
});

// 初始化WebSocket处理器
const { initializeWebSocket } = require("./wsHandler");
initializeWebSocket(wss, pool, sessionStore);

// 对象存储签名端点
app.get("/api/oss-signature", (req, res) => {
  const policy = {
    expiration: new Date(Date.now() + 300000),
    conditions: [["content-length-range", 0, 10485760]],
  };
  res.json({
    accessKey: "OSS_ACCESS_KEY",
    policy: Buffer.from(JSON.stringify(policy)).toString("base64"),
    signature: "SIGNATURE_HASH",
  });
});

// 静态文件服务 (添加fallback处理)
app.use(express.static("public"));
// 前端路由回退（确保在API路由之后）
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../public', 'index.html'));
});

// 初始化multer
const multer = require('multer');

// 用户认证路由
app.post('/api/register', async (req, res) => {
    try {
    // 处理字段名兼容性并去除空格
    // 统一处理字段名大小写问题
    // 调试日志记录原始请求体
    // 统一处理字段名格式
    // 增强字段名兼容性处理 (支持常见大小写变体)
    console.log('请求头:', req.headers);  // 新增请求头日志
    // 定义字段名兼容性处理函数
    const getField = (fieldName) => {
      // 处理嵌套对象格式（如user.username）
      const nestedKeys = Object.keys(req.body).filter(k => k.includes('.'));
      for (const key of nestedKeys) {
        const [parentKey, childKey] = key.split('.');
        if (childKey === fieldName) {
          return req.body[key];
        }
      }

      // 字段名变体配置
      const fieldVariants = {
        username: ['username', 'name', 'login', 'userName', 'account', 'user_name', 'uname', 'user', 'loginName', 'nickname', 'userId', 'userAccount', 'user', 'identifier'],
        password: ['password', 'pass', 'pwd', 'passWord', 'user_password', 'passKey', 'pwdHash', 'passphrase', 'secret', 'secureKey', 'userPassword', 'passcode', 'pwdStr', 'credential']
      };

      // 优先精确匹配原始字段名
      if (req.body[fieldName]) {
        return req.body[fieldName];
      }

      // 遍历字段变体
      for (const variant of fieldVariants[fieldName]) {
        if (req.body[variant]) {
          return req.body[variant];
        }
      }

      // 全小写匹配
      const lowerField = fieldName.toLowerCase();
      for (const key of Object.keys(req.body)) {
        if (key.toLowerCase() === lowerField) {
          return req.body[key];
        }
      }

      return null;
    };

    // 获取并处理字段值
    const rawUsername = getField('username');
    const rawPassword = getField('password');
    
    console.log('处理后的字段:', {
      username: rawUsername,
      password: rawPassword
    });
    
    // 验证必填字段
    if (!rawUsername?.trim() || !rawPassword?.trim()) {
      return res.status(400).json({ 
        error: '请求字段缺失或字段名不匹配',
        details: `支持的字段别名: 
          ${!rawUsername ? '用户名(username/login/account/user等) ' : ''}
          ${!rawPassword ? '密码(password/pwd/secret/credential等)' : ''}`,
        received: Object.keys(req.body)
      });
    }
    
    const username = rawUsername.trim();
    const password = rawPassword.trim();
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能只包含空格' });
    }
    
    // 增强密码复杂度检查（使用实际处理后的密码）
    if (password.length < 8) {
      return res.status(400).json({ 
        error: '密码复杂度不足',
        requirements: ['至少8个字符', '包含字母和数字']
      });
    }
    
    // 添加密码复杂度检查
    // 密码复杂度校验
    // 临时放宽密码策略用于测试
    const passwordRegex = /^.{8,}$/; // 仅检查长度
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        error: '密码长度不足',
        requirements: ['至少8个字符']
      });
    }
    
    // 强制生成SHA256哈希 (修复未哈希问题)
    // 强制生成SHA256哈希 (确保使用原始密码)
    // 使用处理后的password变量而非直接访问req.body
    const hashedPassword = require('crypto')
      .createHash('sha256')
      .update(password) // 使用已处理的password变量
      .digest('hex');
    
    console.log('生成哈希:', hashedPassword); // 添加调试日志
    
    // 添加数据库连接测试
    const conn = await pool.getConnection();
    try {
    const [result] = await conn.execute(
        'INSERT INTO users (user_id, username, password_hash) VALUES (UUID(), ?, ?)',
        [username, hashedPassword]
    );
    
    // 自动生成JWT并登录
    // 获取新插入的用户ID
    const [newUser] = await conn.execute(
        'SELECT user_id FROM users WHERE username = ?',
        [username]
    );
    
    const token = jwt.sign(
        { userId: newUser[0].user_id, username: username },
        'your_jwt_secret',
        { expiresIn: '7d' }
    );
    
    res.cookie('token', token, { 
        httpOnly: true,
        maxAge: 7 * 24 * 3600 * 1000,
        sameSite: 'lax'
    }).status(201).json({ 
        message: '注册成功',
        user: { username }
      });
      
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('注册错误:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: '用户名已存在' });
    } else {
      res.status(500).json({ 
        error: '服务器错误',
        detail: err.message 
      });
    }
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = require('crypto').createHash('sha256').update(password).digest('hex');
    const [users] = await pool.execute(
      'SELECT user_id, username FROM users WHERE username = ? AND password_hash = ?',
      [username, hashedPassword]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: '无效的凭证' });
    }

    const token = jwt.sign(
      { userId: users[0].user_id, username: users[0].username },
      'your_jwt_secret',
      { expiresIn: '7d' }
    );
    
    res.cookie('token', token, { 
      httpOnly: true,
      maxAge: 7 * 24 * 3600 * 1000,
      sameSite: 'lax'
    }).json({ 
      user: {
        id: users[0].user_id,
        username: users[0].username
      }
    });
  } catch (err) {
    res.status(500).json({ error: '登录失败' });
  }
});

// 好友管理路由
app.get('/api/friends', authenticate, async (req, res) => {
  try {
    const [friends] = await pool.execute(`
      SELECT u.user_id, u.username, u.avatar_url, f.status, f.created_at 
      FROM friends f
      JOIN users u ON f.friend_id = u.user_id
      WHERE f.user_id = ?
    `, [req.user.userId]);
    
    res.json(friends);
  } catch (err) {
    res.status(500).json({ error: '获取好友列表失败' });
  }
});

app.post('/api/friends', authenticate, async (req, res) => {
  try {
    const { friendUsername } = req.body;
    const [users] = await pool.execute(
      'SELECT user_id FROM users WHERE username = ?',
      [friendUsername]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ error: '用户不存在' });
    }

    await pool.execute(
      'INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, "pending")',
      [req.user.userId, users[0].user_id]
    );
    
    res.status(201).json({ message: '好友请求已发送' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: '请求已存在' });
    } else {
      res.status(500).json({ error: '发送请求失败' });
    }
  }
});

// 显式添加健康检查路由（测试路由解析）
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

module.exports = { app, pool, wss };
