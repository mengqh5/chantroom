const express = require('express')
const WebSocket = require('ws')
const path = require('path')

const app = express()
const PORT = 3000

// 静态文件服务
app.use(express.static(path.join(__dirname, '../../public')))

// 创建HTTP服务器
const server = app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`)
})

// 创建WebSocket服务器
const wss = new WebSocket.Server({ server })

// 客户端连接管理
const clients = new Map()

wss.on('connection', (ws) => {
  const id = uuidv4()
  clients.set(id, ws)
  
  console.log(`New client connected: ${id}`)
  
  ws.on('message', (message) => {
    try {
      const parsedMsg = JSON.parse(message)
      // 广播消息给所有客户端
      broadcastMessage(message, id)
    } catch (e) {
      console.error('Invalid message format:', message)
    }
  })

  ws.on('close', () => {
    clients.delete(id)
    console.log(`Client disconnected: ${id}`)
  })
})

function broadcastMessage(message, senderId) {
  clients.forEach((client, id) => {
    if (id !== senderId) {
      client.send(message)
    }
  })
}

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}
