const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mysql = require('mysql');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.json());
app.use(express.static('public')); // Serve static files from the 'public' directory

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'chatroom'
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// User registration
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
    const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    db.query(query, [username, password, email], (err, result) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        res.send({ message: 'User registered successfully', userId: result.insertId });
    });
});

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    db.query(query, [username, password], (err, results) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        if (results.length > 0) {
            const userId = results[0].id;
            const getMessagesQuery = 'SELECT * FROM messages WHERE sender_id = ? OR receiver_id = ? ORDER BY timestamp ASC';
            db.query(getMessagesQuery, [userId, userId], (msgErr, messages) => {
                if (msgErr) {
                    res.status(500).send(msgErr.message);
                    return;
                }
                const getUsersQuery = 'SELECT id, username FROM users WHERE id != ?';
                db.query(getUsersQuery, [userId], (usersErr, users) => {
                    if (usersErr) {
                        res.status(500).send(usersErr.message);
                        return;
                    }
                    res.send({ message: 'Login successful', userId, messages, users });
                });
            });
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// Get users list
app.get('/users', (req, res) => {
    const query = 'SELECT id, username FROM users';
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        res.send(results);
    });
});

// Socket.IO for real-time messaging
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });

    socket.on('sendMessage', ({ senderId, receiverId, content, type }) => {
        const query = 'INSERT INTO messages (sender_id, receiver_id, content, type) VALUES (?, ?, ?, ?)';
        db.query(query, [senderId, receiverId, content, type], (err, result) => {
            if (err) {
                console.error('Error saving message:', err);
                return;
            }
            const messageId = result.insertId;
            io.emit('receiveMessage', { messageId, senderId, receiverId, content, type, timestamp: new Date() });
        });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
