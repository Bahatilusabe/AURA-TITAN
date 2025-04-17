const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.get('/', (req, res) => {
    res.send('SOC Dashboard Backend is running!');
});

// Example endpoint to fetch logs
app.get('/logs', (req, res) => {
    const logs = [
        { id: 1, message: 'Connection from 192.168.1.1', timestamp: '2025-04-06T12:00:00Z' },
        { id: 2, message: 'Connection from 192.168.1.2', timestamp: '2025-04-06T12:05:00Z' },
    ];
    res.json(logs);
});

// Example endpoint to fetch alerts
app.get('/alerts', (req, res) => {
    const alerts = [
        { id: 1, type: 'Anomaly', message: 'High MSE detected', timestamp: '2025-04-06T12:10:00Z' },
        { id: 2, type: 'Threat', message: 'Malicious IP detected', timestamp: '2025-04-06T12:15:00Z' },
    ];
    res.json(alerts);
});

// Example endpoint for user login
app.post('/users/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'password') {
        res.json({ success: true, token: 'fake-jwt-token' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: 'http://localhost:3000', // Allow requests from the frontend
    },
});

// Emit logs and alerts in real-time
setInterval(() => {
    const log = { id: Date.now(), message: 'New connection detected', timestamp: new Date().toISOString() };
    io.emit('log', log);
}, 5000); // Emit a new log every 5 seconds

setInterval(() => {
    const alert = { id: Date.now(), type: 'Threat', message: 'Suspicious activity detected', timestamp: new Date().toISOString() };
    io.emit('alert', alert);
}, 10000); // Emit a new alert every 10 seconds

// Handle WebSocket connections
io.on('connection', (socket) => {
    console.log('A user connected');
    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});