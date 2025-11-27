// server.js - Main Backend Server for Freshno.Chat
// Install dependencies: npm install express socket.io bcryptjs jsonwebtoken cors dotenv

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// In-memory storage (replace with database later)
const users = new Map();
const messages = new Map();
const onlineUsers = new Map();
const roomAccess = new Map();

// Room configurations
const ROOMS = {
  public: { price: 0, maxUsers: Infinity, subRooms: 10 },
  private: { price: 10, maxUsers: 100, subRooms: 0 },
  special: { price: 50, maxUsers: 30, subRooms: 0 },
  vip: { price: 100, maxUsers: 10, subRooms: 0 }
};

// JWT Secret (should be in .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// ==================== AUTHENTICATION ====================

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate ProtonMail email
    if (!email.endsWith('@protonmail.com') && !email.endsWith('@proton.me')) {
      return res.status(400).json({ 
        error: 'Only ProtonMail addresses are allowed' 
      });
    }

    // Check if user exists
    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Validate password
    if (password.length < 8) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = {
      email,
      password: hashedPassword,
      createdAt: new Date(),
      rooms: ['public'] // Default access to public room
    };

    users.set(email, user);

    // Generate token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      success: true, 
      token,
      user: { email, rooms: user.rooms }
    });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate ProtonMail email
    if (!email.endsWith('@protonmail.com') && !email.endsWith('@proton.me')) {
      return res.status(400).json({ 
        error: 'Only ProtonMail addresses are allowed' 
      });
    }

    // Check if user exists
    const user = users.get(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      success: true, 
      token,
      user: { email, rooms: user.rooms || ['public'] }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userEmail = decoded.email;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ==================== ROOM ACCESS ====================

// Upload file endpoint
app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    res.json({
      success: true,
      file: {
        filename: req.file.originalname,
        url: fileUrl,
        size: req.file.size,
        mimetype: req.file.mimetype
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Check room access
app.get('/api/rooms/access', verifyToken, (req, res) => {
  const user = users.get(req.userEmail);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ 
    rooms: user.rooms || ['public'],
    available: Object.keys(ROOMS)
  });
});

// Purchase room access (placeholder for Bitcoin payment)
app.post('/api/rooms/purchase', verifyToken, async (req, res) => {
  try {
    const { room, bitcoinTxId } = req.body;

    if (!ROOMS[room]) {
      return res.status(400).json({ error: 'Invalid room' });
    }

    // TODO: Verify Bitcoin payment here
    // For now, we'll just simulate it
    
    const user = users.get(req.userEmail);
    if (!user.rooms) user.rooms = ['public'];
    
    if (!user.rooms.includes(room)) {
      user.rooms.push(room);
    }

    res.json({ 
      success: true, 
      message: `Access granted to ${room} room`,
      rooms: user.rooms
    });

  } catch (error) {
    console.error('Purchase error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== WEBSOCKET CHAT ====================

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication error'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userEmail = decoded.email;
    next();
  } catch (error) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.userEmail}`);
  
  // Add user to online users
  onlineUsers.set(socket.userEmail, {
    socketId: socket.id,
    email: socket.userEmail,
    currentRoom: null
  });

  // Join room
  socket.on('join-room', (roomName) => {
    const user = users.get(socket.userEmail);
    
    // Check if user exists
    if (!user) {
      socket.emit('error', { message: 'User not found' });
      return;
    }

    // Initialize rooms if not exists
    if (!user.rooms) {
      user.rooms = ['public'];
    }
    
    // Check if user has access to room
    const roomType = roomName.split('-')[0];
    if (!user.rooms.includes(roomType)) {
      socket.emit('error', { message: 'No access to this room' });
      return;
    }

    // Leave previous room
    const userInfo = onlineUsers.get(socket.userEmail);
    if (userInfo.currentRoom) {
      socket.leave(userInfo.currentRoom);
    }

    // Join new room
    socket.join(roomName);
    userInfo.currentRoom = roomName;

    // Get room user count
    const roomUsers = Array.from(onlineUsers.values())
      .filter(u => u.currentRoom === roomName).length;

    // Notify room
    io.to(roomName).emit('user-joined', {
      email: socket.userEmail,
      roomUsers
    });

    socket.emit('room-joined', { 
      room: roomName, 
      userCount: roomUsers 
    });
  });

  // Send message
  socket.on('send-message', (data) => {
    const userInfo = onlineUsers.get(socket.userEmail);
    
    if (!userInfo) {
      socket.emit('error', { message: 'User not found' });
      return;
    }

    const room = userInfo.currentRoom;

    if (!room) {
      socket.emit('error', { message: 'Not in a room' });
      return;
    }

    const message = {
      id: Date.now(),
      user: socket.userEmail.split('@')[0],
      text: data.message,
      room,
      timestamp: new Date()
    };

    // Store message
    if (!messages.has(room)) {
      messages.set(room, []);
    }
    messages.get(room).push(message);

    // Broadcast to room
    io.to(room).emit('new-message', message);
  });

  // File sharing
  socket.on('share-file', (data) => {
    const userInfo = onlineUsers.get(socket.userEmail);
    
    if (!userInfo) return;

    const room = userInfo.currentRoom;

    if (!room) return;

    io.to(room).emit('file-shared', {
      user: socket.userEmail.split('@')[0],
      fileName: data.fileName,
      fileUrl: data.fileUrl,
      fileSize: data.fileSize,
      fileType: data.fileType,
      timestamp: new Date()
    });
  });

  // WebRTC signaling for video/audio
  socket.on('webrtc-offer', (data) => {
    socket.to(data.to).emit('webrtc-offer', {
      from: socket.id,
      offer: data.offer
    });
  });

  socket.on('webrtc-answer', (data) => {
    socket.to(data.to).emit('webrtc-answer', {
      from: socket.id,
      answer: data.answer
    });
  });

  socket.on('webrtc-ice-candidate', (data) => {
    socket.to(data.to).emit('webrtc-ice-candidate', {
      from: socket.id,
      candidate: data.candidate
    });
  });

  // Disconnect
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.userEmail}`);
    
    const userInfo = onlineUsers.get(socket.userEmail);
    if (userInfo && userInfo.currentRoom) {
      io.to(userInfo.currentRoom).emit('user-left', {
        email: socket.userEmail
      });
    }

    onlineUsers.delete(socket.userEmail);
  });
});

// ==================== UTILITY ENDPOINTS ====================

// Get online users in room
app.get('/api/rooms/:room/users', verifyToken, (req, res) => {
  const room = req.params.room;
  const roomUsers = Array.from(onlineUsers.values())
    .filter(u => u.currentRoom === room)
    .map(u => ({ email: u.email }));

  res.json({ users: roomUsers, count: roomUsers.length });
});

// Get messages from room
app.get('/api/rooms/:room/messages', verifyToken, (req, res) => {
  const room = req.params.room;
  const roomMessages = messages.get(room) || [];
  
  res.json({ messages: roomMessages.slice(-50) }); // Last 50 messages
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'online', 
    users: users.size,
    onlineUsers: onlineUsers.size 
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`🚀 Freshno.Chat server running on port ${PORT}`);
  console.log(`💀 Backend ready for connections`);
});

// Export for testing
module.exports = { app, server, io };