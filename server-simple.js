/**
 * NearbyChat Backend - Simplified Version
 * This version uses in-memory storage (no PostgreSQL needed)
 * Perfect for development and testing
 * 
 * To run:
 * 1. npm init -y
 * 2. npm install express socket.io cors
 * 3. node server-simple.js
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { 
    origin: "*", 
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true
});

app.use(cors());
app.use(express.json());

// ============================================
// IN-MEMORY DATABASE (Replace with PostgreSQL later)
// ============================================

const db = {
  users: new Map(),
  conversations: new Map(),
  messages: new Map(),
  otpStore: new Map(), // Temporary OTP storage
};

// Helper to generate IDs
const generateId = () => Math.random().toString(36).substring(2, 15);

// Helper to generate random username
const generateUsername = () => {
  const adjectives = ['Happy', 'Lucky', 'Sunny', 'Cool', 'Swift', 'Bright', 'Calm', 'Bold', 'Wise', 'Kind'];
  const nouns = ['Panda', 'Tiger', 'Eagle', 'Wolf', 'Fox', 'Bear', 'Hawk', 'Lion', 'Deer', 'Owl'];
  return `${adjectives[Math.floor(Math.random() * adjectives.length)]}${nouns[Math.floor(Math.random() * nouns.length)]}${Math.floor(Math.random() * 1000)}`;
};

// Helper to calculate distance between two points (Haversine formula)
const calculateDistance = (lat1, lon1, lat2, lon2) => {
  const R = 6371e3; // Earth's radius in meters
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
};

// Format distance for display
const formatDistance = (meters) => {
  if (meters < 100) return 'Very close';
  if (meters < 1000) return `${Math.round(meters)}m away`;
  return `${(meters / 1000).toFixed(1)}km away`;
};

// Simple JWT-like token (for demo - use real JWT in production)
const createToken = (userId) => Buffer.from(JSON.stringify({ userId, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 })).toString('base64');
const verifyToken = (token) => {
  try {
    const data = JSON.parse(Buffer.from(token, 'base64').toString());
    if (data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
};

// Auth middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  req.user = decoded;
  next();
};

// ============================================
// AUTH ROUTES
// ============================================

// Request OTP
app.post('/api/auth/request-otp', (req, res) => {
  const { phone } = req.body;
  
  if (!phone || phone.length < 10) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }
  
  // Generate OTP (in production, send via SMS)
  const otp = '123456'; // Fixed for development
  db.otpStore.set(phone, { otp, expires: Date.now() + 5 * 60 * 1000 });
  
  console.log(`📱 OTP for ${phone}: ${otp}`);
  
  res.json({ 
    success: true, 
    message: 'OTP sent successfully',
    dev_otp: otp // Remove in production
  });
});

// Verify OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { phone, otp } = req.body;
  
  // For development, accept '123456'
  if (otp !== '123456') {
    return res.status(400).json({ error: 'Invalid OTP' });
  }
  
  // Find or create user
  let user = Array.from(db.users.values()).find(u => u.phone === phone);
  let isNewUser = false;
  
  if (!user) {
    user = {
      id: generateId(),
      phone,
      username: generateUsername(),
      verificationLevel: 1,
      karmaScore: 100,
      location: null,
      isOnline: true,
      isVisible: true,
      discoveryRadius: 5000,
      createdAt: new Date().toISOString()
    };
    db.users.set(user.id, user);
    isNewUser = true;
    console.log(`✨ New user created: ${user.username}`);
  }
  
  const token = createToken(user.id);
  
  res.json({
    success: true,
    isNewUser,
    token,
    user: {
      id: user.id,
      username: user.username,
      verificationLevel: user.verificationLevel,
      karmaScore: user.karmaScore
    }
  });
});

// Verify token
app.get('/api/auth/verify-token', authMiddleware, (req, res) => {
  const user = db.users.get(req.user.userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }
  res.json({
    valid: true,
    user: {
      id: user.id,
      username: user.username,
      verificationLevel: user.verificationLevel,
      karmaScore: user.karmaScore
    }
  });
});

// ============================================
// USER ROUTES
// ============================================

// Update location
app.post('/api/users/location', authMiddleware, (req, res) => {
  const { latitude, longitude } = req.body;
  const user = db.users.get(req.user.userId);
  
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  user.location = { latitude, longitude, updatedAt: new Date().toISOString() };
  user.isOnline = true;
  
  console.log(`📍 ${user.username} updated location: ${latitude}, ${longitude}`);
  
  res.json({ success: true });
});

// Update username
app.post('/api/users/username', authMiddleware, (req, res) => {
  const { username } = req.body;
  const user = db.users.get(req.user.userId);
  
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  // Check if username taken
  const taken = Array.from(db.users.values()).find(u => u.username === username && u.id !== user.id);
  if (taken) {
    return res.status(400).json({ error: 'Username already taken' });
  }
  
  user.username = username;
  res.json({ success: true, username });
});

// Get profile
app.get('/api/users/profile', authMiddleware, (req, res) => {
  const user = db.users.get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  res.json({
    id: user.id,
    username: user.username,
    verificationLevel: user.verificationLevel,
    karmaScore: user.karmaScore,
    discoveryRadius: user.discoveryRadius,
    isVisible: user.isVisible
  });
});

// Update visibility (ghost mode)
app.post('/api/users/visibility', authMiddleware, (req, res) => {
  const { isVisible } = req.body;
  const user = db.users.get(req.user.userId);
  
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  user.isVisible = isVisible;
  res.json({ success: true, isVisible });
});

// ============================================
// MATCH ROUTES
// ============================================

// Get nearby users
app.get('/api/match/nearby', authMiddleware, (req, res) => {
  const { latitude, longitude, radius = 5000 } = req.query;
  const userId = req.user.userId;
  const user = db.users.get(userId);
  
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const lat = parseFloat(latitude);
  const lng = parseFloat(longitude);
  const searchRadius = parseInt(radius);
  
  // Find nearby users
  const nearbyUsers = Array.from(db.users.values())
    .filter(u => {
      if (u.id === userId) return false;
      if (!u.isVisible) return false;
      if (!u.location) return false;
      
      const distance = calculateDistance(lat, lng, u.location.latitude, u.location.longitude);
      return distance <= searchRadius;
    })
    .map(u => {
      const distance = calculateDistance(lat, lng, u.location.latitude, u.location.longitude);
      return {
        id: u.id,
        username: u.username,
        verificationLevel: u.verificationLevel,
        karmaScore: u.karmaScore,
        distance: Math.round(distance),
        distanceText: formatDistance(distance),
        isOnline: u.isOnline
      };
    })
    .sort((a, b) => a.distance - b.distance)
    .slice(0, 50);
  
  res.json({ users: nearbyUsers });
});

// Start chat
app.post('/api/match/start-chat', authMiddleware, (req, res) => {
  const { targetUserId } = req.body;
  const userId = req.user.userId;
  
  // Check for existing conversation
  let conversation = Array.from(db.conversations.values()).find(c =>
    (c.user1Id === userId && c.user2Id === targetUserId) ||
    (c.user1Id === targetUserId && c.user2Id === userId)
  );
  
  if (conversation) {
    return res.json({ conversationId: conversation.id, existing: true });
  }
  
  // Create new conversation
  conversation = {
    id: generateId(),
    user1Id: userId,
    user2Id: targetUserId,
    status: 'active',
    createdAt: new Date().toISOString(),
    lastMessageAt: new Date().toISOString()
  };
  
  db.conversations.set(conversation.id, conversation);
  db.messages.set(conversation.id, []);
  
  console.log(`💬 New conversation started: ${conversation.id}`);
  
  res.json({ conversationId: conversation.id, existing: false });
});

// Get conversations
app.get('/api/match/conversations', authMiddleware, (req, res) => {
  const userId = req.user.userId;
  
  const conversations = Array.from(db.conversations.values())
    .filter(c => c.user1Id === userId || c.user2Id === userId)
    .map(c => {
      const otherUserId = c.user1Id === userId ? c.user2Id : c.user1Id;
      const otherUser = db.users.get(otherUserId);
      const messages = db.messages.get(c.id) || [];
      const unreadCount = messages.filter(m => m.senderId !== userId && !m.isRead).length;
      
      return {
        id: c.id,
        otherUser: {
          id: otherUser?.id,
          username: otherUser?.username || 'Unknown',
          isOnline: otherUser?.isOnline || false,
          verificationLevel: otherUser?.verificationLevel || 1
        },
        lastMessageAt: c.lastMessageAt,
        unreadCount
      };
    })
    .sort((a, b) => new Date(b.lastMessageAt) - new Date(a.lastMessageAt));
  
  res.json({ conversations });
});

// Get conversation messages
app.get('/api/match/conversation/:conversationId', authMiddleware, (req, res) => {
  const { conversationId } = req.params;
  const userId = req.user.userId;
  
  const conversation = db.conversations.get(conversationId);
  if (!conversation) {
    return res.status(404).json({ error: 'Conversation not found' });
  }
  
  // Verify user is part of conversation
  if (conversation.user1Id !== userId && conversation.user2Id !== userId) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const otherUserId = conversation.user1Id === userId ? conversation.user2Id : conversation.user1Id;
  const otherUser = db.users.get(otherUserId);
  const messages = (db.messages.get(conversationId) || []).map(m => ({
    ...m,
    isMe: m.senderId === userId
  }));
  
  // Mark as read
  messages.forEach(m => {
    if (m.senderId !== userId) m.isRead = true;
  });
  
  res.json({
    conversation: { id: conversation.id, status: conversation.status },
    otherUser: {
      id: otherUser?.id,
      username: otherUser?.username || 'Unknown',
      verificationLevel: otherUser?.verificationLevel || 1
    },
    messages
  });
});

// ============================================
// SOCKET.IO - REAL-TIME CHAT
// ============================================

const userSockets = new Map(); // userId -> socketId

io.on('connection', (socket) => {
  console.log(`🔌 Socket connected: ${socket.id}`);
  
  // Authenticate
  socket.on('authenticate', (token) => {
    const decoded = verifyToken(token);
    if (!decoded) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    
    socket.userId = decoded.userId;
    userSockets.set(decoded.userId, socket.id);
    
    const user = db.users.get(decoded.userId);
    if (user) {
      user.isOnline = true;
      console.log(`✅ ${user.username} authenticated`);
    }
    
    socket.emit('authenticated', { success: true });
  });
  
  // Join conversation
  socket.on('join_conversation', ({ conversationId }) => {
    socket.join(`conversation:${conversationId}`);
    socket.currentConversation = conversationId;
    console.log(`👥 User joined conversation: ${conversationId}`);
  });
  
  // Leave conversation
  socket.on('leave_conversation', ({ conversationId }) => {
    socket.leave(`conversation:${conversationId}`);
    socket.currentConversation = null;
  });
  
  // Send message
  socket.on('send_message', ({ conversationId, content, messageType = 'text' }) => {
    if (!socket.userId) return;
    
    const user = db.users.get(socket.userId);
    if (!user) return;
    
    const conversation = db.conversations.get(conversationId);
    if (!conversation) return;
    
    // Create message
    const message = {
      id: generateId(),
      conversationId,
      senderId: socket.userId,
      senderUsername: user.username,
      content,
      messageType,
      isRead: false,
      createdAt: new Date().toISOString()
    };
    
    // Store message
    if (!db.messages.has(conversationId)) {
      db.messages.set(conversationId, []);
    }
    db.messages.get(conversationId).push(message);
    
    // Update conversation
    conversation.lastMessageAt = message.createdAt;
    
    // Broadcast to conversation room
    io.to(`conversation:${conversationId}`).emit('new_message', message);
    
    console.log(`💬 Message in ${conversationId}: ${content.substring(0, 30)}...`);
  });
  
  // Typing indicators
  socket.on('typing', ({ conversationId }) => {
    if (!socket.userId) return;
    const user = db.users.get(socket.userId);
    socket.to(`conversation:${conversationId}`).emit('user_typing', {
      userId: socket.userId,
      username: user?.username
    });
  });
  
  socket.on('stop_typing', ({ conversationId }) => {
    socket.to(`conversation:${conversationId}`).emit('user_stop_typing', {
      userId: socket.userId
    });
  });
  
  // Disconnect
  socket.on('disconnect', () => {
    if (socket.userId) {
      userSockets.delete(socket.userId);
      const user = db.users.get(socket.userId);
      if (user) {
        user.isOnline = false;
        console.log(`📴 ${user.username} disconnected`);
      }
    }
  });
});

// ============================================
// HEALTH CHECK & START SERVER
// ============================================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    users: db.users.size,
    conversations: db.conversations.size
  });
});

// API documentation
app.get('/', (req, res) => {
  res.json({
    name: 'NearbyChat API',
    version: '1.0.0',
    endpoints: {
      auth: {
        'POST /api/auth/request-otp': 'Request OTP (body: { phone })',
        'POST /api/auth/verify-otp': 'Verify OTP (body: { phone, otp })',
        'GET /api/auth/verify-token': 'Verify token (header: Authorization: Bearer <token>)'
      },
      users: {
        'POST /api/users/location': 'Update location (body: { latitude, longitude })',
        'POST /api/users/username': 'Update username (body: { username })',
        'GET /api/users/profile': 'Get profile'
      },
      match: {
        'GET /api/match/nearby': 'Get nearby users (query: latitude, longitude, radius)',
        'POST /api/match/start-chat': 'Start chat (body: { targetUserId })',
        'GET /api/match/conversations': 'List conversations',
        'GET /api/match/conversation/:id': 'Get conversation messages'
      }
    },
    socket_events: {
      client_to_server: ['authenticate', 'join_conversation', 'send_message', 'typing', 'stop_typing'],
      server_to_client: ['authenticated', 'new_message', 'user_typing', 'user_stop_typing']
    }
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║           🚀 NearbyChat Server Started 🚀            ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║   HTTP API:    http://localhost:${PORT}                 ║
║   WebSocket:   ws://localhost:${PORT}                   ║
║   Health:      http://localhost:${PORT}/health          ║
║                                                      ║
║   📱 Test OTP: 123456                                ║
║                                                      ║
║   This is the simplified version (in-memory DB).     ║
║   Data resets when server restarts.                  ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
  `);
});
