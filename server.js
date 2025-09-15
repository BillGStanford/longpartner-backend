const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'https://longpartner.vercel.app',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://longpartner.vercel.app',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// In-memory storage
const adminSessions = new Map(); // adminId -> [{ socketId, userId, character, ip, scenario }]
const waitingUsers = []; // Queue of users waiting for admin
const bannedIPs = new Set(); // Set of banned IP addresses
const tempBans = new Map(); // IP -> { until: timestamp, reason: string }
const connectedUsers = new Map(); // socketId -> { userId, ip, character, scenario }
const admins = new Map(); // socketId -> { adminId, isAvailable, currentUsers: [] }
const messageStatus = new Map(); // messageId -> { isRead: boolean }

// Admin authentication
const ADMIN_TOKENS = process.env.ADMIN_TOKENS ? process.env.ADMIN_TOKENS.split(',') : ['admin123', 'admin456', 'admin789'];

// Middleware to check IP bans
const checkBanStatus = (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  
  if (bannedIPs.has(clientIP)) {
    return res.status(403).json({ error: 'IP address is permanently banned' });
  }
  
  if (tempBans.has(clientIP)) {
    const ban = tempBans.get(clientIP);
    if (Date.now() < ban.until) {
      return res.status(403).json({ 
        error: 'IP address is temporarily banned', 
        reason: ban.reason,
        until: new Date(ban.until).toISOString()
      });
    } else {
      tempBans.delete(clientIP);
    }
  }
  
  next();
};

app.use(checkBanStatus);

// Routes
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/admin/login', (req, res) => {
  const { token } = req.body;
  if (ADMIN_TOKENS.includes(token)) {
    const adminId = uuidv4();
    res.json({ success: true, adminId });
  } else {
    res.status(401).json({ error: 'Invalid admin token' });
  }
});

app.post('/admin/ban', (req, res) => {
  const { adminToken, ip, type, duration, reason } = req.body;
  
  if (!ADMIN_TOKENS.includes(adminToken)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  if (type === 'permanent') {
    bannedIPs.add(ip);
    io.sockets.sockets.forEach((socket) => {
      if (socket.handshake.address === ip) {
        socket.emit('banned', { type: 'permanent', reason });
        socket.disconnect();
      }
    });
    res.json({ success: true, message: 'IP permanently banned' });
  } else if (type === 'temporary') {
    const until = Date.now() + (duration * 60 * 1000);
    tempBans.set(ip, { until, reason });
    io.sockets.sockets.forEach((socket) => {
      if (socket.handshake.address === ip) {
        socket.emit('banned', { type: 'temporary', reason, until: new Date(until).toISOString() });
        socket.disconnect();
      }
    });
    res.json({ success: true, message: 'IP temporarily banned', until: new Date(until).toISOString() });
  } else {
    res.status(400).json({ error: 'Invalid ban type' });
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  const clientIP = socket.handshake.address;
  
  if (bannedIPs.has(clientIP)) {
    socket.emit('banned', { type: 'permanent', reason: 'IP permanently banned' });
    socket.disconnect();
    return;
  }
  
  if (tempBans.has(clientIP)) {
    const ban = tempBans.get(clientIP);
    if (Date.now() < ban.until) {
      socket.emit('banned', { type: 'temporary', reason: ban.reason, until: new Date(ban.until).toISOString() });
      socket.disconnect();
      return;
    } else {
      tempBans.delete(clientIP);
    }
  }

  // Handle admin login
  socket.on('admin-login', (data) => {
    const { adminId } = data;
    admins.set(socket.id, {
      adminId,
      isAvailable: true,
      currentUsers: []
    });
    socket.join('admins');
    socket.emit('admin-logged-in', { adminId });
    
    // Send full list of waiting users with IP and scenario
    socket.emit('waiting-users-list', waitingUsers.map(user => ({
      userId: user.userId,
      ip: user.ip,
      character: {
        name: user.character.name,
        age: user.character.age,
        personality: user.character.personality
      },
      scenario: user.scenario || ''
    })));
  });

  // Handle user character creation completion
  socket.on('character-created', (data) => {
    const { character, userId, scenario } = data;
    connectedUsers.set(socket.id, { userId, ip: clientIP, character, scenario: scenario || '' });
    
    waitingUsers.push({
      socketId: socket.id,
      userId,
      ip: clientIP,
      character,
      scenario: scenario || '',
      timestamp: Date.now()
    });
    
    io.to('admins').emit('waiting-users-list', waitingUsers.map(user => ({
      userId: user.userId,
      ip: user.ip,
      character: {
        name: user.character.name,
        age: user.character.age,
        personality: user.character.personality
      },
      scenario: user.scenario || ''
    })));
    
    socket.emit('waiting-for-admin', { position: waitingUsers.length });
  });

  // Handle scenario selection
  socket.on('scenario-selected', (data) => {
    const { userId, scenario } = data;
    const user = connectedUsers.get(socket.id);
    if (!user || user.userId !== userId) {
      socket.emit('error', { message: 'Invalid user or session' });
      return;
    }

    // Update scenario in connectedUsers
    connectedUsers.set(socket.id, { ...user, scenario });

    // Update scenario in waitingUsers if user is still in queue
    const waitingUserIndex = waitingUsers.findIndex(u => u.userId === userId);
    if (waitingUserIndex !== -1) {
      waitingUsers[waitingUserIndex].scenario = scenario;
      io.to('admins').emit('waiting-users-list', waitingUsers.map(user => ({
        userId: user.userId,
        ip: user.ip,
        character: {
          name: user.character.name,
          age: user.character.age,
          personality: user.character.personality
        },
        scenario: user.scenario || ''
      })));
    }

    // Notify the admin if the user is in an active session
    for (let [adminSocketId, admin] of admins) {
      if (admin.currentUsers.includes(userId)) {
        io.to(adminSocketId).emit('scenario-updated', { userId, scenario });
        break;
      }
    }
  });

  // Handle admin accepting a user
  socket.on('admin-accept-user', (data) => {
    const admin = admins.get(socket.id);
    if (!admin) {
      socket.emit('error', { message: 'Admin not available' });
      return;
    }
    
    const { userId } = data;
    const userIndex = waitingUsers.findIndex(u => u.userId === userId);
    
    if (userIndex === -1) {
      socket.emit('error', { message: 'User not found in queue' });
      return;
    }
    
    const user = waitingUsers.splice(userIndex, 1)[0];
    
    admin.currentUsers.push(user.userId);
    admins.set(socket.id, admin);
    
    adminSessions.set(`${admin.adminId}-${user.userId}`, {
      socketId: socket.id,
      userId: user.userId,
      ip: user.ip,
      character: user.character,
      userSocketId: user.socketId,
      scenario: user.scenario || ''
    });
    
    io.to(user.socketId).emit('admin-connected', {
      character: user.character
    });
    
    socket.emit('user-connected', {
      userId: user.userId,
      ip: user.ip,
      character: user.character,
      scenario: user.scenario || ''
    });
    
    io.to('admins').emit('waiting-users-list', waitingUsers.map(user => ({
      userId: user.userId,
      ip: user.ip,
      character: {
        name: user.character.name,
        age: user.character.age,
        personality: user.character.personality
      },
      scenario: user.scenario || ''
    })));
  });

  // Handle chat messages from users
  socket.on('user-message', (data) => {
    const user = connectedUsers.get(socket.id);
    if (!user) return;
    
    const messageId = uuidv4();
    messageStatus.set(messageId, { isRead: false });
    
    for (let [socketId, admin] of admins) {
      if (admin.currentUsers.includes(user.userId)) {
        io.to(socketId).emit('user-message', {
          message: data.message,
          userId: user.userId,
          messageId,
          timestamp: Date.now()
        });
        break;
      }
    }
  });

  // Handle chat messages from admins
  socket.on('admin-message', (data) => {
    const admin = admins.get(socket.id);
    if (!admin || !admin.currentUsers.includes(data.userId)) return;
    
    const messageId = uuidv4();
    messageStatus.set(messageId, { isRead: false });
    
    for (let [socketId, user] of connectedUsers) {
      if (user.userId === data.userId) {
        io.to(socketId).emit('admin-message', {
          message: data.message,
          messageId,
          timestamp: Date.now()
        });
        break;
      }
    }
  });

  // Handle message read receipt
  socket.on('message-read', (data) => {
    const { messageId, userId } = data;
    if (messageStatus.has(messageId)) {
      messageStatus.set(messageId, { isRead: true });
      
      const senderSocketId = [...connectedUsers.entries()].find(([_, user]) => user.userId === userId)?.[0] ||
                            [...admins.entries()].find(([_, admin]) => admin.currentUsers.includes(userId))?.[0];
      
      if (senderSocketId) {
        io.to(senderSocketId).emit('message-read-receipt', { messageId });
      }
    }
  });

  // Handle chat end
  socket.on('end-chat', (data) => {
    const admin = admins.get(socket.id);
    const user = connectedUsers.get(socket.id);
    
    if (admin && data.userId) {
      const sessionKey = `${admin.adminId}-${data.userId}`;
      const session = adminSessions.get(sessionKey);
      if (session) {
        io.to(session.userSocketId).emit('chat-ended', {
          character: session.character
        });
        adminSessions.delete(sessionKey);
        
        admin.currentUsers = admin.currentUsers.filter(uid => uid !== data.userId);
        admins.set(socket.id, admin);
      }
      
      socket.emit('chat-ended-admin', { userId: data.userId });
      
      io.to('admins').emit('waiting-users-list', waitingUsers.map(user => ({
        userId: user.userId,
        ip: user.ip,
        character: {
          name: user.character.name,
          age: user.character.age,
          personality: user.character.personality
        },
        scenario: user.scenario || ''
      })));
    } else if (user) {
      // Remove from waiting queue if present
      const queueIndex = waitingUsers.findIndex(u => u.socketId === socket.id);
      if (queueIndex !== -1) {
        waitingUsers.splice(queueIndex, 1);
        io.to('admins').emit('waiting-users-list', waitingUsers.map(user => ({
          userId: user.userId,
          ip: user.ip,
          character: {
            name: user.character.name,
            age: user.character.age,
            personality: user.character.personality
          },
          scenario: user.scenario || ''
        })));
      }
      
      // End active chat if present
      for (let [adminSocketId, admin] of admins) {
        if (admin.currentUsers.includes(user.userId)) {
          io.to(adminSocketId).emit('user-disconnected', { userId: user.userId });
          admin.currentUsers = admin.currentUsers.filter(uid => uid !== user.userId);
          admins.set(adminSocketId, admin);
          adminSessions.delete(`${admin.adminId}-${user.userId}`);
          break;
        }
      }
      
      socket.emit('chat-ended', { character: user.character });
    }
  });

  // Handle character JSON upload
  socket.on('upload-character', (data) => {
    const { characterData } = data;
    try {
      const parsedData = JSON.parse(characterData);
      const { character, scenario } = parsedData;
      
      if (character && character.name && character.personality && character.backstory) {
        const userId = uuidv4();
        connectedUsers.set(socket.id, { userId, ip: clientIP, character, scenario: scenario || '' });
        
        socket.emit('character-loaded', { character, userId, scenario: scenario || '' });
      } else {
        socket.emit('error', { message: 'Invalid character data' });
      }
    } catch (error) {
      socket.emit('error', { message: 'Invalid JSON format' });
    }
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    
    const admin = admins.get(socket.id);
    if (admin) {
      admin.currentUsers.forEach(userId => {
        const sessionKey = `${admin.adminId}-${userId}`;
        const session = adminSessions.get(sessionKey);
        if (session) {
          io.to(session.userSocketId).emit('admin-disconnected');
          adminSessions.delete(sessionKey);
        }
      });
      admins.delete(socket.id);
    }
    
    const user = connectedUsers.get(socket.id);
    if (user) {
      const queueIndex = waitingUsers.findIndex(u => u.socketId === socket.id);
      if (queueIndex !== -1) {
        waitingUsers.splice(queueIndex, 1);
        io.to('admins').emit('waiting-users-list', waitingUsers.map(user => ({
          userId: user.userId,
          ip: user.ip,
          character: {
            name: user.character.name,
            age: user.character.age,
            personality: user.character.personality
          },
          scenario: user.scenario || ''
        })));
      }
      
      for (let [adminSocketId, admin] of admins) {
        if (admin.currentUsers.includes(user.userId)) {
          io.to(adminSocketId).emit('user-disconnected', { userId: user.userId });
          admin.currentUsers = admin.currentUsers.filter(uid => uid !== user.userId);
          admins.set(adminSocketId, admin);
          adminSessions.delete(`${admin.adminId}-${user.userId}`);
        }
      }
      
      connectedUsers.delete(socket.id);
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`LongPartner server running on port ${PORT}`);
});

module.exports = app;