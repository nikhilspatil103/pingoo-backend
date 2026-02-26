require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const validator = require('validator');
const User = require('./models/User');
const Message = require('./models/Message');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const redis = require('redis');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { Expo } = require('expo-server-sdk');

const expo = new Expo();

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure multer for memory storage
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Redis client setup (optional)
let redisClient = null;
let redisConnected = false;

try {
  redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: {
      reconnectStrategy: () => false // Don't reconnect if fails
    }
  });

  redisClient.on('error', (err) => {
    console.log('Redis not available, running without cache');
    redisConnected = false;
  });
  
  redisClient.on('connect', () => {
    console.log('Redis connected');
    redisConnected = true;
  });

  // Connect to Redis (optional)
  (async () => {
    try {
      await redisClient.connect();
    } catch (error) {
      console.log('Redis not available, running without cache');
      redisConnected = false;
    }
  })();
} catch (error) {
  console.log('Redis not available, running without cache');
  redisConnected = false;
}

// Cache helper functions
const CACHE_TTL = {
  USER_PROFILE: 300,
  ONLINE_USERS: 60,
  LIKE_COUNTS: 300,
  CLOUDINARY_URL: 86400
};

const getCache = async (key) => {
  if (!redisConnected || !redisClient) return null;
  try {
    const data = await redisClient.get(key);
    return data ? JSON.parse(data) : null;
  } catch (error) {
    return null;
  }
};

const setCache = async (key, value, ttl = 300) => {
  if (!redisConnected || !redisClient) return;
  try {
    await redisClient.setEx(key, ttl, JSON.stringify(value));
  } catch (error) {
    // Silently fail
  }
};

const deleteCache = async (key) => {
  if (!redisConnected || !redisClient) return;
  try {
    await redisClient.del(key);
  } catch (error) {
    // Silently fail
  }
};

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pingoo';

// Database connection with pooling
mongoose.connect(MONGODB_URI, {
  maxPoolSize: 10,
  minPoolSize: 5,
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 5000,
})
  .then(() => {
    console.log('MongoDB connected with connection pooling');
    createIndexes();
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Create database indexes for performance
const createIndexes = async () => {
  try {
    await User.collection.createIndex({ isOnline: -1 });
    await User.collection.createIndex({ lastSeen: -1 });
    await User.collection.createIndex({ location: 1 });
    await User.collection.createIndex({ gender: 1 });
    await User.collection.createIndex({ isOnline: -1, lastSeen: -1 });
    console.log('Database indexes created successfully');
  } catch (error) {
    console.error('Error creating indexes:', error);
  }
};

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: 'Server is running',
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    redis: redisConnected ? 'connected' : 'disconnected'
  });
});

app.get('/', (req, res) => {
  res.status(200).json({ message: 'Pingoo API is running' });
});

// Signup API
app.post('/api/signup', async (req, res) => {
  const { name, email, password, age, gender, interestedIn, lookingFor, profilePhoto } = req.body;

  if (!name || !email || !password || !age || !gender) {
    return res.status(400).json({ error: 'Name, email, password, age, and gender are required' });
  }

  // Input sanitization
  const sanitizedName = validator.escape(validator.trim(name));
  const sanitizedEmail = validator.normalizeEmail(email);
  
  if (!validator.isEmail(sanitizedEmail)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  if (age < 18) {
    return res.status(400).json({ error: 'You must be at least 18 years old' });
  }

  try {
    const existingUser = await User.findOne({ email: sanitizedEmail });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ 
      name: sanitizedName, 
      email: sanitizedEmail, 
      password: hashedPassword, 
      age, 
      gender, 
      interestedIn: interestedIn || null,
      lookingFor: lookingFor || null,
      profilePhoto: profilePhoto || null 
    });
    await user.save();

    // Generate token for auto-login after signup
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    
    // Set user as online
    await User.findByIdAndUpdate(user._id, { 
      isOnline: true, 
      lastSeen: new Date() 
    });

    res.status(201).json({ 
      message: 'User created successfully', 
      token, 
      user: { 
        userId: user._id, 
        name: user.name, 
        email: user.email 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Input sanitization
  const sanitizedEmail = validator.normalizeEmail(email);
  
  if (!validator.isEmail(sanitizedEmail)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  try {
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update user online status
    await User.findByIdAndUpdate(user._id, { 
      isOnline: true, 
      lastSeen: new Date() 
    });

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(200).json({ token, userId: user._id, name: user.name, email: user.email });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Auth middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log('Auth header:', authHeader);
  
  const token = authHeader?.replace('Bearer ', '');
  console.log('Extracted token:', token);
  
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded token:', decoded);
    req.user = decoded;
    next();
  } catch (error) {
    console.log('Token verification error:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Send push notification helper
const sendPushNotification = async (pushToken, title, body, data = {}) => {
  if (!Expo.isExpoPushToken(pushToken)) {
    console.error(`Push token ${pushToken} is not a valid Expo push token`);
    return;
  }

  const message = {
    to: pushToken,
    sound: 'default',
    title,
    body,
    data,
  };

  try {
    const ticket = await expo.sendPushNotificationsAsync([message]);
    console.log('Notification sent:', ticket);
  } catch (error) {
    console.error('Error sending notification:', error);
  }
};

// Logout API
app.post('/api/logout', authMiddleware, async (req, res) => {
  try {
    // Update user offline status
    await User.findByIdAndUpdate(req.user.userId, { 
      isOnline: false, 
      lastSeen: new Date() 
    });
    
    res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Register push token API
app.post('/api/register-push-token', authMiddleware, async (req, res) => {
  try {
    const { pushToken } = req.body;
    const userId = req.user.userId;
    
    if (!pushToken) {
      return res.status(400).json({ error: 'Push token is required' });
    }
    
    await User.findByIdAndUpdate(userId, { pushToken });
    
    res.status(200).json({ message: 'Push token registered successfully' });
  } catch (error) {
    console.error('Error registering push token:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users API
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const skip = (page - 1) * limit;
    
    // Get current user's blocked list and interested in preference
    const currentUser = await User.findById(currentUserId).select('blockedUsers interestedIn');
    const blockedUsers = currentUser?.blockedUsers || [];
    const interestedIn = currentUser?.interestedIn;
    
    // Build gender filter based on interestedIn
    let genderFilter = {};
    if (interestedIn === 'male') {
      genderFilter = { gender: 'male' };
    } else if (interestedIn === 'female') {
      genderFilter = { gender: 'female' };
    }
    // If interestedIn is 'both' or not set, show all genders
    
    // Check cache for online users list
    const cacheKey = `users:page:${page}:limit:${limit}:interest:${interestedIn}`;
    const cachedUsers = await getCache(cacheKey);
    
    if (cachedUsers) {
      // Filter out blocked users from cached results
      const filteredUsers = cachedUsers.filter(u => !blockedUsers.includes(u.id));
      return res.status(200).json({ users: filteredUsers, page, limit, cached: true });
    }
    
    // Optimized query with projection and lean() - exclude blocked users and filter by gender
    const users = await User.find(
      { 
        _id: { 
          $ne: currentUserId,
          $nin: blockedUsers
        },
        ...genderFilter
      }
    )
    .select('name age gender profilePhoto location lookingFor isOnline lastSeen likes')
    .sort({ isOnline: -1, lastSeen: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    // Transform users data for frontend
    const transformedUsers = users.map(user => ({
      id: user._id,
      name: user.name,
      age: user.age,
      gender: user.gender,
      profilePhoto: user.profilePhoto,
      location: user.location,
      lookingFor: user.lookingFor,
      isOnline: user.isOnline,
      lastSeen: user.lastSeen,
      likesCount: user.likes?.length || 0
    }));
    
    // Cache the result for 1 minute (online status changes frequently)
    await setCache(cacheKey, transformedUsers, CACHE_TTL.ONLINE_USERS);
    
    res.status(200).json({ users: transformedUsers, page, limit });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile API
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const updateData = req.body;
    
    // Remove sensitive fields
    delete updateData.password;
    delete updateData.email;
    delete updateData._id;
    
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { ...updateData, lastSeen: new Date() },
      { new: true, select: '-password' }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Invalidate profile cache after update
    await deleteCache(`profile:${userId}`);
    
    res.status(200).json({ 
      message: 'Profile updated successfully',
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        age: updatedUser.age,
        gender: updatedUser.gender,
        profilePhoto: updatedUser.profilePhoto,
        additionalPhotos: updatedUser.additionalPhotos || [],
        location: updatedUser.location,
        interests: updatedUser.interests || [],
        interestedIn: updatedUser.interestedIn,
        bio: updatedUser.bio,
        height: updatedUser.height,
        bodyType: updatedUser.bodyType,
        smoking: updatedUser.smoking,
        drinking: updatedUser.drinking,
        exercise: updatedUser.exercise,
        diet: updatedUser.diet,
        occupation: updatedUser.occupation,
        company: updatedUser.company,
        graduation: updatedUser.graduation,
        school: updatedUser.school,
        hometown: updatedUser.hometown,
        currentCity: updatedUser.currentCity,
        lookingFor: updatedUser.lookingFor,
        relationshipStatus: updatedUser.relationshipStatus,
        kids: updatedUser.kids,
        languages: updatedUser.languages || [],
        isOnline: updatedUser.isOnline,
        lastSeen: updatedUser.lastSeen,
        createdAt: updatedUser.createdAt
      }
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user profile API
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Check cache for user profile
    const cacheKey = `profile:${userId}`;
    const cachedProfile = await getCache(cacheKey);
    
    if (cachedProfile) {
      return res.status(200).json({ user: cachedProfile, cached: true });
    }
    
    const user = await User.findById(userId, { password: 0 });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userProfile = {
      id: user._id,
      name: user.name,
      email: user.email,
      age: user.age,
      gender: user.gender,
      interestedIn: user.interestedIn,
      profilePhoto: user.profilePhoto,
      additionalPhotos: user.additionalPhotos || [],
      location: user.location,
      interests: user.interests || [],
      bio: user.bio,
      height: user.height,
      bodyType: user.bodyType,
      smoking: user.smoking,
      drinking: user.drinking,
      exercise: user.exercise,
      diet: user.diet,
      occupation: user.occupation,
      company: user.company,
      graduation: user.graduation,
      school: user.school,
      hometown: user.hometown,
      currentCity: user.currentCity,
      lookingFor: user.lookingFor,
      relationshipStatus: user.relationshipStatus,
      kids: user.kids,
      languages: user.languages || [],
      likes: user.likes || [],
      coins: user.coins || 0,
      isOnline: user.isOnline,
      lastSeen: user.lastSeen,
      createdAt: user.createdAt
    };
    
    // Cache profile for 5 minutes
    await setCache(cacheKey, userProfile, CACHE_TTL.USER_PROFILE);
    
    res.status(200).json({ user: userProfile });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload image endpoint (base64) - Public for signup
app.post('/api/upload-image-public', async (req, res) => {
  try {
    const { image, filename } = req.body;
    
    if (!image) {
      return res.status(400).json({ error: 'No image data provided' });
    }
    
    const result = await cloudinary.uploader.upload(image, {
      folder: 'pingoo-profiles',
      public_id: `profile_${Date.now()}`,
      transformation: [
        { width: 400, height: 400, crop: 'fill' },
        { quality: 'auto' }
      ]
    });

    // Cache Cloudinary URL for 24 hours
    await setCache(`cloudinary:${result.public_id}`, result.secure_url, CACHE_TTL.CLOUDINARY_URL);

    res.status(200).json({ 
      message: 'Image uploaded successfully',
      imageUrl: result.secure_url 
    });
  } catch (error) {
    console.error('Error uploading base64 image:', error);
    res.status(500).json({ error: 'Failed to upload image', details: error.message });
  }
});

// Upload image endpoint (base64)
app.post('/api/upload-image-base64', authMiddleware, async (req, res) => {
  try {
    console.log('Base64 upload request received');
    
    const { image, filename } = req.body;
    
    if (!image) {
      console.log('No image data provided');
      return res.status(400).json({ error: 'No image data provided' });
    }
    
    console.log('Uploading base64 image to Cloudinary');
    
    const result = await cloudinary.uploader.upload(image, {
      folder: 'pingoo-profiles',
      public_id: `profile_${Date.now()}`,
      transformation: [
        { width: 400, height: 400, crop: 'fill' },
        { quality: 'auto' }
      ]
    });

    // Cache Cloudinary URL for 24 hours
    await setCache(`cloudinary:${result.public_id}`, result.secure_url, CACHE_TTL.CLOUDINARY_URL);

    res.status(200).json({ 
      message: 'Image uploaded successfully',
      imageUrl: result.secure_url 
    });
  } catch (error) {
    console.error('Error uploading base64 image:', error);
    res.status(500).json({ error: 'Failed to upload image', details: error.message });
  }
});

// Delete photo API
app.delete('/api/delete-photo', authMiddleware, async (req, res) => {
  try {
    const { photoUrl, isProfilePhoto } = req.body;
    const userId = req.user.userId;
    
    if (!photoUrl) {
      return res.status(400).json({ error: 'Photo URL is required' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Extract public_id from Cloudinary URL for deletion
    const publicId = photoUrl.split('/').pop().split('.')[0];
    
    try {
      await cloudinary.uploader.destroy(`pingoo-profiles/${publicId}`);
    } catch (cloudinaryError) {
      console.log('Cloudinary deletion error:', cloudinaryError);
    }
    
    if (isProfilePhoto) {
      user.profilePhoto = null;
    } else {
      user.additionalPhotos = user.additionalPhotos.filter(photo => photo !== photoUrl);
    }
    
    await user.save();
    
    res.status(200).json({ 
      message: 'Photo deleted successfully',
      user: {
        id: user._id,
        profilePhoto: user.profilePhoto,
        additionalPhotos: user.additionalPhotos || []
      }
    });
  } catch (error) {
    console.error('Error deleting photo:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Set profile photo API
app.put('/api/set-profile-photo', authMiddleware, async (req, res) => {
  try {
    const { photoUrl } = req.body;
    const userId = req.user.userId;
    
    if (!photoUrl) {
      return res.status(400).json({ error: 'Photo URL is required' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // If there's already a profile photo, move it to additional photos
    if (user.profilePhoto && user.profilePhoto !== photoUrl) {
      if (!user.additionalPhotos.includes(user.profilePhoto)) {
        user.additionalPhotos.push(user.profilePhoto);
      }
    }
    
    // Set new profile photo and remove from additional photos if it exists there
    user.profilePhoto = photoUrl;
    user.additionalPhotos = user.additionalPhotos.filter(photo => photo !== photoUrl);
    
    await user.save();
    
    res.status(200).json({ 
      message: 'Profile photo updated successfully',
      user: {
        id: user._id,
        profilePhoto: user.profilePhoto,
        additionalPhotos: user.additionalPhotos || []
      }
    });
  } catch (error) {
    console.error('Error setting profile photo:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update location API
app.put('/api/location', authMiddleware, async (req, res) => {
  try {
    const { latitude, longitude, location } = req.body;
    const userId = req.user.userId;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ error: 'Latitude and longitude are required' });
    }
    
    await User.findByIdAndUpdate(userId, {
      latitude,
      longitude,
      location: location || 'Unknown',
      lastSeen: new Date()
    });
    
    res.status(200).json({ message: 'Location updated successfully' });
  } catch (error) {
    console.error('Error updating location:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile by ID API
app.get('/api/user/:userId', authMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId, { password: 0 });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.status(200).json({ 
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        age: user.age,
        gender: user.gender,
        profilePhoto: user.profilePhoto,
        additionalPhotos: user.additionalPhotos || [],
        location: user.location,
        interests: user.interests || [],
        bio: user.bio,
        height: user.height,
        bodyType: user.bodyType,
        smoking: user.smoking,
        drinking: user.drinking,
        exercise: user.exercise,
        diet: user.diet,
        occupation: user.occupation,
        company: user.company,
        graduation: user.graduation,
        school: user.school,
        hometown: user.hometown,
        currentCity: user.currentCity,
        lookingFor: user.lookingFor,
        relationshipStatus: user.relationshipStatus,
        kids: user.kids,
        languages: user.languages || [],
        isOnline: user.isOnline,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Socket.IO connection handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join', async (userId) => {
    connectedUsers.set(userId, socket.id);
    socket.userId = userId;
    console.log(`User ${userId} joined with socket ${socket.id}`);
    
    // Set user as online
    try {
      await User.findByIdAndUpdate(userId, { 
        isOnline: true, 
        lastSeen: new Date() 
      });
    } catch (error) {
      console.error('Error updating user online status:', error);
    }
  });

  socket.on('sendMessage', async (data) => {
    const { receiverId, message, senderId, mediaUrl, mediaType } = data;
    
    try {
      // Save message to database
      const newMessage = new Message({
        senderId,
        receiverId,
        message: message || '',
        mediaUrl: mediaUrl || null,
        mediaType: mediaType || 'text',
        timestamp: new Date()
      });
      await newMessage.save();
      
      // Get sender and receiver info
      const sender = await User.findById(senderId).select('name');
      const receiver = await User.findById(receiverId).select('pushToken isOnline');
      
      // Send to receiver if online with database ID
      const receiverSocketId = connectedUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', {
          messageId: newMessage._id,
          senderId,
          message: message || '',
          mediaUrl: mediaUrl || null,
          mediaType: mediaType || 'text',
          timestamp: newMessage.timestamp
        });
      }
      
      // Send push notification if receiver is offline or not in chat
      if (receiver?.pushToken && !receiverSocketId) {
        const notificationBody = mediaType === 'image' ? '📷 Sent a photo' : message;
        await sendPushNotification(
          receiver.pushToken,
          sender?.name || 'Someone',
          notificationBody,
          { type: 'message', senderId, senderName: sender?.name }
        );
      }
      
      // Send back to sender with database ID
      const senderSocketId = connectedUsers.get(senderId);
      if (senderSocketId) {
        socket.emit('messageSaved', {
          tempId: data.tempId,
          messageId: newMessage._id,
          timestamp: newMessage.timestamp
        });
      }
    } catch (error) {
      console.error('Error saving message:', error);
    }
  });

  socket.on('typing', (data) => {
    const { receiverId, userId } = data;
    const receiverSocketId = connectedUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userTyping', { userId });
    }
  });

  socket.on('stopTyping', (data) => {
    const { receiverId, userId } = data;
    const receiverSocketId = connectedUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userStopTyping', { userId });
    }
  });

  socket.on('deleteMessage', async (data) => {
    const { messageId, receiverId, senderId } = data;
    
    try {
      // Delete message from database
      await Message.findByIdAndDelete(messageId);
      
      // Notify receiver if online
      const receiverSocketId = connectedUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('messageDeleted', {
          messageId,
          senderId,
          receiverId
        });
      }
    } catch (error) {
      console.error('Error deleting message:', error);
    }
  });

  socket.on('recallMessage', async (data) => {
    const { messageId, receiverId, senderId } = data;
    
    try {
      // Update message in database to recalled state
      const message = await Message.findByIdAndUpdate(
        messageId,
        { 
          message: 'This message was recalled',
          isRecalled: true,
          mediaUrl: null,
          mediaType: 'text'
        },
        { new: true }
      );
      
      if (message) {
        // Get sender name
        const sender = await User.findById(senderId).select('name');
        
        // Notify receiver if online
        const receiverSocketId = connectedUsers.get(receiverId);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('messageRecalled', {
            messageId,
            senderId,
            receiverId,
            senderName: sender?.name || 'User'
          });
        }
      }
    } catch (error) {
      console.error('Error recalling message:', error);
    }
  });

  socket.on('disconnect', async () => {
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
      console.log(`User ${socket.userId} disconnected`);
      
      // Set user as offline
      try {
        await User.findByIdAndUpdate(socket.userId, { 
          isOnline: false, 
          lastSeen: new Date() 
        });
      } catch (error) {
        console.error('Error updating user offline status:', error);
      }
    }
  });
});

// Mark messages as read API
app.put('/api/messages/read/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    await Message.updateMany(
      {
        senderId: userId,
        receiverId: currentUserId,
        isRead: false
      },
      { isRead: true }
    );
    
    res.status(200).json({ message: 'Messages marked as read' });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like/Unlike user API
app.post('/api/like/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    if (currentUserId === userId) {
      return res.status(400).json({ error: 'Cannot like yourself' });
    }
    
    const user = await User.findById(userId).select('likes pushToken newLikes');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const likes = user.likes || [];
    const isLiked = likes.some(id => id.toString() === currentUserId);
    
    if (isLiked) {
      user.likes = likes.filter(id => id.toString() !== currentUserId);
      user.newLikes = (user.newLikes || []).filter(l => l.userId.toString() !== currentUserId);
    } else {
      user.likes = [...likes, currentUserId];
      
      // Add to newLikes
      if (!user.newLikes) user.newLikes = [];
      user.newLikes.push({ userId: currentUserId, timestamp: new Date(), read: false });
      
      // Send push notification for new like
      if (user.pushToken) {
        const liker = await User.findById(currentUserId).select('name');
        await sendPushNotification(
          user.pushToken,
          'New Like! 💖',
          `${liker?.name || 'Someone'} liked your profile`,
          { type: 'like', likerId: currentUserId, likerName: liker?.name }
        );
      }
    }
    
    await user.save();
    
    // Invalidate like count cache
    await deleteCache(`likes:${userId}`);
    await deleteCache(`profile:${userId}`);
    
    res.status(200).json({ 
      message: isLiked ? 'Unliked' : 'Liked',
      isLiked: !isLiked,
      likeCount: user.likes.length
    });
  } catch (error) {
    console.error('Error liking user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get like status for a user API
app.get('/api/like-status/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const likes = user.likes || [];
    const isLiked = likes.some(id => id.toString() === currentUserId);
    
    res.status(200).json({ 
      isLiked,
      likeCount: likes.length
    });
  } catch (error) {
    console.error('Error getting like status:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get new likes API
app.get('/api/new-likes', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const user = await User.findById(userId)
      .populate('newLikes.userId', 'name age profilePhoto')
      .select('newLikes');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const likes = (user.newLikes || [])
      .filter(l => !l.read)
      .map(l => ({
        id: l.userId._id,
        name: l.userId.name,
        age: l.userId.age,
        profilePhoto: l.userId.profilePhoto,
        timestamp: l.timestamp
      }));
    
    res.status(200).json({ likes });
  } catch (error) {
    console.error('Error fetching new likes:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all likes API
app.get('/api/all-likes', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const user = await User.findById(userId)
      .populate('newLikes.userId', 'name age profilePhoto')
      .select('newLikes');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const likes = (user.newLikes || [])
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .map(l => ({
        id: l.userId._id,
        name: l.userId.name,
        age: l.userId.age,
        profilePhoto: l.userId.profilePhoto,
        timestamp: l.timestamp,
        read: l.read
      }));
    
    res.status(200).json({ likes });
  } catch (error) {
    console.error('Error fetching all likes:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark likes as read API
app.post('/api/mark-likes-read', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    await User.findByIdAndUpdate(userId, {
      $set: { 'newLikes.$[].read': true }
    });
    
    res.status(200).json({ message: 'Likes marked as read' });
  } catch (error) {
    console.error('Error marking likes as read:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get chat history API
app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    const messages = await Message.find({
      $or: [
        { senderId: currentUserId, receiverId: userId },
        { senderId: userId, receiverId: currentUserId }
      ]
    }).sort({ timestamp: 1 });
    
    const formattedMessages = messages.map(msg => ({
      id: msg._id,
      text: msg.isRecalled ? (msg.senderId.toString() === currentUserId ? 'You recalled this message' : 'This message was recalled') : (msg.message || ''),
      mediaUrl: msg.isRecalled ? null : (msg.mediaUrl || null),
      mediaType: msg.isRecalled ? 'text' : (msg.mediaType || 'text'),
      isRecalled: msg.isRecalled || false,
      sent: msg.senderId.toString() === currentUserId,
      time: new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      timestamp: msg.timestamp
    }));
    
    res.status(200).json({ messages: formattedMessages });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check chat access API
app.get('/api/chat-access/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    const user = await User.findById(currentUserId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const access = user.chatAccess?.find(a => a.userId.toString() === userId);
    const hasAccess = access && new Date(access.expiresAt) > new Date();
    
    res.status(200).json({ 
      hasAccess,
      expiresAt: access?.expiresAt,
      coins: user.coins
    });
  } catch (error) {
    console.error('Error checking chat access:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Purchase chat access API
app.post('/api/purchase-chat/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    const CHAT_COST = 10;
    const CHAT_DURATION_HOURS = 6;
    
    const user = await User.findById(currentUserId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.coins < CHAT_COST) {
      return res.status(400).json({ error: 'Insufficient coins' });
    }
    
    // Deduct coins
    user.coins -= CHAT_COST;
    
    // Add or update chat access
    const expiresAt = new Date(Date.now() + CHAT_DURATION_HOURS * 60 * 60 * 1000);
    const existingAccess = user.chatAccess?.findIndex(a => a.userId.toString() === userId);
    
    if (existingAccess !== -1) {
      user.chatAccess[existingAccess].expiresAt = expiresAt;
    } else {
      if (!user.chatAccess) user.chatAccess = [];
      user.chatAccess.push({ userId, expiresAt });
    }
    
    await user.save();
    
    res.status(200).json({ 
      message: 'Chat access purchased',
      coins: user.coins,
      expiresAt
    });
  } catch (error) {
    console.error('Error purchasing chat access:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user coins API
app.get('/api/coins', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('coins');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ coins: user.coins });
  } catch (error) {
    console.error('Error fetching coins:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check spin availability API
app.get('/api/spin-availability', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('lastSpinDate');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const now = new Date();
    const lastSpin = user.lastSpinDate;
    
    // Check if 24 hours have passed
    const canSpin = !lastSpin || (now - new Date(lastSpin)) >= 24 * 60 * 60 * 1000;
    
    let nextSpinTime = null;
    if (!canSpin && lastSpin) {
      nextSpinTime = new Date(new Date(lastSpin).getTime() + 24 * 60 * 60 * 1000);
    }
    
    res.status(200).json({ canSpin, nextSpinTime });
  } catch (error) {
    console.error('Error checking spin availability:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Spin wheel API
app.post('/api/spin-wheel', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const now = new Date();
    const lastSpin = user.lastSpinDate;
    
    // Check if 24 hours have passed
    if (lastSpin && (now - lastSpin) < 24 * 60 * 60 * 1000) {
      return res.status(400).json({ error: 'You can only spin once per day' });
    }
    
    // Segments array matching frontend
    const segments = [10, 20, 10, 30, 10, 20, 10, 50];
    const randomIndex = Math.floor(Math.random() * segments.length);
    const wonCoins = segments[randomIndex];
    
    // Initialize coins if undefined
    if (typeof user.coins !== 'number') {
      user.coins = 50;
    }
    
    // Update user coins and last spin date
    user.coins += wonCoins;
    user.lastSpinDate = now;
    const nextSpinTime = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    await user.save();
    
    res.status(200).json({ 
      coins: wonCoins,
      segmentIndex: randomIndex,
      totalCoins: user.coins,
      nextSpinTime
    });
  } catch (error) {
    console.error('Error spinning wheel:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get conversations API
app.get('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { senderId: new mongoose.Types.ObjectId(userId) },
            { receiverId: new mongoose.Types.ObjectId(userId) }
          ]
        }
      },
      {
        $sort: { timestamp: -1 }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$senderId', new mongoose.Types.ObjectId(userId)] },
              '$receiverId',
              '$senderId'
            ]
          },
          lastMessage: { $first: '$message' },
          lastMessageTime: { $first: '$timestamp' },
          isFromMe: { $first: { $eq: ['$senderId', new mongoose.Types.ObjectId(userId)] } },
          unreadCount: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $eq: ['$isRead', false] },
                    { $ne: ['$senderId', new mongoose.Types.ObjectId(userId)] }
                  ]
                },
                1,
                0
              ]
            }
          }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          id: '$_id',
          name: '$user.name',
          age: '$user.age',
          profilePhoto: '$user.profilePhoto',
          lastMessage: 1,
          lastMessageTime: 1,
          isFromMe: 1,
          unreadCount: 1
        }
      },
      {
        $sort: { lastMessageTime: -1 }
      }
    ]);
    
    res.status(200).json({ conversations });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Block user API
app.post('/api/block/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    if (currentUserId === userId) {
      return res.status(400).json({ error: 'Cannot block yourself' });
    }
    
    const user = await User.findById(currentUserId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const blockedUsers = user.blockedUsers || [];
    if (!blockedUsers.includes(userId)) {
      user.blockedUsers = [...blockedUsers, userId];
      await user.save();
    }
    
    res.status(200).json({ message: 'User blocked successfully' });
  } catch (error) {
    console.error('Error blocking user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Unblock user API
app.post('/api/unblock/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    const user = await User.findById(currentUserId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.blockedUsers = (user.blockedUsers || []).filter(id => id.toString() !== userId);
    await user.save();
    
    res.status(200).json({ message: 'User unblocked successfully' });
  } catch (error) {
    console.error('Error unblocking user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get blocked users API
app.get('/api/blocked-users', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const user = await User.findById(userId).populate('blockedUsers', 'name age profilePhoto');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const blockedUsers = (user.blockedUsers || []).map(u => ({
      _id: u._id,
      name: u.name,
      age: u.age,
      profilePhoto: u.profilePhoto
    }));
    
    res.status(200).json({ blockedUsers });
  } catch (error) {
    console.error('Error fetching blocked users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check if blocked by user API
app.get('/api/blocked-by/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    
    const user = await User.findById(userId).select('blockedUsers');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isBlockedByUser = (user.blockedUsers || []).some(id => id.toString() === currentUserId);
    
    res.status(200).json({ isBlockedByUser });
  } catch (error) {
    console.error('Error checking block status:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Report user API
app.post('/api/report/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    const { reason } = req.body;
    
    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Report reason is required' });
    }
    
    if (currentUserId === userId) {
      return res.status(400).json({ error: 'Cannot report yourself' });
    }
    
    const reportedUser = await User.findById(userId);
    if (!reportedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const reports = reportedUser.reports || [];
    reports.push({
      reportedBy: currentUserId,
      reason: reason.trim(),
      timestamp: new Date()
    });
    
    reportedUser.reports = reports;
    await reportedUser.save();
    
    res.status(200).json({ message: 'User reported successfully' });
  } catch (error) {
    console.error('Error reporting user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Pingoo backend running on port ${PORT}`);
});
