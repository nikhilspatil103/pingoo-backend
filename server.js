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

// Signup API
app.post('/api/signup', async (req, res) => {
  const { name, email, password, age, gender, profilePhoto } = req.body;

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

// Get all users API
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const skip = (page - 1) * limit;
    
    // Check cache for online users list
    const cacheKey = `users:page:${page}:limit:${limit}`;
    const cachedUsers = await getCache(cacheKey);
    
    if (cachedUsers) {
      return res.status(200).json({ users: cachedUsers, page, limit, cached: true });
    }
    
    // Optimized query with projection and lean()
    const users = await User.find(
      { _id: { $ne: currentUserId } }
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
    const { receiverId, message, senderId } = data;
    
    try {
      // Save message to database
      const newMessage = new Message({
        senderId,
        receiverId,
        message,
        timestamp: new Date()
      });
      await newMessage.save();
      
      // Send to receiver if online
      const receiverSocketId = connectedUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', {
          senderId,
          message,
          timestamp: new Date()
        });
      }
    } catch (error) {
      console.error('Error saving message:', error);
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
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const likes = user.likes || [];
    const isLiked = likes.some(id => id.toString() === currentUserId);
    
    if (isLiked) {
      user.likes = likes.filter(id => id.toString() !== currentUserId);
    } else {
      user.likes = [...likes, currentUserId];
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
      text: msg.message,
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

server.listen(PORT, () => {
  console.log(`Pingoo backend running on port ${PORT}`);
});
