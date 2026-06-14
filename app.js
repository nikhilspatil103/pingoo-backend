require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const User = require('./models/User');
const Message = require('./models/Message');
const Mood = require('./models/Mood');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const redis = require('redis');
const { Expo } = require('expo-server-sdk');

const expo = new Expo();

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

const generateUsername = async (name) => {
  const base = name.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
  let username = base;
  let exists = await User.findOne({ username });
  while (exists) {
    username = `${base}_${Math.floor(Math.random() * 9999)}`;
    exists = await User.findOne({ username });
  }
  return username;
};

// Redis client setup (optional)
let redisClient = null;
let redisConnected = false;

try {
  redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: { reconnectStrategy: () => false }
  });
  redisClient.on('error', () => { redisConnected = false; });
  redisClient.on('connect', () => { redisConnected = true; });
  (async () => { try { await redisClient.connect(); } catch (e) { redisConnected = false; } })();
} catch (e) { redisConnected = false; }

const CACHE_TTL = { USER_PROFILE: 300, ONLINE_USERS: 60, LIKE_COUNTS: 300, CLOUDINARY_URL: 86400 };

const getCache = async (key) => {
  if (!redisConnected || !redisClient) return null;
  try { const data = await redisClient.get(key); return data ? JSON.parse(data) : null; } catch (e) { return null; }
};
const setCache = async (key, value, ttl = 300) => {
  if (!redisConnected || !redisClient) return;
  try { await redisClient.setEx(key, ttl, JSON.stringify(value)); } catch (e) {}
};
const deleteCache = async (key) => {
  if (!redisConnected || !redisClient) return;
  try { await redisClient.del(key); } catch (e) {}
};

// MongoDB connection (Lambda reuses connections across warm invocations)
let isConnected = false;
const connectDB = async () => {
  if (isConnected) return;
  const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pingoo';
  try {
    await mongoose.connect(MONGODB_URI, {
      maxPoolSize: 10,
      minPoolSize: 2,
      socketTimeoutMS: 45000,
      serverSelectionTimeoutMS: 15000,
    });
    isConnected = true;
    console.log('MongoDB connected');
  } catch (e) {
    console.error('MongoDB connection error:', e.message);
  }
};
connectDB();

const app = express();

// Trust proxy for Lambda/API Gateway (required by express-rate-limit)
app.set('trust proxy', 1);

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

// Rate limiting
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: 'Too many login attempts' } });
const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { error: 'Too many uploads' } });

app.use('/api/', generalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/upload-image-base64', uploadLimiter);
app.use('/api/upload-image-public', uploadLimiter);

// Auth middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Push notification helper
const sendPushNotification = async (pushToken, title, body, data = {}) => {
  if (!Expo.isExpoPushToken(pushToken)) return;
  try {
    await expo.sendPushNotificationsAsync([{ to: pushToken, sound: 'default', title, body, data, priority: 'high', channelId: 'default' }]);
  } catch (e) { console.error('Push notification error:', e.message); }
};

// Health check
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

app.get('/', (req, res) => { res.status(200).json({ message: 'Pingoo API is running on Lambda' }); });

// ==================== AUTH APIs ====================

app.post('/api/signup', async (req, res) => {
  const { name, email, password, age, gender, interestedIn, lookingFor, profilePhoto } = req.body;
  if (!name || !email || !password || !age || !gender) return res.status(400).json({ error: 'Name, email, password, age, and gender are required' });

  const sanitizedName = validator.escape(validator.trim(name));
  const sanitizedEmail = validator.normalizeEmail(email);
  if (!validator.isEmail(sanitizedEmail)) return res.status(400).json({ error: 'Invalid email format' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (age < 18) return res.status(400).json({ error: 'You must be at least 18 years old' });

  try {
    const existingUser = await User.findOne({ email: sanitizedEmail });
    if (existingUser) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = await generateUsername(sanitizedName);

    const user = new User({ name: sanitizedName, username, email: sanitizedEmail, password: hashedPassword, age, gender, interestedIn: interestedIn || null, lookingFor: lookingFor || null, profilePhoto: profilePhoto || null });
    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    await User.findByIdAndUpdate(user._id, { isOnline: true, lastSeen: new Date() });

    res.status(201).json({ message: 'User created', token, user: { userId: user._id, name: user.name, email: user.email } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  const sanitizedEmail = validator.normalizeEmail(email);
  if (!validator.isEmail(sanitizedEmail)) return res.status(400).json({ error: 'Invalid email format' });

  try {
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.isBanned) return res.status(403).json({ error: 'Your account has been banned.' });

    await User.findByIdAndUpdate(user._id, { isOnline: true, lastSeen: new Date() });
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(200).json({ token, userId: user._id, name: user.name, email: user.email });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/google', async (req, res) => {
  const { idToken, accessToken } = req.body;
  if (!idToken && !accessToken) return res.status(400).json({ error: 'Token is required' });

  try {
    let googleId, email, name, picture;
    if (idToken) {
      const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
      if (!googleRes.ok) return res.status(401).json({ error: 'Invalid Google token' });
      const payload = await googleRes.json();
      googleId = payload.sub; email = payload.email; name = payload.name; picture = payload.picture;
    } else {
      const googleRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${accessToken}` } });
      if (!googleRes.ok) return res.status(401).json({ error: 'Invalid Google token' });
      const googleUser = await googleRes.json();
      googleId = googleUser.id; email = googleUser.email; name = googleUser.name; picture = googleUser.picture;
    }

    let user = await User.findOne({ $or: [{ googleId }, { email }] });
    if (user) {
      if (!user.googleId) { user.googleId = googleId; user.authProvider = 'google'; await user.save(); }
      if (user.isBanned) return res.status(403).json({ error: 'Your account has been banned.' });
      await User.findByIdAndUpdate(user._id, { isOnline: true, lastSeen: new Date() });
      const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
      return res.status(200).json({ token, user: { userId: user._id, name: user.name, email: user.email }, isNewUser: false });
    }

    const username = await generateUsername(name);
    user = new User({ name, username, email, googleId, authProvider: 'google', profilePhoto: picture || null, age: 18, gender: 'male', isOnline: true, lastSeen: new Date() });
    await user.save();
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ token, user: { userId: user._id, name: user.name, email: user.email }, isNewUser: true });
  } catch (e) { console.error('Google auth error:', e); res.status(500).json({ error: 'Server error' }); }
});

// ==================== PROFILE APIs ====================

app.post('/api/logout', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.userId, { isOnline: false, lastSeen: new Date(), pushToken: null });
    res.status(200).json({ message: 'Logout successful' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/register-push-token', authMiddleware, async (req, res) => {
  try {
    const { pushToken } = req.body;
    if (!pushToken) return res.status(400).json({ error: 'Push token is required' });
    await User.findByIdAndUpdate(req.user.userId, { pushToken });
    res.status(200).json({ message: 'Push token registered' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const skip = (page - 1) * limit;

    const currentUser = await User.findById(currentUserId).select('blockedUsers interestedIn');
    const blockedUsers = currentUser?.blockedUsers || [];
    const interestedIn = currentUser?.interestedIn;

    let genderFilter = {};
    if (interestedIn === 'male') genderFilter = { gender: 'male' };
    else if (interestedIn === 'female') genderFilter = { gender: 'female' };

    const users = await User.find({ _id: { $ne: currentUserId, $nin: blockedUsers }, ...genderFilter })
      .select('name age gender profilePhoto location latitude longitude lookingFor isOnline lastSeen likes')
      .sort({ isOnline: -1, lastSeen: -1 }).skip(skip).limit(limit).lean();

    const transformedUsers = users.map(user => ({
      id: user._id, name: user.name, username: user.username, age: user.age, gender: user.gender,
      profilePhoto: user.profilePhoto, location: user.location, latitude: user.latitude, longitude: user.longitude,
      lookingFor: user.lookingFor, isOnline: user.isOnline, lastSeen: user.lastSeen, likesCount: user.likes?.length || 0
    }));

    res.status(200).json({ users: transformedUsers, page, limit });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const updateData = { ...req.body };
    delete updateData.password; delete updateData.email; delete updateData._id;

    const updatedUser = await User.findByIdAndUpdate(req.user.userId, { ...updateData, lastSeen: new Date() }, { new: true, select: '-password' });
    if (!updatedUser) return res.status(404).json({ error: 'User not found' });
    await deleteCache(`profile:${req.user.userId}`);

    res.status(200).json({ message: 'Profile updated', user: { id: updatedUser._id, name: updatedUser.name, email: updatedUser.email, age: updatedUser.age, gender: updatedUser.gender, profilePhoto: updatedUser.profilePhoto, additionalPhotos: updatedUser.additionalPhotos || [], location: updatedUser.location, interests: updatedUser.interests || [], interestedIn: updatedUser.interestedIn, bio: updatedUser.bio, height: updatedUser.height, bodyType: updatedUser.bodyType, smoking: updatedUser.smoking, drinking: updatedUser.drinking, exercise: updatedUser.exercise, diet: updatedUser.diet, occupation: updatedUser.occupation, company: updatedUser.company, graduation: updatedUser.graduation, school: updatedUser.school, hometown: updatedUser.hometown, currentCity: updatedUser.currentCity, lookingFor: updatedUser.lookingFor, relationshipStatus: updatedUser.relationshipStatus, kids: updatedUser.kids, languages: updatedUser.languages || [], isOnline: updatedUser.isOnline, lastSeen: updatedUser.lastSeen, createdAt: updatedUser.createdAt } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const cachedProfile = await getCache(`profile:${userId}`);
    if (cachedProfile) return res.status(200).json({ user: cachedProfile, cached: true });

    const user = await User.findById(userId, { password: 0 });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const userProfile = { id: user._id, name: user.name, username: user.username, email: user.email, age: user.age, gender: user.gender, interestedIn: user.interestedIn, profilePhoto: user.profilePhoto, additionalPhotos: user.additionalPhotos || [], location: user.location, latitude: user.latitude, longitude: user.longitude, interests: user.interests || [], bio: user.bio, height: user.height, bodyType: user.bodyType, smoking: user.smoking, drinking: user.drinking, exercise: user.exercise, diet: user.diet, occupation: user.occupation, company: user.company, graduation: user.graduation, school: user.school, hometown: user.hometown, currentCity: user.currentCity, lookingFor: user.lookingFor, relationshipStatus: user.relationshipStatus, kids: user.kids, languages: user.languages || [], likes: user.likes || [], coins: user.coins || 0, isOnline: user.isOnline, lastSeen: user.lastSeen, createdAt: user.createdAt };
    await setCache(`profile:${userId}`, userProfile, CACHE_TTL.USER_PROFILE);
    res.status(200).json({ user: userProfile });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/user/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId, { password: 0 });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.status(200).json({ user: { id: user._id, name: user.name, username: user.username, email: user.email, age: user.age, gender: user.gender, profilePhoto: user.profilePhoto, additionalPhotos: user.additionalPhotos || [], location: user.location, latitude: user.latitude, longitude: user.longitude, interests: user.interests || [], bio: user.bio, height: user.height, bodyType: user.bodyType, smoking: user.smoking, drinking: user.drinking, exercise: user.exercise, diet: user.diet, occupation: user.occupation, company: user.company, graduation: user.graduation, school: user.school, hometown: user.hometown, currentCity: user.currentCity, lookingFor: user.lookingFor, relationshipStatus: user.relationshipStatus, kids: user.kids, languages: user.languages || [], isOnline: user.isOnline, lastSeen: user.lastSeen, createdAt: user.createdAt } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== UPLOAD APIs ====================

app.post('/api/upload-image-public', async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ error: 'No image data' });
    const result = await cloudinary.uploader.upload(image, { folder: 'pingoo-profiles', public_id: `profile_${Date.now()}`, transformation: [{ width: 400, height: 400, crop: 'fill' }, { quality: 'auto' }] });
    res.status(200).json({ message: 'Image uploaded', imageUrl: result.secure_url });
  } catch (e) { res.status(500).json({ error: 'Failed to upload image' }); }
});

app.post('/api/upload-image-base64', authMiddleware, async (req, res) => {
  try {
    const { image, type } = req.body;
    if (!image) return res.status(400).json({ error: 'No image data' });
    const isProfile = type === 'profile';
    const opts = { folder: isProfile ? 'pingoo-profiles' : 'pingoo-media', public_id: `${isProfile ? 'profile' : 'media'}_${Date.now()}` };
    if (isProfile) opts.transformation = [{ width: 400, height: 400, crop: 'fill' }, { quality: 'auto' }];
    else opts.transformation = [{ quality: 'auto:best' }];
    const result = await cloudinary.uploader.upload(image, opts);
    res.status(200).json({ message: 'Image uploaded', imageUrl: result.secure_url });
  } catch (e) { res.status(500).json({ error: 'Failed to upload image' }); }
});

app.post('/api/upload-audio-base64', authMiddleware, async (req, res) => {
  try {
    const { audio } = req.body;
    if (!audio) return res.status(400).json({ error: 'No audio data' });
    const result = await cloudinary.uploader.upload(audio, { folder: 'pingoo-audio', public_id: `audio_${Date.now()}`, resource_type: 'video' });
    res.status(200).json({ message: 'Audio uploaded', audioUrl: result.secure_url });
  } catch (e) { res.status(500).json({ error: 'Failed to upload audio' }); }
});

app.delete('/api/delete-photo', authMiddleware, async (req, res) => {
  try {
    const { photoUrl, isProfilePhoto } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const publicId = photoUrl.split('/').pop().split('.')[0];
    try { await cloudinary.uploader.destroy(`pingoo-profiles/${publicId}`); } catch (e) {}
    if (isProfilePhoto) user.profilePhoto = null;
    else user.additionalPhotos = user.additionalPhotos.filter(p => p !== photoUrl);
    await user.save();
    res.status(200).json({ message: 'Photo deleted', user: { id: user._id, profilePhoto: user.profilePhoto, additionalPhotos: user.additionalPhotos || [] } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/set-profile-photo', authMiddleware, async (req, res) => {
  try {
    const { photoUrl } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.profilePhoto && user.profilePhoto !== photoUrl) {
      if (!user.additionalPhotos.includes(user.profilePhoto)) user.additionalPhotos.push(user.profilePhoto);
    }
    user.profilePhoto = photoUrl;
    user.additionalPhotos = user.additionalPhotos.filter(p => p !== photoUrl);
    await user.save();
    res.status(200).json({ message: 'Profile photo updated', user: { id: user._id, profilePhoto: user.profilePhoto, additionalPhotos: user.additionalPhotos || [] } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== LOCATION ====================
app.put('/api/location', authMiddleware, async (req, res) => {
  try {
    const { latitude, longitude, location } = req.body;
    if (!latitude || !longitude) return res.status(400).json({ error: 'Latitude and longitude required' });
    await User.findByIdAndUpdate(req.user.userId, { latitude, longitude, location: location || 'Unknown', lastSeen: new Date() });
    res.status(200).json({ message: 'Location updated' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== MESSAGES ====================
app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    const messages = await Message.find({ $or: [{ senderId: currentUserId, receiverId: userId }, { senderId: userId, receiverId: currentUserId }] }).sort({ timestamp: 1 });
    const formatted = messages.map(msg => ({
      id: msg._id, text: msg.isRecalled ? (msg.senderId.toString() === currentUserId ? 'You recalled this message' : 'This message was recalled') : (msg.message || ''),
      mediaUrl: msg.isRecalled ? null : (msg.mediaUrl || null), mediaType: msg.isRecalled ? 'text' : (msg.mediaType || 'text'),
      audioDuration: msg.audioDuration || null, replyTo: msg.replyTo || null, isRecalled: msg.isRecalled || false, isRead: msg.isRead || false,
      sent: msg.senderId.toString() === currentUserId, time: new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), timestamp: msg.timestamp
    }));
    res.status(200).json({ messages: formatted });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/messages/read/:userId', authMiddleware, async (req, res) => {
  try {
    await Message.updateMany({ senderId: req.params.userId, receiverId: req.user.userId, isRead: false }, { isRead: true });
    res.status(200).json({ message: 'Messages marked as read' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Send message via REST (for Lambda - replaces Socket.IO sendMessage)
app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { receiverId, message, mediaUrl, mediaType, replyTo } = req.body;
    const senderId = req.user.userId;
    if (!receiverId) return res.status(400).json({ error: 'receiverId required' });

    const newMessage = new Message({ senderId, receiverId, message: message || '', mediaUrl: mediaUrl || null, mediaType: mediaType || 'text', replyTo: replyTo || null, timestamp: new Date() });
    await newMessage.save();

    // Push notification
    const sender = await User.findById(senderId).select('name');
    const receiver = await User.findById(receiverId).select('pushToken');
    if (receiver?.pushToken) {
      let body = message;
      if (mediaType === 'image') body = '📷 Sent a photo';
      else if (mediaType === 'audio') body = '🎵 Sent an audio message';
      await sendPushNotification(receiver.pushToken, sender?.name || 'Someone', body, { type: 'message', senderId, senderName: sender?.name });
    }

    res.status(201).json({ messageId: newMessage._id, timestamp: newMessage.timestamp });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const conversations = await Message.aggregate([
      { $match: { $or: [{ senderId: new mongoose.Types.ObjectId(userId) }, { receiverId: new mongoose.Types.ObjectId(userId) }] } },
      { $sort: { timestamp: -1 } },
      { $group: { _id: { $cond: [{ $eq: ['$senderId', new mongoose.Types.ObjectId(userId)] }, '$receiverId', '$senderId'] }, lastMessage: { $first: '$message' }, lastMessageTime: { $first: '$timestamp' }, isFromMe: { $first: { $eq: ['$senderId', new mongoose.Types.ObjectId(userId)] } }, unreadCount: { $sum: { $cond: [{ $and: [{ $eq: ['$isRead', false] }, { $ne: ['$senderId', new mongoose.Types.ObjectId(userId)] }] }, 1, 0] } } } },
      { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
      { $unwind: '$user' },
      { $project: { id: '$_id', name: '$user.name', age: '$user.age', profilePhoto: '$user.profilePhoto', lastMessage: 1, lastMessageTime: 1, isFromMe: 1, unreadCount: 1 } },
      { $sort: { lastMessageTime: -1 } }
    ]);
    res.status(200).json({ conversations });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== LIKES ====================
app.post('/api/like/:userId', authMiddleware, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const { userId } = req.params;
    if (currentUserId === userId) return res.status(400).json({ error: 'Cannot like yourself' });

    const user = await User.findById(userId).select('likes pushToken newLikes');
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isLiked = (user.likes || []).some(id => id.toString() === currentUserId);
    if (isLiked) {
      user.likes = user.likes.filter(id => id.toString() !== currentUserId);
      user.newLikes = (user.newLikes || []).filter(l => l.userId.toString() !== currentUserId);
    } else {
      user.likes.push(currentUserId);
      if (!user.newLikes) user.newLikes = [];
      user.newLikes.push({ userId: currentUserId, timestamp: new Date(), read: false });
      if (user.pushToken) {
        const liker = await User.findById(currentUserId).select('name');
        await sendPushNotification(user.pushToken, 'New Like! 💖', `${liker?.name || 'Someone'} liked your profile`, { type: 'like', likerId: currentUserId });
      }
    }
    await user.save();
    await deleteCache(`profile:${userId}`);
    res.status(200).json({ message: isLiked ? 'Unliked' : 'Liked', isLiked: !isLiked, likeCount: user.likes.length });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/like-status/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('likes');
    if (!user) return res.status(404).json({ error: 'User not found' });
    const isLiked = (user.likes || []).some(id => id.toString() === req.user.userId);
    res.status(200).json({ isLiked, likeCount: (user.likes || []).length });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/new-likes', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('newLikes.userId', 'name age profilePhoto').select('newLikes');
    if (!user) return res.status(404).json({ error: 'User not found' });
    const likes = (user.newLikes || []).filter(l => !l.read).map(l => ({ id: l.userId._id, name: l.userId.name, age: l.userId.age, profilePhoto: l.userId.profilePhoto, timestamp: l.timestamp }));
    res.status(200).json({ likes });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/all-likes', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('newLikes.userId', 'name age profilePhoto').select('newLikes');
    if (!user) return res.status(404).json({ error: 'User not found' });
    const likes = (user.newLikes || []).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).map(l => ({ id: l.userId._id, name: l.userId.name, age: l.userId.age, profilePhoto: l.userId.profilePhoto, timestamp: l.timestamp, read: l.read, type: l.type || 'profile_like', moodId: l.moodId || null }));
    res.status(200).json({ likes });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mark-likes-read', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.userId, { $set: { 'newLikes.$[].read': true } });
    res.status(200).json({ message: 'Likes marked as read' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== CHAT ACCESS / COINS ====================
app.get('/api/chat-access/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const access = user.chatAccess?.find(a => a.userId.toString() === req.params.userId);
    const hasAccess = access && new Date(access.expiresAt) > new Date();
    res.status(200).json({ hasAccess, expiresAt: access?.expiresAt, coins: user.coins });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/purchase-chat/:userId', authMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.coins < 10) return res.status(400).json({ error: 'Insufficient coins' });

    user.coins -= 10;
    const expiresAt = new Date(Date.now() + 6 * 60 * 60 * 1000);
    const idx = user.chatAccess?.findIndex(a => a.userId.toString() === userId);
    if (idx !== undefined && idx !== -1) user.chatAccess[idx].expiresAt = expiresAt;
    else { if (!user.chatAccess) user.chatAccess = []; user.chatAccess.push({ userId, expiresAt }); }
    await user.save();
    res.status(200).json({ message: 'Chat access purchased', coins: user.coins, expiresAt });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/coins', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('coins');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.status(200).json({ coins: user.coins });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/spin-availability', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('lastSpinDate');
    if (!user) return res.status(404).json({ error: 'User not found' });
    const canSpin = !user.lastSpinDate || (new Date() - new Date(user.lastSpinDate)) >= 24 * 60 * 60 * 1000;
    const nextSpinTime = !canSpin ? new Date(new Date(user.lastSpinDate).getTime() + 24 * 60 * 60 * 1000) : null;
    res.status(200).json({ canSpin, nextSpinTime });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/spin-wheel', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.lastSpinDate && (new Date() - user.lastSpinDate) < 24 * 60 * 60 * 1000) return res.status(400).json({ error: 'You can only spin once per day' });

    const segments = [10, 20, 10, 30, 10, 20, 10, 50];
    const randomIndex = Math.floor(Math.random() * segments.length);
    const wonCoins = segments[randomIndex];
    if (typeof user.coins !== 'number') user.coins = 50;
    user.coins += wonCoins;
    user.lastSpinDate = new Date();
    await user.save();
    res.status(200).json({ coins: wonCoins, segmentIndex: randomIndex, totalCoins: user.coins, nextSpinTime: new Date(Date.now() + 24 * 60 * 60 * 1000) });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== BLOCK / REPORT ====================
app.post('/api/block/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!(user.blockedUsers || []).includes(req.params.userId)) { user.blockedUsers = [...(user.blockedUsers || []), req.params.userId]; await user.save(); }
    res.status(200).json({ message: 'User blocked' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/unblock/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.blockedUsers = (user.blockedUsers || []).filter(id => id.toString() !== req.params.userId);
    await user.save();
    res.status(200).json({ message: 'User unblocked' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/blocked-users', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('blockedUsers', 'name age profilePhoto');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.status(200).json({ blockedUsers: (user.blockedUsers || []).map(u => ({ _id: u._id, name: u.name, age: u.age, profilePhoto: u.profilePhoto })) });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/blocked-by/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('blockedUsers');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.status(200).json({ isBlockedByUser: (user.blockedUsers || []).some(id => id.toString() === req.user.userId) });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/report/:userId', authMiddleware, async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason required' });
    const reportedUser = await User.findById(req.params.userId);
    if (!reportedUser) return res.status(404).json({ error: 'User not found' });
    reportedUser.reports = [...(reportedUser.reports || []), { reportedBy: req.user.userId, reason: reason.trim(), timestamp: new Date() }];
    await reportedUser.save();
    res.status(200).json({ message: 'User reported' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== MOOD APIs ====================
app.post('/api/mood', authMiddleware, async (req, res) => {
  try {
    const { video, thumbnail, caption, mood } = req.body;
    if (!video) return res.status(400).json({ error: 'Video required' });

    const result = await cloudinary.uploader.upload(video, { folder: 'pingoo-moods', resource_type: 'video', transformation: [{ quality: 'auto', duration: 15 }] });
    let thumbnailUrl = null;
    if (thumbnail) {
      const thumbResult = await cloudinary.uploader.upload(thumbnail, { folder: 'pingoo-moods-thumbnails', transformation: [{ width: 400, height: 700, crop: 'fill' }, { quality: 'auto' }] });
      thumbnailUrl = thumbResult.secure_url;
    }

    const newMood = new Mood({ userId: req.user.userId, videoUrl: result.secure_url, thumbnailUrl, caption: caption || '', mood: mood || 'vibing' });
    await newMood.save();
    res.status(201).json({ message: 'Mood posted!', mood: newMood });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/moods', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const skip = (page - 1) * 10;
    const currentUserId = req.user.userId;
    const currentUser = await User.findById(currentUserId).select('blockedUsers');
    const blockedUsers = currentUser?.blockedUsers || [];

    const moods = await Mood.find({ isActive: true, userId: { $nin: [...blockedUsers, currentUserId] } })
      .sort({ createdAt: -1 }).skip(skip).limit(10)
      .populate('userId', 'name age profilePhoto gender isOnline')
      .populate('comments.userId', 'name profilePhoto').lean();

    const transformed = moods.map(m => ({
      id: m._id, user: { id: m.userId._id, name: m.userId.name, age: m.userId.age, profilePhoto: m.userId.profilePhoto, gender: m.userId.gender, isOnline: m.userId.isOnline },
      videoUrl: m.videoUrl, thumbnailUrl: m.thumbnailUrl || null, caption: m.caption, mood: m.mood,
      likesCount: m.likes.length, isLiked: m.likes.some(id => id.toString() === currentUserId),
      comments: m.comments.slice(-20).map(c => ({ id: c._id, user: { id: c.userId._id, name: c.userId.name, profilePhoto: c.userId.profilePhoto }, text: c.text, createdAt: c.createdAt })),
      commentsCount: m.comments.length, views: m.views, createdAt: m.createdAt
    }));
    res.status(200).json({ moods: transformed, page });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mood/:moodId/like', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const mood = await Mood.findById(req.params.moodId);
    if (!mood) return res.status(404).json({ error: 'Mood not found' });

    const isLiked = mood.likes.some(id => id.toString() === userId);
    if (isLiked) { mood.likes = mood.likes.filter(id => id.toString() !== userId); }
    else {
      mood.likes.push(userId);
      if (mood.userId.toString() !== userId) {
        const moodOwner = await User.findById(mood.userId).select('pushToken newLikes');
        const liker = await User.findById(userId).select('name');
        if (moodOwner?.pushToken) await sendPushNotification(moodOwner.pushToken, '❤️ Mood Liked!', `${liker?.name || 'Someone'} liked your mood`, { type: 'mood_like', moodId: req.params.moodId });
        if (!moodOwner.newLikes) moodOwner.newLikes = [];
        moodOwner.newLikes.push({ userId, timestamp: new Date(), read: false, type: 'mood_like', moodId: req.params.moodId });
        await moodOwner.save();
      }
    }
    await mood.save();
    res.status(200).json({ isLiked: !isLiked, likesCount: mood.likes.length });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mood/:moodId/comment', authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    const userId = req.user.userId;
    if (!text?.trim()) return res.status(400).json({ error: 'Comment text required' });

    const mood = await Mood.findById(req.params.moodId);
    if (!mood) return res.status(404).json({ error: 'Mood not found' });
    mood.comments.push({ userId, text: text.trim() });
    await mood.save();

    const user = await User.findById(userId).select('name profilePhoto');
    if (mood.userId.toString() !== userId) {
      const moodOwner = await User.findById(mood.userId).select('pushToken newLikes');
      if (moodOwner?.pushToken) await sendPushNotification(moodOwner.pushToken, '💬 New Comment!', `${user?.name || 'Someone'} commented: "${text.trim().substring(0, 50)}"`, { type: 'mood_comment', moodId: req.params.moodId });
      if (!moodOwner.newLikes) moodOwner.newLikes = [];
      moodOwner.newLikes.push({ userId, timestamp: new Date(), read: false, type: 'mood_comment', moodId: req.params.moodId });
      await moodOwner.save();
    }
    res.status(201).json({ comment: { id: mood.comments[mood.comments.length - 1]._id, user: { id: userId, name: user.name, profilePhoto: user.profilePhoto }, text: text.trim(), createdAt: new Date() } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mood/:moodId/view', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const mood = await Mood.findById(req.params.moodId);
    if (!mood) return res.status(404).json({ error: 'Mood not found' });
    if (mood.userId.toString() === userId || mood.viewedBy.includes(userId)) return res.status(200).json({ views: mood.views });
    mood.viewedBy.push(userId); mood.views = mood.viewedBy.length; await mood.save();
    res.status(200).json({ views: mood.views });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/mood/:moodId', authMiddleware, async (req, res) => {
  try {
    const mood = await Mood.findOne({ _id: req.params.moodId, userId: req.user.userId });
    if (!mood) return res.status(404).json({ error: 'Mood not found' });
    await Mood.findByIdAndDelete(req.params.moodId);
    res.status(200).json({ message: 'Mood deleted' });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/my-moods', authMiddleware, async (req, res) => {
  try {
    const moods = await Mood.find({ userId: req.user.userId }).sort({ createdAt: -1 }).lean();
    const transformed = moods.map(m => ({ id: m._id, videoUrl: m.videoUrl, thumbnailUrl: m.thumbnailUrl || null, caption: m.caption, mood: m.mood, likesCount: m.likes.length, commentsCount: m.comments.length, views: m.views || 0, isActive: m.isActive, createdAt: m.createdAt }));
    res.status(200).json({ moods: transformed });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/mood/:moodId/toggle', authMiddleware, async (req, res) => {
  try {
    const mood = await Mood.findOne({ _id: req.params.moodId, userId: req.user.userId });
    if (!mood) return res.status(404).json({ error: 'Mood not found' });
    mood.isActive = !mood.isActive; await mood.save();
    res.status(200).json({ message: mood.isActive ? 'Mood visible' : 'Mood hidden', isActive: mood.isActive });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mood-chat/:userId', authMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user.userId;
    if (currentUserId === userId) return res.status(400).json({ error: 'Cannot chat with yourself' });

    const user = await User.findById(currentUserId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const existingAccess = user.chatAccess?.find(a => a.userId.toString() === userId);
    if (existingAccess && new Date(existingAccess.expiresAt) > new Date()) return res.status(200).json({ message: 'Already have access', coins: user.coins, expiresAt: existingAccess.expiresAt });
    if (user.coins < 30) return res.status(400).json({ error: 'Insufficient coins', required: 30, current: user.coins });

    user.coins -= 30;
    const expiresAt = new Date(Date.now() + 6 * 60 * 60 * 1000);
    const idx = user.chatAccess?.findIndex(a => a.userId.toString() === userId);
    if (idx !== undefined && idx !== -1) user.chatAccess[idx].expiresAt = expiresAt;
    else { if (!user.chatAccess) user.chatAccess = []; user.chatAccess.push({ userId, expiresAt }); }
    await user.save();
    res.status(200).json({ message: 'Chat access purchased', coins: user.coins, expiresAt });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/mood/:moodId/report', authMiddleware, async (req, res) => {
  try {
    const { reason } = req.body;
    const userId = req.user.userId;
    if (!reason?.trim()) return res.status(400).json({ error: 'Reason required' });

    const mood = await Mood.findById(req.params.moodId);
    if (!mood) return res.status(404).json({ error: 'Mood not found' });
    if (mood.reports?.some(r => r.userId.toString() === userId)) return res.status(400).json({ error: 'Already reported' });

    mood.reports.push({ userId, reason: reason.trim() });
    if (mood.reports.length >= 2) {
      mood.isActive = false;
      const moodOwner = await User.findById(mood.userId);
      if (moodOwner) {
        moodOwner.strikes = (moodOwner.strikes || 0) + 1;
        if (moodOwner.strikes >= 3) moodOwner.isBanned = true;
        await moodOwner.save();
        if (moodOwner.pushToken) {
          const title = moodOwner.strikes >= 3 ? '⛔ Account Banned' : '⚠️ Content Warning';
          const body = moodOwner.strikes >= 3 ? 'Your account has been banned.' : `Your mood was removed. Strike ${moodOwner.strikes}/3.`;
          await sendPushNotification(moodOwner.pushToken, title, body, { type: 'strike' });
        }
      }
    }
    await mood.save();
    res.status(200).json({ message: 'Mood reported', hidden: mood.reports.length >= 2 });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== SEARCH / USERNAME ====================
app.get('/api/search', authMiddleware, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 2) return res.status(400).json({ error: 'Query too short' });
    const users = await User.find({ $or: [{ username: { $regex: q.trim(), $options: 'i' } }, { name: { $regex: q.trim(), $options: 'i' } }], _id: { $ne: req.user.userId } }).select('name username age gender profilePhoto isOnline').limit(20).lean();
    res.status(200).json({ users: users.map(u => ({ id: u._id, name: u.name, username: u.username, age: u.age, gender: u.gender, profilePhoto: u.profilePhoto, isOnline: u.isOnline })) });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/username', authMiddleware, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username || username.trim().length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    const sanitized = username.toLowerCase().replace(/[^a-z0-9_]/g, '').trim();
    if (sanitized.length < 3 || sanitized.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
    const existing = await User.findOne({ username: sanitized, _id: { $ne: req.user.userId } });
    if (existing) return res.status(400).json({ error: 'Username taken' });
    await User.findByIdAndUpdate(req.user.userId, { username: sanitized });
    res.status(200).json({ message: 'Username updated', username: sanitized });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/username/check', authMiddleware, async (req, res) => {
  try {
    const { username } = req.query;
    if (!username || username.length < 3) return res.status(400).json({ available: false });
    const sanitized = username.toLowerCase().replace(/[^a-z0-9_]/g, '');
    const existing = await User.findOne({ username: sanitized, _id: { $ne: req.user.userId } });
    res.status(200).json({ available: !existing, username: sanitized });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Payment test
app.post('/api/payment/test-purchase', authMiddleware, async (req, res) => {
  const { coins } = req.body;
  if (!coins || coins <= 0) return res.status(400).json({ error: 'Invalid amount' });
  try {
    await User.findByIdAndUpdate(req.user.userId, { $inc: { coins } });
    const user = await User.findById(req.user.userId).select('coins');
    res.json({ success: true, coins: user.coins, purchased: coins });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

module.exports = { app, connectDB, sendPushNotification };
