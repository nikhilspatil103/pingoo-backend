const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String },
  authProvider: { type: String, enum: ['local', 'google'], default: 'local' },
  age: { type: Number, required: true, min: 18 },
  gender: { type: String, required: true, enum: ['male', 'female'] },
  interestedIn: { type: String, enum: ['male', 'female', 'both'] },
  profilePhoto: { type: String },
  additionalPhotos: [{ type: String }],
  location: { type: String },
  latitude: { type: Number },
  longitude: { type: Number },
  interests: [{ type: String }],
  bio: { type: String },
  height: { type: Number },
  bodyType: { type: String },
  smoking: { type: String },
  drinking: { type: String },
  exercise: { type: String },
  diet: { type: String },
  occupation: { type: String },
  company: { type: String },
  graduation: { type: String },
  school: { type: String },
  hometown: { type: String },
  currentCity: { type: String },
  lookingFor: { type: String },
  relationshipStatus: { type: String },
  kids: { type: String },
  languages: [{ type: String }],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  reports: [{
    reportedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  coins: { type: Number, default: 50 },
  chatAccess: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    expiresAt: { type: Date }
  }],
  lastSpinDate: { type: Date },
  dailyStreak: { type: Number, default: 0 },
  lastDailyReward: { type: Date },
  pushToken: { type: String },
  newLikes: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false },
    type: { type: String, enum: ['profile_like', 'mood_like', 'mood_comment'], default: 'profile_like' },
    moodId: { type: mongoose.Schema.Types.ObjectId, ref: 'Mood' }
  }],
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  strikes: { type: Number, default: 0 },
  isBanned: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Indexes for fast queries
userSchema.index({ gender: 1, isBanned: 1 });
userSchema.index({ isOnline: 1 });
userSchema.index({ createdAt: -1 });

module.exports = mongoose.model('User', userSchema);
