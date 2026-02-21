const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: { type: Number, required: true, min: 18 },
  gender: { type: String, required: true, enum: ['male', 'female', 'other'] },
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
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
