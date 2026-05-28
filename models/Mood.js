const mongoose = require('mongoose');

const moodSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  videoUrl: { type: String, required: true },
  thumbnailUrl: { type: String },
  caption: { type: String, maxlength: 150 },
  mood: { type: String }, // happy, sad, excited, chill, etc.
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true, maxlength: 200 },
    createdAt: { type: Date, default: Date.now }
  }],
  views: { type: Number, default: 0 },
  viewedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  reports: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: { type: String },
    createdAt: { type: Date, default: Date.now }
  }],
  isActive: { type: Boolean, default: true },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) }, // 7 days expiry
  createdAt: { type: Date, default: Date.now }
});

moodSchema.index({ createdAt: -1 });
moodSchema.index({ userId: 1 });
moodSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Auto-delete expired moods

module.exports = mongoose.model('Mood', moodSchema);
