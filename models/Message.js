const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  message: {
    type: String,
    required: false
  },
  mediaUrl: {
    type: String
  },
  mediaType: {
    type: String,
    enum: ['image', 'video', 'text'],
    default: 'text'
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  isRead: {
    type: Boolean,
    default: false
  },
  isRecalled: {
    type: Boolean,
    default: false
  }
});

module.exports = mongoose.model('Message', messageSchema);