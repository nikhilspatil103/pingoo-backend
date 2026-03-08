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
    enum: ['image', 'video', 'audio', 'text'],
    default: 'text'
  },
  audioDuration: {
    type: Number
  },
  replyTo: {
    messageId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Message'
    },
    text: String
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
  },
  replyTo: {
    messageId: String,
    text: String
  }
});

module.exports = mongoose.model('Message', messageSchema);