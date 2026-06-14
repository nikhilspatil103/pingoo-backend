// Local development server with Socket.IO support
// For Lambda deployment, use lambda.js instead

const { app, connectDB, sendPushNotification } = require('./app');
const { createServer } = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const User = require('./models/User');
const Message = require('./models/Message');

const server = createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;

// Socket.IO connection handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join', async (userId) => {
    connectedUsers.set(userId, socket.id);
    socket.userId = userId;
    try { await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() }); } catch (e) {}
  });

  socket.on('sendMessage', async (data) => {
    const { receiverId, message, senderId, mediaUrl, mediaType, tempId, replyTo } = data;
    try {
      const newMessage = new Message({ senderId, receiverId, message: message || '', mediaUrl: mediaUrl || null, mediaType: mediaType || 'text', replyTo: replyTo || null, timestamp: new Date() });
      await newMessage.save();

      const sender = await User.findById(senderId).select('name');
      const receiver = await User.findById(receiverId).select('pushToken isOnline');

      const receiverSocketId = connectedUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', { messageId: newMessage._id, senderId, message: message || '', mediaUrl: mediaUrl || null, mediaType: mediaType || 'text', replyTo: replyTo || null, timestamp: newMessage.timestamp });
      }

      if (receiver?.pushToken) {
        let body = message;
        if (mediaType === 'image') body = '📷 Sent a photo';
        else if (mediaType === 'audio') body = '🎵 Sent an audio message';
        await sendPushNotification(receiver.pushToken, sender?.name || 'Someone', body, { type: 'message', senderId, senderName: sender?.name });
      }

      socket.emit('messageSaved', { tempId, messageId: newMessage._id, timestamp: newMessage.timestamp });
    } catch (e) { console.error('Error saving message:', e); }
  });

  socket.on('typing', (data) => {
    const receiverSocketId = connectedUsers.get(data.receiverId);
    if (receiverSocketId) io.to(receiverSocketId).emit('userTyping', { userId: data.userId });
  });

  socket.on('stopTyping', (data) => {
    const receiverSocketId = connectedUsers.get(data.receiverId);
    if (receiverSocketId) io.to(receiverSocketId).emit('userStopTyping', { userId: data.userId });
  });

  socket.on('deleteMessage', async (data) => {
    try {
      await Message.findByIdAndDelete(data.messageId);
      const receiverSocketId = connectedUsers.get(data.receiverId);
      if (receiverSocketId) io.to(receiverSocketId).emit('messageDeleted', { messageId: data.messageId, senderId: data.senderId, receiverId: data.receiverId });
    } catch (e) {}
  });

  socket.on('recallMessage', async (data) => {
    try {
      const message = await Message.findByIdAndUpdate(data.messageId, { message: 'This message was recalled', isRecalled: true, mediaUrl: null, mediaType: 'text' }, { new: true });
      if (message) {
        const sender = await User.findById(data.senderId).select('name');
        const receiverSocketId = connectedUsers.get(data.receiverId);
        if (receiverSocketId) io.to(receiverSocketId).emit('messageRecalled', { messageId: data.messageId, senderId: data.senderId, receiverId: data.receiverId, senderName: sender?.name || 'User' });
      }
    } catch (e) {}
  });

  socket.on('markMessageSeen', async (data) => {
    try {
      await Message.findByIdAndUpdate(data.messageId, { isRead: true });
      const senderSocketId = connectedUsers.get(data.senderId);
      if (senderSocketId) io.to(senderSocketId).emit('messageSeen', { messageId: data.messageId });
    } catch (e) {}
  });

  socket.on('disconnect', async () => {
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
      try { await User.findByIdAndUpdate(socket.userId, { isOnline: false, lastSeen: new Date() }); } catch (e) {}
    }
  });
});

server.listen(PORT, () => {
  console.log(`Pingoo backend running on port ${PORT}`);
});
