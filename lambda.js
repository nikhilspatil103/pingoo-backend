const serverless = require('serverless-http');
const mongoose = require('mongoose');
const { app } = require('./app');

// Ensure MongoDB is connected before handling requests
const handler = serverless(app);

module.exports.handler = async (event, context) => {
  // Wait for MongoDB connection on cold starts
  if (mongoose.connection.readyState !== 1) {
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pingoo';
    console.log('Connecting to MongoDB from Lambda...');
    try {
      await mongoose.connect(MONGODB_URI, {
        maxPoolSize: 2,
        minPoolSize: 1,
        socketTimeoutMS: 45000,
        serverSelectionTimeoutMS: 15000,
      });
      console.log('MongoDB connected successfully, state:', mongoose.connection.readyState);
    } catch (e) {
      console.error('MongoDB connection FAILED. Error:', e.message);
      console.error('MongoDB URI prefix:', MONGODB_URI.substring(0, 30) + '...');
    }
  } else {
    console.log('MongoDB already connected, state:', mongoose.connection.readyState);
  }
  return handler(event, context);
};
