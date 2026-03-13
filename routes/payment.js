const express = require('express');
const router = express.Router();
const Razorpay = require('razorpay');
const crypto = require('crypto');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Auth middleware
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Initiate payment
router.post('/initiate', auth, async (req, res) => {
  try {
    const { coins, amount } = req.body;
    
    const options = {
      amount: amount * 100, // Convert to paise
      currency: 'INR',
      receipt: `coin_${Date.now()}`,
      notes: {
        userId: req.user.id,
        coins: coins
      }
    };

    const order = await razorpay.orders.create(options);
    
    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify payment
router.post('/verify', auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    
    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    if (razorpay_signature === expectedSign) {
      // Add coins to user
      await User.findByIdAndUpdate(req.user.id, {
        $inc: { coins: req.body.coins }
      });

      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Invalid signature' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;