const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// In-memory storage (replace with database later)
const users = [];

// Signup API
app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ error: 'Email already exists' });
  }

  const user = { id: users.length + 1, name, email, password };
  users.push(user);

  res.status(201).json({ message: 'User created successfully', userId: user.id });
});

app.listen(PORT, () => {
  console.log(`Koozi backend running on port ${PORT}`);
});
