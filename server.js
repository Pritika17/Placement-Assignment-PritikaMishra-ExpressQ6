const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// In-memory storage for registered users
const users = [];

// Secret key for JWT
const jwtSecret = 'your_secret_key';

// Endpoint: POST /signup
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the username is already taken
    if (users.find(user => user.username === username)) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user object
    const user = { username, password: hashedPassword };

    // Add the user to the array
    users.push(user);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint: POST /login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user with the given username
    const user = users.find(user => user.username === username);

    // If the user is not found or the password is incorrect, return an error
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ username: user.username }, jwtSecret);

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Middleware: Verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Protected endpoint: GET /profile
app.get('/profile', verifyToken, (req, res) => {
  res.json({ username: req.user.username });
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
