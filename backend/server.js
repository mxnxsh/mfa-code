// backend/server.js

const express = require('express');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ⚠️ In real life, use a database
const users = {}; // username -> { secret, tempSecret }

// JWT secret (use env var)
const JWT_SECRET = 'supersecretjwtkey';

// POST /api/setup-mfa 
app.post('/api/setup-mfa', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ message: 'Username required' });

  const secret = speakeasy.generateSecret({ name: `MFA-SSO-Demo (${username})` });
  users[username] = { tempSecret: secret.base32 };

  const qrDataURL = await qrcode.toDataURL(secret.otpauth_url);

  res.json({
    message: 'Scan QR code in Authenticator App',
    qr: qrDataURL,
    secret: secret.base32
  });
});

// POST /api/verify-mfa-setup
app.post('/api/verify-mfa-setup', (req, res) => {
  const { username, token } = req.body;
  const user = users[username];
  if (!user || !user.tempSecret) return res.status(400).json({ message: 'No MFA setup found' });

  const verified = speakeasy.totp.verify({
    secret: user.tempSecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (verified) {
    user.secret = user.tempSecret;
    delete user.tempSecret;
    res.json({ message: 'MFA setup complete! 🎉' });
  } else {
    res.status(400).json({ message: 'Invalid code, please try again.' });
  }
});

// POST /api/login (fake passwordless login)
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!users[username]) {
    users[username] = {}; // auto-create for demo
  }
  res.json({ message: 'User found, now enter MFA code.' });
});

// POST /api/verify-login
app.post('/api/verify-login', (req, res) => {
  const { username, token } = req.body;
  const user = users[username];
  if (!user || !user.secret) return res.status(400).json({ message: 'MFA not set up' });

  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (verified) {
    const jwtToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: '10m' });
    res.json({ message: 'MFA verified! ✅', token: jwtToken });
  } else {
    res.status(401).json({ message: 'Invalid MFA code' });
  }
});

// GET /api/protected
app.get('/api/protected', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'No token' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: `Hello ${decoded.username}, you accessed protected data! 🔒` });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(3000, () => console.log('🚀 Server running at http://localhost:3000'));
