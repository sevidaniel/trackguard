require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const User = require('./models/User');
const Asset = require('./models/Asset');
const AuditLog = require('./models/AuditLog');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 15 * 60 * 1000 }
}));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ Connection Error:', err));

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.redirect('/login');
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.session.role !== 'Admin') {
    return res.status(403).send('Access Denied: Admin privileges required.');
  }
  next();
};

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user._id;
    req.session.userName = user.name;
    req.session.role = user.role;

    await AuditLog.create({
      action: 'LOGIN',
      performedBy: user.email,
      details: 'User logged in successfully'
    });

    return res.redirect('/dashboard');
  }

  res.render('login', { error: 'Invalid email or password' });
});

app.get('/dashboard', requireAuth, async (req, res) => {
  const assets = await Asset.find();
  const logs = req.session.role === 'Admin' ? await AuditLog.find().sort({ timestamp: -1 }) : [];
  
  res.render('dashboard', {
    user: { name: req.session.userName, role: req.session.role },
    assets,
    logs
  });
});

app.post('/assets/add', requireAuth, requireAdmin, async (req, res) => {
  const { tagNumber, name, category } = req.body;
  
  await Asset.create({ tagNumber, name, category });
  await AuditLog.create({
    action: 'ASSET_CREATED',
    performedBy: req.session.userName,
    details: `Created asset ${tagNumber} - ${name}`
  });

  res.redirect('/dashboard');
});

app.post('/assets/transfer', requireAuth, async (req, res) => {
  const { assetId, assignedTo, status } = req.body;
  
  const asset = await Asset.findByIdAndUpdate(assetId, { assignedTo, status });
  await AuditLog.create({
    action: 'ASSET_TRANSFERRED',
    performedBy: req.session.userName,
    details: `Reassigned asset ${asset.tagNumber} to ${assignedTo} (${status})`
  });

  res.redirect('/dashboard');
});

// GET /register
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// POST /register
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.render('register', { error: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({
    name,
    email,
    password: hashedPassword,
    role: 'Staff' // Default non-admin role
  });

  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`🚀 Server active at http://localhost:${PORT}`);
  
  const adminExists = await User.findOne({ email: 'admin@trackguard.com' });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await User.create({
      name: 'System Admin',
      email: 'admin@trackguard.com',
      password: hashedPassword,
      role: 'Admin'
    });
    console.log('👤 Default Admin created: admin@trackguard.com / admin123');
  }
});