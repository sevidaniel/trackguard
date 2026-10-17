const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

// Safely import Middlewares
const authModule = require('./middleware/auth');
const isAuthenticated = typeof authModule === 'function' ? authModule : (authModule.isAuthenticated || ((req, res, next) => next()));

const rateLimitModule = require('./middleware/rateLimit');
const loginLimiter = rateLimitModule.loginLimiter || ((req, res, next) => next());
const apiLimiter = rateLimitModule.apiLimiter || ((req, res, next) => next());

const errorHandler = require('./middleware/errorHandler');

const app = express();

// Base Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(apiLimiter);

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'trackguard_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 3600000 }
}));

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

const assetSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: 'No description provided' },
  employeeAccountable: { type: String, required: true },
  status: { type: String, default: 'Active' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { strict: false });

const auditSchema = new mongoose.Schema({
  action: { type: String, required: true },
  performedBy: { type: String, required: true },
  details: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Asset = mongoose.models.Asset || mongoose.model('Asset', assetSchema);
const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditSchema);

// --- Routes ---

app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

// GET Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// GET Register Page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// POST Register Handle
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = email ? email.trim().toLowerCase() : '';

    if (!cleanEmail || !password) {
      return res.status(400).render('register', { error: 'Please provide both email and password.' });
    }

    const existingUser = await User.findOne({ email: cleanEmail });
    if (existingUser) {
      return res.status(400).render('register', { error: 'Account with this email already exists.' });
    }

    const newUser = new User({ email: cleanEmail, password, role: 'Admin' });
    await newUser.save();

    await AuditLog.create({
      action: 'USER_REGISTERED',
      performedBy: cleanEmail,
      details: `New admin account registered: ${cleanEmail}`
    });

    res.redirect('/login');
  } catch (err) {
    res.status(500).render('register', { error: 'Failed to create account.' });
  }
});

// POST Login Handle
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = email ? email.trim().toLowerCase() : '';

    const user = await User.findOne({ email: cleanEmail });

    if (!user || user.password !== password) {
      return res.status(401).render('login', { error: 'Invalid email or password.' });
    }

    req.session.user = { email: user.email, role: user.role || 'Admin' };

    req.session.save((err) => {
      if (err) {
        return res.status(500).render('login', { error: 'Session storage error.' });
      }
      res.redirect('/dashboard');
    });

  } catch (err) {
    res.status(500).render('login', { error: 'Error processing login request.' });
  }
});

// Protected Dashboard Route - Inii-fetch LAHAT ng assets nang walang limit sa database query
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const assets = await Asset.find().sort({ updatedAt: -1 });
    const auditLogs = await AuditLog.find().sort({ timestamp: -1 });
    res.render('dashboard', { assets, auditLogs });
  } catch (err) {
    console.error('Dashboard Load Error:', err);
    res.status(500).send('Error loading dashboard');
  }
});

// Protected Add Asset Route
app.post('/add-asset', isAuthenticated, async (req, res) => {
  try {
    const { name, employeeAccountable, description } = req.body;
    
    const newAsset = new Asset({
      name: name || 'Unnamed Asset',
      employeeAccountable: employeeAccountable || 'Unassigned',
      description: description || 'No description provided'
    });
    
    await newAsset.save();

    await AuditLog.create({
      action: 'ASSET_REGISTERED',
      performedBy: (req.session && req.session.user) ? req.session.user.email : 'admin@trackguard.com',
      details: `Registered asset ${newAsset.name} (#TG-${newAsset._id.toString().slice(-6)}) assigned to ${newAsset.employeeAccountable}.`
    });

    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send(`Failed to add asset: ${err.message}`);
  }
});

// Protected Update Asset Route
app.post('/update-asset', isAuthenticated, async (req, res) => {
  try {
    const { assetId, employeeAccountable } = req.body;

    const updatedAsset = await Asset.findByIdAndUpdate(
      assetId,
      { 
        employeeAccountable: employeeAccountable,
        updatedAt: Date.now()
      },
      { returnDocument: 'after' }
    );

    if (updatedAsset) {
      await AuditLog.create({
        action: 'EMPLOYEE_REASSIGNED',
        performedBy: (req.session && req.session.user) ? req.session.user.email : 'admin@trackguard.com',
        details: `Reassigned asset ${updatedAsset.name} (#TG-${updatedAsset._id.toString().slice(-6)}) to ${employeeAccountable}.`
      });
    }

    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Failed to update asset');
  }
});

// Protected Delete Asset Route
app.post('/delete-asset', isAuthenticated, async (req, res) => {
  try {
    const { assetId } = req.body;

    const deletedAsset = await Asset.findByIdAndDelete(assetId);

    if (deletedAsset) {
      await AuditLog.create({
        action: 'MISINPUT_DELETED',
        performedBy: (req.session && req.session.user) ? req.session.user.email : 'admin@trackguard.com',
        details: `Deleted misinput asset "${deletedAsset.name}" (#TG-${deletedAsset._id.toString().slice(-6)}).`
      });
    }

    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Failed to delete asset');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.use(errorHandler);

// DB Connection & Server Start
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/trackguard';

mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('Connected to MongoDB Atlas');

    try {
      await Asset.collection.dropIndex('tagNumber_1');
    } catch (indexErr) {}

    app.listen(PORT, () => console.log(`TrackGuard server running on http://localhost:${PORT}`));
  })
  .catch(err => console.error('MongoDB connection error:', err));