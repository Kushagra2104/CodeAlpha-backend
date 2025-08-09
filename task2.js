const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/eventdb';
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// ----- Mongoose models -----
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error', err));

const { Schema } = mongoose;

const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const EventSchema = new Schema({
  title: { type: String, required: true },
  description: String,
  location: String,
  startDate: Date,
  endDate: Date,
  capacity: Number, // optional
  createdAt: { type: Date, default: Date.now }
});
const Event = mongoose.model('Event', EventSchema);

const RegistrationSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  event: { type: Schema.Types.ObjectId, ref: 'Event', required: true },
  status: { type: String, enum: ['registered','cancelled'], default: 'registered' },
  createdAt: { type: Date, default: Date.now },
  extra: Schema.Types.Mixed // e.g. answers to registration form
});
RegistrationSchema.index({ user: 1, event: 1 }, { unique: true }); // one registration per user per event
const Registration = mongoose.model('Registration', RegistrationSchema);

// ----- Auth middleware -----
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed Authorization header' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // contains id and email
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ----- Auth routes -----
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ----- Event routes -----
// Public: list events (with simple pagination)
app.get('/api/events', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.max(1, Math.min(50, parseInt(req.query.limit || '10')));
    const skip = (page - 1) * limit;
    const events = await Event.find().sort({ startDate: 1 }).skip(skip).limit(limit).lean();
    const total = await Event.countDocuments();
    res.json({ data: events, page, limit, total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public: event details
app.get('/api/events/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).lean();
    if (!event) return res.status(404).json({ error: 'Event not found' });
    // optionally include registered count
    const registeredCount = await Registration.countDocuments({ event: event._id, status: 'registered' });
    res.json({ ...event, registeredCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create event (for simplicity this route is public — in production protect it with admin role)
app.post('/api/events', async (req, res) => {
  try {
    const e = req.body;
    const event = await Event.create(e);
    res.status(201).json(event);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ----- Registration routes -----
// Register for an event (authenticated)
app.post('/api/events/:id/register', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const eventId = req.params.id;
    const event = await Event.findById(eventId);
    if (!event) return res.status(404).json({ error: 'Event not found' });

    // check capacity if provided
    if (event.capacity) {
      const registeredCount = await Registration.countDocuments({ event: eventId, status: 'registered' });
      if (registeredCount >= event.capacity) return res.status(400).json({ error: 'Event is full' });
    }

    // create or update registration
    try {
      const reg = await Registration.create({ user: userId, event: eventId, extra: req.body.extra || {} });
      return res.status(201).json(reg);
    } catch (err) {
      // duplicate key -> already registered
      if (err.code === 11000) {
        // if previously cancelled, update status back to registered
        const existing = await Registration.findOne({ user: userId, event: eventId });
        if (existing.status === 'cancelled') {
          existing.status = 'registered';
          existing.extra = req.body.extra || existing.extra;
          await existing.save();
          return res.json(existing);
        }
        return res.status(400).json({ error: 'Already registered' });
      }
      throw err;
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get registrations for current user
app.get('/api/my/registrations', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const regs = await Registration.find({ user: userId }).populate('event').sort({ createdAt: -1 }).lean();
    res.json(regs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Cancel a registration (authenticated) - soft cancel
app.post('/api/registrations/:id/cancel', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const reg = await Registration.findById(req.params.id);
    if (!reg) return res.status(404).json({ error: 'Registration not found' });
    if (reg.user.toString() !== userId) return res.status(403).json({ error: 'Forbidden' });
    if (reg.status === 'cancelled') return res.status(400).json({ error: 'Already cancelled' });
    reg.status = 'cancelled';
    await reg.save();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Optional: admin route to view all registrations for an event
app.get('/api/events/:id/registrations', async (req, res) => {
  try {
    const regs = await Registration.find({ event: req.params.id }).populate('user', '-password').lean();
    res.json(regs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
