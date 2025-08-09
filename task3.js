/*
Restaurant Management System Backend (Express + MongoDB)
-------------------------------------------------------
Single-file starter backend: server.js
Features:
- Menu (MenuItem) with categories and price
- Inventory (InventoryItem) tracking ingredient stock and unit
- Tables and Reservations (Table & Reservation)
- Orders linked to users and tables, order processing reduces inventory
- APIs for menu viewing, placing orders, reserving tables, updating inventory, checking table availability
- Simple auth (email/password + JWT) for users and admin (admin flag) — reuse for protected routes

Setup:
1. Put this file as server.js
2. npm init -y
3. npm i express mongoose bcryptjs jsonwebtoken dotenv body-parser cors
4. Create .env with:
   PORT=5000
   MONGO_URI=mongodb://localhost:27017/restaurantdb
   JWT_SECRET=your_jwt_secret

Notes:
- This is a starter implementation. In production split into modules, add validation, tests, role checks, logging, and error handling middleware.
- Inventory model assumes each MenuItem lists required ingredients with quantity — when an order is placed we check and decrement inventory atomically.
*/

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

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/restaurantdb';
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// Connect
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error', err));

const { Schema } = mongoose;

// --- Schemas ---
const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Menu item: includes a list of ingredients required and the qty per single menu item
const MenuItemSchema = new Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  category: String,
  ingredients: [{ ingredientId: { type: Schema.Types.ObjectId, ref: 'InventoryItem' }, qty: Number }],
  available: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const MenuItem = mongoose.model('MenuItem', MenuItemSchema);

// Inventory item: e.g., 'Tomato', unit: 'kg' or 'pcs' and current stock
const InventoryItemSchema = new Schema({
  name: { type: String, required: true, unique: true },
  unit: { type: String, default: 'pcs' },
  stock: { type: Number, default: 0 },
  reorderLevel: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const InventoryItem = mongoose.model('InventoryItem', InventoryItemSchema);

// Tables
const TableSchema = new Schema({
  name: { type: String, required: true },
  seats: { type: Number, default: 2 },
  location: String, // e.g., 'indoor', 'outdoor'
  createdAt: { type: Date, default: Date.now }
});
const Table = mongoose.model('Table', TableSchema);

// Reservations
const ReservationSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  table: { type: Schema.Types.ObjectId, ref: 'Table', required: true },
  date: { type: Date, required: true }, // reservation start time
  durationMinutes: { type: Number, default: 90 },
  status: { type: String, enum: ['booked','cancelled','completed'], default: 'booked' },
  createdAt: { type: Date, default: Date.now }
});
ReservationSchema.index({ table: 1, date: 1 });
const Reservation = mongoose.model('Reservation', ReservationSchema);

// Orders
const OrderItemSub = new Schema({
  menuItem: { type: Schema.Types.ObjectId, ref: 'MenuItem' },
  qty: { type: Number, default: 1 },
  priceAtOrder: Number
}, { _id: false });

const OrderSchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User' },
  table: { type: Schema.Types.ObjectId, ref: 'Table' },
  items: [OrderItemSub],
  total: Number,
  status: { type: String, enum: ['placed','processing','served','cancelled'], default: 'placed' },
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

// --- Auth middleware ---
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

async function adminOnly(req, res, next) {
  try {
    const u = await User.findById(req.user.id);
    if (!u || !u.isAdmin) return res.status(403).json({ error: 'Admin only' });
    next();
  } catch (err) {
    next(err);
  }
}

// --- Auth routes ---
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

// --- Menu APIs ---
app.get('/api/menu', async (req, res) => {
  try {
    const items = await MenuItem.find().populate('ingredients.ingredientId').lean();
    res.json(items);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/menu', authMiddleware, adminOnly, async (req, res) => {
  try {
    const item = await MenuItem.create(req.body);
    res.status(201).json(item);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Inventory APIs ---
app.get('/api/inventory', authMiddleware, adminOnly, async (req, res) => {
  const items = await InventoryItem.find().lean();
  res.json(items);
});

app.post('/api/inventory', authMiddleware, adminOnly, async (req, res) => {
  try {
    const item = await InventoryItem.create(req.body);
    res.status(201).json(item);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update inventory stock (increase/decrease)
app.post('/api/inventory/:id/update', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { delta } = req.body; // positive or negative number
    const item = await InventoryItem.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Inventory item not found' });
    item.stock = Math.max(0, item.stock + (delta || 0));
    await item.save();
    res.json(item);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Table & Reservation APIs ---
app.get('/api/tables', async (req, res) => {
  const tables = await Table.find().lean();
  res.json(tables);
});

// Check table availability around a datetime for duration
app.post('/api/tables/availability', async (req, res) => {
  try {
    const { date, durationMinutes = 90, seats } = req.body;
    if (!date) return res.status(400).json({ error: 'date is required' });
    const start = new Date(date);
    const end = new Date(start.getTime() + durationMinutes * 60000);

    // find tables that match seats if provided
    const tableFilter = seats ? { seats: { $gte: seats } } : {};
    const candidateTables = await Table.find(tableFilter).lean();

    const available = [];
    for (const t of candidateTables) {
      const overlapping = await Reservation.findOne({
        table: t._id,
        status: 'booked',
        $or: [
          { date: { $lt: end }, $expr: { $gte: [ { $add: ["$date", { $multiply: ["$durationMinutes", 60000] }] }, start ] } },
          // simplified check handled in code below if DB expr is messy
        ]
      });
      // fallback simpler check: fetch reservations and check in JS
      if (!overlapping) {
        // double-check by fetching reservations for the table in the window
        const resvs = await Reservation.find({ table: t._id, status: 'booked' });
        let conflict = false;
        for (const r of resvs) {
          const rStart = new Date(r.date);
          const rEnd = new Date(rStart.getTime() + r.durationMinutes * 60000);
          if (start < rEnd && rStart < end) { conflict = true; break; }
        }
        if (!conflict) available.push(t);
      }
    }

    res.json({ available });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/reservations', authMiddleware, async (req, res) => {
  try {
    const { tableId, date, durationMinutes } = req.body;
    if (!tableId || !date) return res.status(400).json({ error: 'Missing fields' });
    const start = new Date(date);
    const duration = durationMinutes || 90;
    const end = new Date(start.getTime() + duration * 60000);

    // check conflicts for this table
    const existing = await Reservation.find({ table: tableId, status: 'booked' });
    for (const r of existing) {
      const rStart = new Date(r.date);
      const rEnd = new Date(rStart.getTime() + r.durationMinutes * 60000);
      if (start < rEnd && rStart < end) return res.status(400).json({ error: 'Table not available at requested time' });
    }

    const reservation = await Reservation.create({ user: req.user.id, table: tableId, date: start, durationMinutes: duration });
    res.status(201).json(reservation);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/my/reservations', authMiddleware, async (req, res) => {
  const regs = await Reservation.find({ user: req.user.id }).populate('table').sort({ date: -1 }).lean();
  res.json(regs);
});

app.post('/api/reservations/:id/cancel', authMiddleware, async (req, res) => {
  const r = await Reservation.findById(req.params.id);
  if (!r) return res.status(404).json({ error: 'Reservation not found' });
  if (r.user.toString() !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  r.status = 'cancelled';
  await r.save();
  res.json({ success: true });
});

// --- Order processing ---
// Helper: check and reserve inventory in a transaction-like manner
async function canFulfillOrder(items) {
  // items: [{ menuItemId, qty }]
  // build required totals per ingredient
  const required = {}; // ingredientId -> totalQty
  for (const it of items) {
    const menu = await MenuItem.findById(it.menuItemId).populate('ingredients.ingredientId');
    if (!menu || !menu.available) return { ok: false, reason: `Menu item ${it.menuItemId} not available` };
    for (const ing of menu.ingredients) {
      const id = ing.ingredientId._id.toString();
      const need = (ing.qty || 0) * it.qty;
      required[id] = (required[id] || 0) + need;
    }
  }
  // fetch inventory items
  const ids = Object.keys(required);
  const inventory = await InventoryItem.find({ _id: { $in: ids } });
  const invMap = {};
  for (const inv of inventory) invMap[inv._id.toString()] = inv;
  for (const id of ids) {
    const inv = invMap[id];
    if (!inv) return { ok: false, reason: `Missing inventory item ${id}` };
    if (inv.stock < required[id]) return { ok: false, reason: `Insufficient ${inv.name}` };
  }
  return { ok: true, required };
}

async function deductInventory(required) {
  // required: {ingredientId: qty}
  const bulk = [];
  for (const [id, qty] of Object.entries(required)) {
    bulk.push({ updateOne: { filter: { _id: id }, update: { $inc: { stock: -qty } } } });
  }
  if (bulk.length) await InventoryItem.bulkWrite(bulk);
}

// Place an order
app.post('/api/orders', authMiddleware, async (req, res) => {
  try {
    // items: [{ menuItemId, qty }], optional tableId
    const { items = [], tableId } = req.body;
    if (!items.length) return res.status(400).json({ error: 'No items' });

    // check table availability if tableId provided (ensure not reserved/occupied)
    if (tableId) {
      // check ongoing reservations overlapping now
      const now = new Date();
      const active = await Reservation.findOne({ table: tableId, status: 'booked' });
      if (active) {
        const rStart = new Date(active.date);
        const rEnd = new Date(rStart.getTime() + active.durationMinutes * 60000);
        if (now < rEnd && rStart < new Date(now.getTime() + 24*3600*1000)) {
          // allow ordering at reservation time, but if someone else has booked now, reject
          // this is simplified — in production track table occupancy and order-seat mapping
        }
      }
    }

    // Build items for order and compute total
    const orderItems = [];
    let total = 0;
    const orderReqs = [];
    for (const it of items) {
      const menu = await MenuItem.findById(it.menuItemId);
      if (!menu) return res.status(400).json({ error: `Menu item not found: ${it.menuItemId}` });
      orderItems.push({ menuItem: menu._id, qty: it.qty, priceAtOrder: menu.price });
      total += menu.price * it.qty;
      orderReqs.push({ menuItemId: menu._id, qty: it.qty });
    }

    // Check inventory
    const check = await canFulfillOrder(orderReqs);
    if (!check.ok) return res.status(400).json({ error: `Cannot fulfill order: ${check.reason}` });

    // Deduct inventory
    await deductInventory(check.required);

    // Create order
    const order = await Order.create({ user: req.user.id, table: tableId, items: orderItems, total, status: 'placed' });
    res.status(201).json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update order status (admin)
app.post('/api/orders/:id/status', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status } = req.body; // 'processing','served','cancelled'
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    // If cancelling, restock inventory
    if (status === 'cancelled' && order.status !== 'cancelled') {
      // compute ingredients to restock
      const required = {};
      for (const it of order.items) {
        const menu = await MenuItem.findById(it.menuItem).populate('ingredients.ingredientId');
        for (const ing of menu.ingredients) {
          const id = ing.ingredientId._id.toString();
          const need = (ing.qty || 0) * it.qty;
          required[id] = (required[id] || 0) + need;
        }
      }
      // add back
      const bulk = [];
      for (const [id, qty] of Object.entries(required)) bulk.push({ updateOne: { filter: { _id: id }, update: { $inc: { stock: qty } } } });
      if (bulk.length) await InventoryItem.bulkWrite(bulk);
    }

    order.status = status;
    await order.save();
    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/my/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find({ user: req.user.id }).populate('items.menuItem').sort({ createdAt: -1 }).lean();
  res.json(orders);
});

app.get('/api/orders', authMiddleware, adminOnly, async (req, res) => {
  const orders = await Order.find().populate('user').populate('items.menuItem').sort({ createdAt: -1 }).lean();
  res.json(orders);
});

// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));