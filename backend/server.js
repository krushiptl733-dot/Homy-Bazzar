// server.js - Only fixed authentication issues
require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const app = express();

// Create uploads directory
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage, 
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    const extname = allowed.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowed.test(file.mimetype);
    cb(null, mimetype && extname);
  }
});

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/homybazaar';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, default: '' },
  location: { type: String, default: 'Mumbai' },
  addresses: [{
    name: String,
    phone: String,
    street: String,
    city: String,
    state: String,
    zip: String,
    type: { type: String, default: 'Home' }
  }],
  wishlist: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    addedAt: { type: Date, default: Date.now }
  }],
  orders: [{
    id: mongoose.Schema.Types.ObjectId,
    total: Number,
    status: String,
    date: Date
  }],
  createdAt: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  unit: { type: String, required: true },
  category: { type: String, required: true },
  image: { type: String, required: true },
  description: { type: String, default: '' },
  inStock: { type: Boolean, default: true },
  rating: { type: Number, default: 4.5 },
  createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    productName: String,
    quantity: Number,
    price: Number,
    unit: String
  }],
  totalAmount: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  shippingAddress: { type: String, required: true },
  status: { type: String, default: 'Processing' },
  statusHistory: [{
    status: String,
    date: Date,
    note: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);

// Auth Middleware - FIXED
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth error:', err.message);
    return res.status(401).json({ success: false, message: 'Token is not valid' });
  }
};

const adminAuth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    if (!decoded || decoded.email !== process.env.ADMIN_EMAIL) {
      return res.status(403).json({ message: 'Not authorized as admin' });
    }

    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// ==================== USER ROUTES ====================

// Register
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ name, email, password: hashed });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });

    res.status(201).json({ success: true, data: { user: { id: user._id, name: user.name, email: user.email }, token } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });
    const populated = await User.findById(user._id).populate('wishlist.productId', 'name price image');

    res.json({ success: true, data: { user: populated, token } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get products (public)
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ inStock: true }).sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const p = await Product.findById(req.params.id);
    if (!p) return res.status(404).json({ message: 'Product not found' });
    res.json(p);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Orders: create (auth)
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { items, totalAmount, paymentMethod, shippingAddress } = req.body;
    if (!items || !items.length) return res.status(400).json({ message: 'No items provided' });

    const enrichedItems = await Promise.all(items.map(async (item) => {
      const product = await Product.findById(item.productId);
      return {
        productId: item.productId,
        productName: product ? product.name : 'Unknown Product',
        quantity: item.quantity,
        price: item.price,
        unit: product ? product.unit : 'pc'
      };
    }));

    const order = new Order({
      user: req.user._id,
      items: enrichedItems,
      totalAmount,
      paymentMethod,
      shippingAddress,
      status: 'Processing',
      statusHistory: [{ status: 'Processing', date: new Date(), note: 'Order placed' }]
    });
    await order.save();

    res.status(201).json({ success: true, data: { order } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get user's orders
app.get('/api/orders/user', auth, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json({ success: true, data: { orders } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Cancel order
app.put('/api/orders/:id/cancel', auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ message: 'Order not found' });
    if (order.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    if (order.status === 'Delivered') {
      return res.status(400).json({ message: 'Cannot cancel delivered order' });
    }

    order.status = 'Cancelled';
    order.statusHistory.push({ status: 'Cancelled', date: new Date(), note: 'Cancelled by user' });
    await order.save();

    res.json({ success: true, message: 'Order cancelled' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});
// Add this endpoint to server.js if not present
app.get('/api/orders/:id', auth, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id).populate('items.productId');
        if (!order) {
            return res.status(404).json({ success: false, message: 'Order not found' });
        }
        if (order.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ success: false, message: 'Not authorized' });
        }
        res.json({ success: true, data: { order } });
    } catch (err) {
        console.error('Error fetching order:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});
// Reorder
app.post('/api/orders/reorder/:orderId', auth, async (req, res) => {
  try {
    const oldOrder = await Order.findById(req.params.orderId);
    if (!oldOrder) return res.status(404).json({ message: 'Order not found' });

    const items = oldOrder.items.map(item => ({
      productId: item.productId,
      quantity: item.quantity,
      price: item.price
    }));

    const order = new Order({
      user: req.user._id,
      items,
      totalAmount: oldOrder.totalAmount,
      paymentMethod: 'COD',
      shippingAddress: oldOrder.shippingAddress,
      status: 'Processing',
      statusHistory: [{ status: 'Processing', date: new Date(), note: 'Reorder placed' }]
    });
    await order.save();

    res.json({ success: true, data: { order } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Wishlist: get
app.get('/api/wishlist', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('wishlist.productId', 'name price image unit');
    res.json({ success: true, data: { wishlist: user.wishlist } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Wishlist: add
app.post('/api/wishlist', auth, async (req, res) => {
  try {
    const { productId } = req.body;
    const user = await User.findById(req.user._id);
    const exists = user.wishlist.some(i => i.productId && i.productId.toString() === productId);
    if (exists) return res.json({ success: false, message: 'Already in wishlist' });

    user.wishlist.push({ productId });
    await user.save();
    const populated = await User.findById(user._id).populate('wishlist.productId', 'name price image');
    res.json({ success: true, data: { wishlist: populated.wishlist } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Wishlist: remove
app.delete('/api/wishlist/:id', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.wishlist = user.wishlist.filter(item => item._id.toString() !== req.params.id);
    await user.save();
    res.json({ success: true, message: 'Removed from wishlist' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Addresses: add/get/delete
app.post('/api/users/addresses', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.addresses.push(req.body);
    await user.save();
    res.json({ success: true, data: { addresses: user.addresses } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/users/addresses', auth, async (req, res) => {
  try {
    res.json({ success: true, data: { addresses: req.user.addresses } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/users/addresses/:id', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.addresses = user.addresses.filter(addr => addr._id.toString() !== req.params.id);
    await user.save();
    res.json({ success: true, message: 'Address deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Profile update
app.put('/api/users/profile', auth, async (req, res) => {
  try {
    const { name, phone } = req.body;
    if (name) req.user.name = name;
    if (phone) req.user.phone = phone;
    await req.user.save();
    res.json({ success: true, data: { user: req.user } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Change password
app.put('/api/users/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ message: 'Provide current and new password' });

    const valid = await bcrypt.compare(currentPassword, req.user.password);
    if (!valid) return res.status(400).json({ message: 'Current password incorrect' });

    req.user.password = await bcrypt.hash(newPassword, 12);
    await req.user.save();
    res.json({ success: true, message: 'Password changed' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Image upload
app.post('/api/upload', auth, upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ success: true, imageUrl: `/uploads/${req.file.filename}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== ADMIN ROUTES ====================

app.post('/api/admin/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
      return res.status(500).json({ message: 'Admin credentials not set in .env' });
    }

    if (email !== process.env.ADMIN_EMAIL || password !== process.env.ADMIN_PASSWORD) {
      return res.status(400).json({ message: 'Invalid admin credentials' });
    }

    const token = jwt.sign({ email, role: 'admin' }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });
    res.json({ message: 'Admin login successful', token, admin: { email, role: 'admin' } });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalProducts = await Product.countDocuments();
    const totalOrders = await Order.countDocuments();
    const revenueAgg = await Order.aggregate([
      { $match: { status: 'Delivered' } },
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);
    const totalRevenue = revenueAgg[0]?.total || 0;
    const recentOrders = await Order.find().populate('user', 'name email').sort({ createdAt: -1 }).limit(10);

    res.json({ totalUsers, totalProducts, totalOrders, totalRevenue, recentOrders });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: products CRUD
app.get('/api/admin/products', adminAuth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/admin/products', adminAuth, upload.single('image'), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.productData);
    if (req.file) productData.image = `/uploads/${req.file.filename}`;
    const product = new Product(productData);
    await product.save();
    res.status(201).json({ message: 'Product created', product });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/products/:id', adminAuth, upload.single('image'), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.productData);
    if (req.file) productData.image = `/uploads/${req.file.filename}`;
    const prod = await Product.findByIdAndUpdate(req.params.id, productData, { new: true });
    res.json({ message: 'Product updated', product: prod });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/products/:id', adminAuth, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Admin: orders & change status
app.get('/api/admin/orders', adminAuth, async (req, res) => {
  try {
    const orders = await Order.find().populate('user', 'name email').sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/orders/:id/status', adminAuth, async (req, res) => {
  try {
    const { status, note } = req.body;
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ message: 'Order not found' });

    order.status = status;
    order.statusHistory.push({ status, date: new Date(), note: note || `Status updated to ${status}` });
    await order.save();

    res.json({ message: 'Order status updated', order });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Admin: users list
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Seed products
app.get('/api/seed', async (req, res) => {
  try {
    const count = await Product.countDocuments();
    if (count > 0) return res.json({ message: 'Products already exist' });

    const sampleProducts = [
      { name: 'Fresh Tomatoes', price: 40, unit: 'kg', category: 'Vegetables', image: 'https://placehold.co/400x300?text=Tomatoes', description: 'Farm fresh red tomatoes', rating: 4.5, inStock: true },
      { name: 'Organic Bananas', price: 60, unit: 'doz', category: 'Fruits', image: 'https://placehold.co/400x300?text=Bananas', description: 'Sweet organic bananas', rating: 4.7, inStock: true },
      { name: 'Basmati Rice', price: 120, unit: 'kg', category: 'Rice & Flours', image: 'https://placehold.co/400x300?text=Rice', description: 'Premium long grain rice', rating: 4.8, inStock: true },
      { name: 'Fresh Milk', price: 60, unit: 'L', category: 'Dairy', image: 'https://placehold.co/400x300?text=Milk', description: 'Fresh cow milk', rating: 4.6, inStock: true },
      { name: 'Garam Masala', price: 80, unit: '100g', category: 'Spices & Masalas', image: 'https://placehold.co/400x300?text=Masala', description: 'Aromatic spice blend', rating: 4.7, inStock: true },
      { name: 'Toor Dal', price: 110, unit: 'kg', category: 'Pulses & Dals', image: 'https://placehold.co/400x300?text=Toor+Dal', description: 'Premium lentils', rating: 4.5, inStock: true }
    ];

    await Product.insertMany(sampleProducts);
    res.json({ message: 'Database seeded' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Catch-all for frontend
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ message: 'API route not found' });
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend static folder: ${path.join(__dirname, 'public')}`);
});