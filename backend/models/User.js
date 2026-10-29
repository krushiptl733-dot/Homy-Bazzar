const mongoose = require('mongoose');

const addressSchema = new mongoose.Schema({
    name: String,
    phone: String,
    street: String,
    city: String,
    state: String,
    zipCode: String,
    type: { type: String, default: 'index' }
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: String,
  // Array of addresses
  addresses: [addressSchema],
  defaultAddressId: String,
  // Wishlist references Product
  wishlist: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    addedAt: { type: Date, default: Date.now }
  }],
  // Simple order history summary (optional, since we have Order model)
  orders: [{
    id: String,
    total: Number,
    status: String,
    date: Date
  }]
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);