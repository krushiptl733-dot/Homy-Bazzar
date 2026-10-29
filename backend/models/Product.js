const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  unit: { type: String, required: true }, // e.g., 'kg', 'pc'
  category: { type: String, required: true },
  image: { type: String, required: true },
  description: String,
  rating: { type: Number, default: 0 },
  inStock: { type: Boolean, default: true }
});

module.exports = mongoose.model('Product', productSchema);