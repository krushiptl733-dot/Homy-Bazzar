const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true } // Price at time of purchase
  }],
  totalAmount: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  shippingAddress: { type: String, required: true },
  status: { 
    type: String, 
    default: 'Processing',
    enum: ['Processing', 'Shipped', 'Delivered', 'Cancelled'] 
  }
}, { timestamps: true });

module.exports = mongoose.model('Order', orderSchema);