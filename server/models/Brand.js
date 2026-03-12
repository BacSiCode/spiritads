const mongoose = require('mongoose');

const brandSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

  name: { type: String, required: true, trim: true },
  description: { type: String, trim: true, maxlength: 800 },
  category: {
    type: String,
    enum: ['Vang', 'Bia', 'Whisky', 'Vodka', 'Brandy', 'Sake', 'Khác'],
    required: true,
  },
  origin: { type: String, trim: true },
  image: { type: String, default: '' },
  logo: { type: String, default: '' },

  // Product details
  alcoholContent: { type: Number }, // %
  volume: { type: Number },         // ml
  price: { type: Number },          // VND suggested retail

  // Display
  isFeatured: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  rating: { type: Number, default: 0, min: 0, max: 5 },
  reviewCount: { type: Number, default: 0 },
  badge: { type: String, enum: ['', 'Nổi bật', 'Mới', 'Bán chạy', 'Premium'], default: '' },

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

brandSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Brand', brandSchema);
