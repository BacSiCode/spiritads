const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  // ─── Basic Info ───────────────────────────────
  fullName: {
    type: String,
    required: [true, 'Vui lòng nhập họ và tên'],
    trim: true,
    maxlength: [100, 'Họ tên không được quá 100 ký tự'],
  },
  email: {
    type: String,
    required: [true, 'Vui lòng nhập email'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Email không hợp lệ'],
  },
  password: {
    type: String,
    required: [true, 'Vui lòng nhập mật khẩu'],
    minlength: [6, 'Mật khẩu phải ít nhất 6 ký tự'],
    select: false,
  },

  // ─── Role & Status ────────────────────────────
  role: {
    type: String,
    enum: ['user', 'advertiser', 'admin'],
    default: 'user',
  },
  isActive: { type: Boolean, default: true },
  isVerified: { type: Boolean, default: false },

  // ─── Business Info (for advertisers) ─────────
  company: {
    name: { type: String, trim: true },
    taxCode: { type: String, trim: true },
    address: { type: String, trim: true },
    phone: { type: String, trim: true },
    website: { type: String, trim: true },
    industry: { type: String, default: 'Đồ uống có cồn' },
  },

  // ─── Profile ──────────────────────────────────
  avatar: { type: String, default: '' },
  phone: { type: String, trim: true },

  // ─── Stats ────────────────────────────────────
  totalCampaigns: { type: Number, default: 0 },
  totalSpent: { type: Number, default: 0 }, // VND

  // ─── Timestamps ───────────────────────────────
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Hash password before save
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Public profile (no sensitive fields)
userSchema.methods.toPublic = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
