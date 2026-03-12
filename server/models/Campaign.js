const mongoose = require('mongoose');

const campaignSchema = new mongoose.Schema({
  // ─── Owner ────────────────────────────────────
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },

  // ─── Basic Info ───────────────────────────────
  name: {
    type: String,
    required: [true, 'Vui lòng nhập tên chiến dịch'],
    trim: true,
    maxlength: [150, 'Tên chiến dịch không được quá 150 ký tự'],
  },
  description: { type: String, trim: true, maxlength: 1000 },
  brand: { type: String, required: true, trim: true },
  productType: {
    type: String,
    enum: ['Vang', 'Bia', 'Whisky', 'Vodka', 'Brandy', 'Khác'],
    default: 'Khác',
  },

  // ─── Type & Status ────────────────────────────
  type: {
    type: String,
    enum: ['product', 'brand', 'marketing', 'digital'],
    default: 'digital',
  },
  status: {
    type: String,
    enum: ['draft', 'pending', 'active', 'paused', 'completed', 'rejected'],
    default: 'draft',
  },

  // ─── Creative ─────────────────────────────────
  image: { type: String, default: '' },
  targetUrl: { type: String, trim: true },
  adCopy: { type: String, trim: true, maxlength: 500 },

  // ─── Budget ───────────────────────────────────
  budget: {
    total: { type: Number, required: true, min: 100000 }, // VND
    spent: { type: Number, default: 0 },
    dailyLimit: { type: Number, default: 0 },
  },

  // ─── Schedule ─────────────────────────────────
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },

  // ─── Targeting ────────────────────────────────
  targeting: {
    ageMin: { type: Number, default: 18 },
    ageMax: { type: Number, default: 65 },
    gender: { type: String, enum: ['all', 'male', 'female'], default: 'all' },
    locations: [{ type: String }],
    interests: [{ type: String }],
  },

  // ─── Channels ─────────────────────────────────
  channels: [{
    type: String,
    enum: ['facebook', 'instagram', 'google', 'tiktok', 'youtube', 'display', 'email'],
  }],

  // ─── Stats (updated by analytics jobs) ────────
  stats: {
    impressions: { type: Number, default: 0 },
    clicks: { type: Number, default: 0 },
    conversions: { type: Number, default: 0 },
    ctr: { type: Number, default: 0 },      // click-through rate %
    cpc: { type: Number, default: 0 },      // cost per click VND
    roi: { type: Number, default: 0 },      // %
  },

  // ─── Admin ────────────────────────────────────
  rejectionReason: { type: String },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedAt: { type: Date },

  // ─── Timestamps ───────────────────────────────
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

campaignSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  // Auto-calculate CTR
  if (this.stats.impressions > 0) {
    this.stats.ctr = ((this.stats.clicks / this.stats.impressions) * 100).toFixed(2);
  }
  if (this.stats.clicks > 0) {
    this.stats.cpc = (this.budget.spent / this.stats.clicks).toFixed(0);
  }
  next();
});

// Virtual: is running
campaignSchema.virtual('isRunning').get(function () {
  const now = new Date();
  return this.status === 'active' && this.startDate <= now && this.endDate >= now;
});

// Virtual: budget usage %
campaignSchema.virtual('budgetUsagePercent').get(function () {
  if (!this.budget.total) return 0;
  return Math.round((this.budget.spent / this.budget.total) * 100);
});

campaignSchema.set('toJSON', { virtuals: true });
campaignSchema.set('toObject', { virtuals: true });

module.exports = mongoose.model('Campaign', campaignSchema);
