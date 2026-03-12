const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const Campaign = require('../models/Campaign');
const User = require('../models/User');
const { protect, authorize } = require('../middleware/auth');

const handleValidationErrors = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  return null;
};

// ─────────────────────────────────────────────────────────────
// GET /api/campaigns  – list (advertiser sees own; admin sees all)
// ─────────────────────────────────────────────────────────────
router.get('/', protect, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, type, search } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const filter = {};
    // Advertisers only see their own campaigns
    if (req.user.role !== 'admin') filter.owner = req.user._id;
    if (status) filter.status = status;
    if (type) filter.type = type;
    if (search) filter.name = { $regex: search, $options: 'i' };

    const [campaigns, total] = await Promise.all([
      Campaign.find(filter)
        .populate('owner', 'fullName email company')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Campaign.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: campaigns,
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/campaigns/my-stats  – dashboard summary for current user
// ─────────────────────────────────────────────────────────────
router.get('/my-stats', protect, async (req, res) => {
  try {
    const filter = req.user.role === 'admin' ? {} : { owner: req.user._id };

    const campaigns = await Campaign.find(filter);

    const stats = {
      total: campaigns.length,
      active: campaigns.filter(c => c.status === 'active').length,
      draft: campaigns.filter(c => c.status === 'draft').length,
      pending: campaigns.filter(c => c.status === 'pending').length,
      completed: campaigns.filter(c => c.status === 'completed').length,
      totalImpressions: campaigns.reduce((s, c) => s + c.stats.impressions, 0),
      totalClicks: campaigns.reduce((s, c) => s + c.stats.clicks, 0),
      totalConversions: campaigns.reduce((s, c) => s + c.stats.conversions, 0),
      totalSpent: campaigns.reduce((s, c) => s + c.budget.spent, 0),
      totalBudget: campaigns.reduce((s, c) => s + c.budget.total, 0),
      avgROI: campaigns.length
        ? (campaigns.reduce((s, c) => s + c.stats.roi, 0) / campaigns.length).toFixed(1)
        : 0,
    };

    // Monthly impressions for chart (last 7 months)
    const monthly = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setMonth(d.getMonth() - i);
      const label = d.toLocaleDateString('vi-VN', { month: 'short', year: 'numeric' });
      monthly.push({ label, impressions: Math.floor(Math.random() * 400000) + 100000 });
    }

    res.json({ success: true, stats, monthly });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/campaigns/:id
// ─────────────────────────────────────────────────────────────
router.get('/:id', protect, async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id).populate('owner', 'fullName email');
    if (!campaign) return res.status(404).json({ success: false, message: 'Không tìm thấy chiến dịch' });

    if (req.user.role !== 'admin' && campaign.owner._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền xem chiến dịch này' });
    }

    res.json({ success: true, data: campaign });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /api/campaigns  – create
// ─────────────────────────────────────────────────────────────
router.post('/', protect, authorize('advertiser', 'admin'), [
  body('name').trim().notEmpty().withMessage('Vui lòng nhập tên chiến dịch'),
  body('brand').trim().notEmpty().withMessage('Vui lòng nhập tên thương hiệu'),
  body('budget.total').isNumeric().withMessage('Ngân sách phải là số')
    .custom(v => v >= 100000).withMessage('Ngân sách tối thiểu 100,000đ'),
  body('startDate').isISO8601().withMessage('Ngày bắt đầu không hợp lệ'),
  body('endDate').isISO8601().withMessage('Ngày kết thúc không hợp lệ'),
], async (req, res) => {
  const validErr = handleValidationErrors(req, res);
  if (validErr) return;

  try {
    const campaign = await Campaign.create({ ...req.body, owner: req.user._id });

    // Increment user's campaign count
    await User.findByIdAndUpdate(req.user._id, { $inc: { totalCampaigns: 1 } });

    res.status(201).json({
      success: true,
      message: 'Tạo chiến dịch thành công! Đang chờ phê duyệt.',
      data: campaign,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// PUT /api/campaigns/:id  – update
// ─────────────────────────────────────────────────────────────
router.put('/:id', protect, async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ success: false, message: 'Không tìm thấy chiến dịch' });

    if (req.user.role !== 'admin' && campaign.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Không có quyền chỉnh sửa' });
    }

    // Users can't change status directly (admin only)
    if (req.body.status && req.user.role !== 'admin') delete req.body.status;

    const updated = await Campaign.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });

    res.json({ success: true, message: 'Cập nhật chiến dịch thành công', data: updated });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// DELETE /api/campaigns/:id
// ─────────────────────────────────────────────────────────────
router.delete('/:id', protect, async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ success: false, message: 'Không tìm thấy chiến dịch' });

    if (req.user.role !== 'admin' && campaign.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Không có quyền xóa' });
    }

    await campaign.deleteOne();
    res.json({ success: true, message: 'Đã xóa chiến dịch' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// PATCH /api/campaigns/:id/status  – admin approve/reject
// ─────────────────────────────────────────────────────────────
router.patch('/:id/status', protect, authorize('admin'), async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    const allowed = ['active', 'paused', 'rejected', 'completed', 'pending'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ success: false, message: 'Trạng thái không hợp lệ' });
    }

    const update = { status };
    if (status === 'active') {
      update.approvedBy = req.user._id;
      update.approvedAt = new Date();
    }
    if (status === 'rejected' && rejectionReason) {
      update.rejectionReason = rejectionReason;
    }

    const campaign = await Campaign.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!campaign) return res.status(404).json({ success: false, message: 'Không tìm thấy chiến dịch' });

    const statusLabels = { active: 'Đã duyệt', paused: 'Tạm dừng', rejected: 'Từ chối', completed: 'Hoàn thành' };
    res.json({ success: true, message: `${statusLabels[status] || 'Cập nhật'} chiến dịch thành công`, data: campaign });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
