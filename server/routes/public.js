const express = require('express');
const router = express.Router();
const Brand = require('../models/Brand');
const Contact = require('../models/Contact');
const { protect, authorize } = require('../middleware/auth');
const { body, validationResult } = require('express-validator');

// ─── BRANDS ──────────────────────────────────────────────────

// GET /api/brands  – public list
router.get('/brands', async (req, res) => {
  try {
    const { category, featured, page = 1, limit = 8, search } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const filter = { isActive: true };
    if (category) filter.category = category;
    if (featured === 'true') filter.isFeatured = true;
    if (search) filter.name = { $regex: search, $options: 'i' };

    const [brands, total] = await Promise.all([
      Brand.find(filter).sort({ isFeatured: -1, createdAt: -1 }).skip(skip).limit(parseInt(limit)),
      Brand.countDocuments(filter),
    ]);

    res.json({ success: true, data: brands, pagination: { total, page: parseInt(page) } });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// POST /api/brands  – create (advertiser+)
router.post('/brands', protect, authorize('advertiser', 'admin'), async (req, res) => {
  try {
    const brand = await Brand.create({ ...req.body, owner: req.user._id });
    res.status(201).json({ success: true, message: 'Thêm thương hiệu thành công', data: brand });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// PUT /api/brands/:id
router.put('/brands/:id', protect, async (req, res) => {
  try {
    const brand = await Brand.findById(req.params.id);
    if (!brand) return res.status(404).json({ success: false, message: 'Không tìm thấy thương hiệu' });

    if (req.user.role !== 'admin' && brand.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Không có quyền' });
    }

    const updated = await Brand.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ success: true, data: updated });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// DELETE /api/brands/:id
router.delete('/brands/:id', protect, async (req, res) => {
  try {
    const brand = await Brand.findById(req.params.id);
    if (!brand) return res.status(404).json({ success: false, message: 'Không tìm thấy' });
    if (req.user.role !== 'admin' && brand.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Không có quyền' });
    }
    await brand.deleteOne();
    res.json({ success: true, message: 'Đã xóa thương hiệu' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─── CONTACT ─────────────────────────────────────────────────

// POST /api/contact  – submit contact form (public)
router.post('/contact', [
  body('fullName').trim().notEmpty().withMessage('Vui lòng nhập họ tên'),
  body('phone').trim().notEmpty().withMessage('Vui lòng nhập số điện thoại'),
  body('email').isEmail().normalizeEmail().withMessage('Email không hợp lệ'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const contact = await Contact.create(req.body);
    res.status(201).json({
      success: true,
      message: 'Cảm ơn bạn! Chúng tôi sẽ liên hệ lại trong vòng 2 giờ làm việc.',
      data: { id: contact._id },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
