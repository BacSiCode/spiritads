const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const User = require('../models/User');
const Campaign = require('../models/Campaign');
const Contact = require('../models/Contact');
const Brand = require('../models/Brand');
const { protect, authorize } = require('../middleware/auth');

// Require Notification model (optional - won't crash if missing)
let Notification;
try { Notification = require('../models/Notification'); } catch (e) {}

router.use(protect, authorize('admin'));

// ─── Overview ─────────────────────────────────────────────────
router.get('/overview', async (req, res) => {
  try {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const [totalUsers, newToday, totalCampaigns, activeCampaigns,
      pendingCampaigns, totalContacts, newContactsToday, totalBrands] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ createdAt: { $gte: today } }),
      Campaign.countDocuments(),
      Campaign.countDocuments({ status: 'active' }),
      Campaign.countDocuments({ status: 'pending' }),
      Contact.countDocuments(),
      Contact.countDocuments({ createdAt: { $gte: today } }),
      Brand.countDocuments(),
    ]);
    const revenueAgg = await Campaign.aggregate([{ $group: { _id: null, total: { $sum: '$budget.spent' } } }]);
    const usersByRole = await User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]);
    const campaignsByStatus = await Campaign.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]);

    // Monthly signup chart (last 6 months)
    const monthlyUsers = [];
    for (let i = 5; i >= 0; i--) {
      const start = new Date(); start.setMonth(start.getMonth() - i); start.setDate(1); start.setHours(0, 0, 0, 0);
      const end = new Date(start); end.setMonth(end.getMonth() + 1);
      const count = await User.countDocuments({ createdAt: { $gte: start, $lt: end } });
      monthlyUsers.push({ label: start.toLocaleDateString('vi-VN', { month: 'short' }), count });
    }

    res.json({ success: true, data: {
      users: { total: totalUsers, newToday, byRole: usersByRole },
      campaigns: { total: totalCampaigns, active: activeCampaigns, pending: pendingCampaigns, byStatus: campaignsByStatus },
      contacts: { total: totalContacts, newToday: newContactsToday },
      brands: { total: totalBrands },
      revenue: { total: revenueAgg[0]?.total || 0 },
      monthlyUsers,
    }});
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── Users list ───────────────────────────────────────────────
router.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 15, role, search, isActive } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const filter = {};
    if (role) filter.role = role;
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (search) filter.$or = [
      { fullName: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
    ];
    const [users, total] = await Promise.all([
      User.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)),
      User.countDocuments(filter),
    ]);
    res.json({ success: true, data: users, pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── Update user (role / isActive) ────────────────────────────
router.patch('/users/:id', async (req, res) => {
  try {
    if (req.params.id === req.user._id.toString() && req.body.role && req.body.role !== 'admin') {
      return res.status(400).json({ success: false, message: 'Không thể thay đổi role của chính mình' });
    }
    const update = {};
    if (req.body.role) update.role = req.body.role;
    if (req.body.isActive !== undefined) update.isActive = req.body.isActive;
    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });

    // Notify user if Notification model available
    if (Notification) {
      await Notification.create({
        recipient: user._id,
        title: 'Tài khoản được cập nhật',
        message: `Tài khoản của bạn đã được ${req.body.isActive === false ? 'vô hiệu hóa' : 'cập nhật'} bởi quản trị viên.`,
        type: 'system',
      });
    }

    res.json({ success: true, message: 'Cập nhật người dùng thành công', data: user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── RESET PASSWORD (Admin cấp lại mật khẩu) ─────────────────
router.post('/users/:id/reset-password', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });

    // Generate secure random password
    const newPassword = crypto.randomBytes(5).toString('hex').toUpperCase(); // e.g. A3F9C2D1B8

    // Set and save (model pre-save will hash it)
    user.password = newPassword;
    await user.save();

    // Notify the user
    if (Notification) {
      await Notification.create({
        recipient: user._id,
        title: '🔐 Mật khẩu đã được reset',
        message: `Mật khẩu của bạn đã được quản trị viên reset. Mật khẩu mới: ${newPassword}. Vui lòng đăng nhập và đổi mật khẩu ngay.`,
        type: 'warning',
      });
    }

    res.json({
      success: true,
      message: `Đã reset mật khẩu thành công cho ${user.fullName}`,
      data: {
        userId: user._id,
        fullName: user.fullName,
        email: user.email,
        newPassword, // Admin thấy để thông báo cho user
      },
    });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── Delete user ──────────────────────────────────────────────
router.delete('/users/:id', async (req, res) => {
  try {
    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Không thể xóa chính mình' });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
    res.json({ success: true, message: `Đã xóa tài khoản ${user.fullName}` });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── Contacts ─────────────────────────────────────────────────
router.get('/contacts', async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const filter = status ? { status } : {};
    const [contacts, total] = await Promise.all([
      Contact.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)),
      Contact.countDocuments(filter),
    ]);
    res.json({ success: true, data: contacts, pagination: { page: parseInt(page), total, pages: Math.ceil(total / parseInt(limit)) } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

router.patch('/contacts/:id', async (req, res) => {
  try {
    const contact = await Contact.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!contact) return res.status(404).json({ success: false, message: 'Không tìm thấy' });
    res.json({ success: true, data: contact });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── Campaign approval ────────────────────────────────────────
router.patch('/campaigns/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    if (!['active', 'paused', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Trạng thái không hợp lệ' });
    }
    const campaign = await Campaign.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!campaign) return res.status(404).json({ success: false, message: 'Không tìm thấy chiến dịch' });

    if (Notification) {
      await Notification.create({
        recipient: campaign.owner,
        title: status === 'active' ? '✅ Chiến dịch được phê duyệt' : status === 'rejected' ? '❌ Chiến dịch bị từ chối' : '⏸️ Chiến dịch bị tạm dừng',
        message: `Chiến dịch "${campaign.name}" đã được ${status === 'active' ? 'phê duyệt và bắt đầu chạy' : status === 'rejected' ? 'từ chối bởi quản trị viên' : 'tạm dừng'}.`,
        type: status === 'active' ? 'success' : status === 'rejected' ? 'error' : 'warning',
      });
    }

    res.json({ success: true, message: `Cập nhật trạng thái thành công`, data: campaign });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ─── Broadcast notification to all users ─────────────────────
router.post('/broadcast', async (req, res) => {
  try {
    if (!Notification) return res.status(400).json({ success: false, message: 'Notification model chưa được cài đặt' });
    const { title, message, type = 'info' } = req.body;
    if (!title || !message) return res.status(400).json({ success: false, message: 'Cần title và message' });
    const users = await User.find({ isActive: true }).select('_id');
    await Notification.insertMany(users.map(u => ({ recipient: u._id, title, message, type })));
    res.json({ success: true, message: `Đã gửi thông báo đến ${users.length} người dùng` });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

module.exports = router;
