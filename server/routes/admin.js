const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Campaign = require('../models/Campaign');
const Contact = require('../models/Contact');
const Brand = require('../models/Brand');
const { protect, authorize } = require('../middleware/auth');

// All admin routes require auth + admin role
router.use(protect, authorize('admin'));

// ─────────────────────────────────────────────────────────────
// GET /api/admin/overview  – system-wide stats
// ─────────────────────────────────────────────────────────────
router.get('/overview', async (req, res) => {
  try {
    const [
      totalUsers, newUsersToday, totalCampaigns,
      activeCampaigns, pendingCampaigns, totalContacts,
      newContactsToday, totalBrands,
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } }),
      Campaign.countDocuments(),
      Campaign.countDocuments({ status: 'active' }),
      Campaign.countDocuments({ status: 'pending' }),
      Contact.countDocuments(),
      Contact.countDocuments({ createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } }),
      Brand.countDocuments(),
    ]);

    // Total revenue (sum of spent budgets)
    const revenueAgg = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$budget.spent' } } }
    ]);
    const totalRevenue = revenueAgg[0]?.total || 0;

    // Users by role
    const usersByRole = await User.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } }
    ]);

    // Campaigns by status
    const campaignsByStatus = await Campaign.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    // Monthly new users (last 6 months)
    const monthlyUsers = [];
    for (let i = 5; i >= 0; i--) {
      const start = new Date(); start.setMonth(start.getMonth() - i); start.setDate(1); start.setHours(0, 0, 0, 0);
      const end = new Date(start); end.setMonth(end.getMonth() + 1);
      const count = await User.countDocuments({ createdAt: { $gte: start, $lt: end } });
      monthlyUsers.push({
        label: start.toLocaleDateString('vi-VN', { month: 'short' }),
        count,
      });
    }

    res.json({
      success: true,
      data: {
        users: { total: totalUsers, newToday: newUsersToday, byRole: usersByRole },
        campaigns: { total: totalCampaigns, active: activeCampaigns, pending: pendingCampaigns, byStatus: campaignsByStatus },
        contacts: { total: totalContacts, newToday: newContactsToday },
        brands: { total: totalBrands },
        revenue: { total: totalRevenue },
        monthlyUsers,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/admin/users  – paginated user list
// ─────────────────────────────────────────────────────────────
router.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 15, role, search, isActive } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const filter = {};
    if (role) filter.role = role;
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (search) {
      filter.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }

    const [users, total] = await Promise.all([
      User.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)),
      User.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: users,
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// PATCH /api/admin/users/:id  – update user (role, status)
// ─────────────────────────────────────────────────────────────
router.patch('/users/:id', async (req, res) => {
  try {
    const { role, isActive } = req.body;

    // Prevent self-demotion
    if (req.params.id === req.user._id.toString() && role && role !== 'admin') {
      return res.status(400).json({ success: false, message: 'Không thể thay đổi role của chính mình' });
    }

    const update = {};
    if (role) update.role = role;
    if (isActive !== undefined) update.isActive = isActive;

    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });

    res.json({ success: true, message: 'Cập nhật người dùng thành công', data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /api/admin/contacts  – all contact submissions
// ─────────────────────────────────────────────────────────────
router.get('/contacts', async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const filter = status ? { status } : {};

    const [contacts, total] = await Promise.all([
      Contact.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)),
      Contact.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: contacts,
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// PATCH /api/admin/contacts/:id
router.patch('/contacts/:id', async (req, res) => {
  try {
    const contact = await Contact.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!contact) return res.status(404).json({ success: false, message: 'Không tìm thấy' });
    res.json({ success: true, data: contact });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
