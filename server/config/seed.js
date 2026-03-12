require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const connectDB = require('./db');

const User = require('../models/User');
const Campaign = require('../models/Campaign');
const Brand = require('../models/Brand');
const Contact = require('../models/Contact');

const seed = async () => {
  await connectDB();
  console.log('🌱 Bắt đầu seed dữ liệu...\n');

  // Clear existing data
  await Promise.all([User.deleteMany(), Campaign.deleteMany(), Brand.deleteMany(), Contact.deleteMany()]);
  console.log('🗑️  Đã xóa dữ liệu cũ');

  // ─── USERS ────────────────────────────────────────────────
  const users = await User.create([
    {
      fullName: 'Quản Trị Viên',
      email: 'admin@phucle.vn',
      password: 'admin123456',
      role: 'admin',
      isVerified: true,
      isActive: true,
      phone: '0901234567',
    },
    {
      fullName: 'Nguyễn Văn Minh',
      email: 'minh@dalat.vn',
      password: 'password123',
      role: 'advertiser',
      isVerified: true,
      phone: '0912345678',
      company: { name: 'Dalat Winery Co.', taxCode: '0100109106', address: 'Đà Lạt, Lâm Đồng', phone: '0912345678', website: 'https://dalatberry.com' },
    },
    {
      fullName: 'Trần Thị Hoa',
      email: 'hoa@hapro.vn',
      password: 'password123',
      role: 'advertiser',
      isVerified: true,
      phone: '0923456789',
      company: { name: 'Hapro Trading Corp', taxCode: '0100109107', address: 'Hà Nội', phone: '0923456789' },
    },
    {
      fullName: 'Lê Quốc Bình',
      email: 'binh@user.vn',
      password: 'password123',
      role: 'user',
      phone: '0934567890',
    },
  ]);
  console.log(`✅ Tạo ${users.length} người dùng`);

  const [admin, advertiser1, advertiser2] = users;

  // ─── BRANDS ───────────────────────────────────────────────
  const brands = await Brand.create([
    {
      owner: advertiser1._id, name: 'Vang Đỏ Đà Lạt Premium',
      description: 'Vang đỏ đặc biệt từ vùng cao nguyên Đà Lạt, hương thơm nồng nàn, vị chát nhẹ cân bằng.',
      category: 'Vang', origin: 'Đà Lạt, Lâm Đồng',
      alcoholContent: 12.5, volume: 750, price: 280000,
      isFeatured: true, isActive: true, rating: 4.8, reviewCount: 342, badge: 'Nổi bật',
    },
    {
      owner: advertiser2._id, name: 'Hapro Brandy 12 Năm',
      description: 'Brandy cao cấp ủ 12 năm trong thùng gỗ sồi Pháp, hương caramel và vanilla tinh tế.',
      category: 'Brandy', origin: 'Hà Nội',
      alcoholContent: 40, volume: 700, price: 650000,
      isFeatured: true, isActive: true, rating: 4.9, reviewCount: 186, badge: 'Premium',
    },
    {
      owner: advertiser1._id, name: 'Vang Trắng Đà Lạt Sauvignon',
      description: 'Vang trắng tươi mát, thích hợp uống kèm hải sản và các món ăn nhẹ.',
      category: 'Vang', origin: 'Đà Lạt, Lâm Đồng',
      alcoholContent: 11.5, volume: 750, price: 240000,
      isFeatured: false, isActive: true, rating: 4.6, reviewCount: 215, badge: 'Mới',
    },
    {
      owner: advertiser2._id, name: 'Rượu Mơ Hà Nội',
      description: 'Rượu mơ truyền thống Hà Nội, vị ngọt thanh tự nhiên từ mơ tươi đặc sản.',
      category: 'Khác', origin: 'Hà Nội',
      alcoholContent: 35, volume: 500, price: 180000,
      isFeatured: true, isActive: true, rating: 4.5, reviewCount: 428, badge: 'Bán chạy',
    },
  ]);
  console.log(`✅ Tạo ${brands.length} thương hiệu`);

  // ─── CAMPAIGNS ────────────────────────────────────────────
  const now = new Date();
  const campaigns = await Campaign.create([
    {
      owner: advertiser1._id, name: 'Chiến dịch Tết 2026 – Vang Đà Lạt',
      description: 'Tăng nhận diện thương hiệu vang Đà Lạt dịp Tết Nguyên Đán.',
      brand: 'Dalat Winery', productType: 'Vang', type: 'marketing', status: 'active',
      budget: { total: 50000000, spent: 34000000, dailyLimit: 2000000 },
      startDate: new Date(now.getFullYear(), 0, 1), endDate: new Date(now.getFullYear(), 2, 31),
      channels: ['facebook', 'instagram', 'google'],
      stats: { impressions: 1240000, clicks: 87600, conversions: 4120, ctr: 7.06, cpc: 388, roi: 280 },
      approvedBy: admin._id, approvedAt: new Date(),
    },
    {
      owner: advertiser1._id, name: 'Brand Awareness – Vang Trắng Q1',
      description: 'Xây dựng nhận thức thương hiệu vang trắng mới ra mắt.',
      brand: 'Dalat Winery', productType: 'Vang', type: 'brand', status: 'active',
      budget: { total: 30000000, spent: 18500000, dailyLimit: 1000000 },
      startDate: new Date(now.getFullYear(), 0, 15), endDate: new Date(now.getFullYear(), 3, 15),
      channels: ['facebook', 'youtube'],
      stats: { impressions: 640000, clicks: 32000, conversions: 1800, ctr: 5.0, cpc: 578, roi: 195 },
      approvedBy: admin._id, approvedAt: new Date(),
    },
    {
      owner: advertiser2._id, name: 'Hapro Brandy – Premium Segment',
      description: 'Nhắm đến phân khúc cao cấp, giới thiệu Brandy 12 năm.',
      brand: 'Hapro', productType: 'Brandy', type: 'product', status: 'pending',
      budget: { total: 80000000, spent: 0 },
      startDate: new Date(now.getFullYear(), 2, 20), endDate: new Date(now.getFullYear(), 5, 20),
      channels: ['google', 'display'],
      stats: { impressions: 0, clicks: 0, conversions: 0 },
    },
    {
      owner: advertiser2._id, name: 'Rượu Mơ Hà Nội – TikTok Campaign',
      description: 'Viral marketing trên TikTok cho sản phẩm rượu mơ truyền thống.',
      brand: 'Hapro', productType: 'Khác', type: 'digital', status: 'draft',
      budget: { total: 25000000, spent: 0 },
      startDate: new Date(now.getFullYear(), 3, 1), endDate: new Date(now.getFullYear(), 5, 30),
      channels: ['tiktok', 'instagram'],
      stats: { impressions: 0, clicks: 0, conversions: 0 },
    },
  ]);
  console.log(`✅ Tạo ${campaigns.length} chiến dịch`);

  // Update user campaign counts
  await User.findByIdAndUpdate(advertiser1._id, { totalCampaigns: 2, totalSpent: 52500000 });
  await User.findByIdAndUpdate(advertiser2._id, { totalCampaigns: 2, totalSpent: 0 });

  // ─── CONTACTS ─────────────────────────────────────────────
  await Contact.create([
    { fullName: 'Phạm Thị Lan', phone: '0945678901', email: 'lan@company.vn', company: 'ABC Trading', service: 'Quảng cáo sản phẩm rượu', message: 'Chúng tôi muốn quảng cáo sản phẩm bia mới.', status: 'new' },
    { fullName: 'Hoàng Văn Nam', phone: '0956789012', email: 'nam@beer.vn', company: 'Nam Beer Corp', service: 'Chiến dịch marketing', message: 'Cần tư vấn chiến dịch quảng cáo cho dịp hè.', status: 'contacted' },
  ]);
  console.log('✅ Tạo dữ liệu liên hệ');

  console.log('\n✨ Seed hoàn thành!\n');
  console.log('📋 Tài khoản demo:');
  console.log('   Admin  : admin@spiritads.vn  / admin123456');
  console.log('   Advertiser: minh@dalat.vn    / password123');
  console.log('   Advertiser: hoa@hapro.vn     / password123');
  console.log('   User   : binh@user.vn        / password123\n');

  process.exit(0);
};

seed().catch(err => { console.error(err); process.exit(1); });
