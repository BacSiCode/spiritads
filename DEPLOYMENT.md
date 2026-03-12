# 🚀 SPIRITADS – Hướng Dẫn Triển Khai Toàn Tập

## 📁 Cấu Trúc Thư Mục

```
spiritads/
├── public/                    ← Frontend (static files)
│   ├── index.html             ← Trang chủ (UI gốc của bạn + JS mới)
│   ├── css/
│   │   └── style.css          ← CSS gốc (không thay đổi)
│   └── js/
│       ├── api.js             ← HTTP client, Auth state, Toast, Modal
│       ├── auth.js            ← Login/Register modal + handlers
│       ├── dashboard.js       ← Dashboard, Campaign management, Admin
│       └── app.js             ← Bootstrap + page interactions
│
├── server/                    ← Backend (Node.js + Express)
│   ├── index.js               ← Entry point – Express app
│   ├── config/
│   │   ├── db.js              ← MongoDB connection
│   │   └── seed.js            ← Demo data seeder
│   ├── middleware/
│   │   ├── auth.js            ← JWT protect, authorize, optionalAuth
│   │   └── errorHandler.js    ← Global error handler
│   ├── models/
│   │   ├── User.js            ← User schema (user/advertiser/admin)
│   │   ├── Campaign.js        ← Campaign schema + stats
│   │   ├── Brand.js           ← Brand/Product schema
│   │   └── Contact.js         ← Contact/Lead schema
│   └── routes/
│       ├── auth.js            ← /api/auth/*
│       ├── campaigns.js       ← /api/campaigns/*
│       ├── admin.js           ← /api/admin/*
│       └── public.js          ← /api/brands, /api/contact
│
├── uploads/                   ← Media upload folder
├── .env.example               ← Biến môi trường mẫu
├── .gitignore
├── package.json
└── DEPLOYMENT.md              ← File này
```

---

## ⚡ Cài Đặt Local (Development)

### Bước 1 – Yêu cầu hệ thống
```bash
node --version   # v18+
npm --version    # v9+
mongod --version # v6+ (hoặc dùng MongoDB Atlas)
```

### Bước 2 – Clone & cài packages
```bash
cd spiritads
npm install
```

### Bước 3 – Cấu hình môi trường
```bash
cp .env.example .env
# Chỉnh sửa .env:
nano .env
```

Nội dung `.env` tối thiểu:
```env
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb://localhost:27017/spiritads
JWT_SECRET=your_super_secret_key_min_32_chars
JWT_EXPIRE=7d
CLIENT_URL=http://localhost:5000
```

### Bước 4 – Khởi động MongoDB
```bash
# macOS (Homebrew)
brew services start mongodb-community

# Ubuntu/Debian
sudo systemctl start mongod

# Windows
net start MongoDB
```

### Bước 5 – Seed dữ liệu demo
```bash
npm run seed
```

Output:
```
✅ Tạo 4 người dùng
✅ Tạo 4 thương hiệu
✅ Tạo 4 chiến dịch
📋 Tài khoản demo:
   Admin      : admin@spiritads.vn  / admin123456
   Advertiser : minh@dalat.vn       / password123
   Advertiser : hoa@hapro.vn        / password123
   User       : binh@user.vn        / password123
```

### Bước 6 – Chạy server
```bash
# Development (auto-reload)
npm run dev

# Production
npm start
```

Mở trình duyệt: **http://localhost:5000**

---

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Auth | Mô tả |
|--------|----------|------|-------|
| POST | /api/auth/register | ✗ | Đăng ký tài khoản |
| POST | /api/auth/login | ✗ | Đăng nhập |
| GET | /api/auth/me | ✅ | Lấy thông tin cá nhân |
| PUT | /api/auth/profile | ✅ | Cập nhật hồ sơ |
| PUT | /api/auth/change-password | ✅ | Đổi mật khẩu |

### Campaigns
| Method | Endpoint | Auth | Mô tả |
|--------|----------|------|-------|
| GET | /api/campaigns | ✅ | Danh sách chiến dịch |
| GET | /api/campaigns/my-stats | ✅ | Thống kê dashboard |
| GET | /api/campaigns/:id | ✅ | Chi tiết chiến dịch |
| POST | /api/campaigns | ✅ advertiser+ | Tạo chiến dịch |
| PUT | /api/campaigns/:id | ✅ owner | Cập nhật |
| DELETE | /api/campaigns/:id | ✅ owner | Xóa |
| PATCH | /api/campaigns/:id/status | ✅ admin | Phê duyệt/từ chối |

### Public
| Method | Endpoint | Auth | Mô tả |
|--------|----------|------|-------|
| GET | /api/brands | ✗ | Danh sách thương hiệu |
| POST | /api/brands | ✅ advertiser+ | Thêm thương hiệu |
| PUT | /api/brands/:id | ✅ owner | Cập nhật thương hiệu |
| DELETE | /api/brands/:id | ✅ owner | Xóa thương hiệu |
| POST | /api/contact | ✗ | Gửi form liên hệ |

### Admin (role: admin only)
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | /api/admin/overview | Thống kê hệ thống |
| GET | /api/admin/users | Danh sách người dùng |
| PATCH | /api/admin/users/:id | Cập nhật role/status |
| GET | /api/admin/contacts | Danh sách liên hệ |
| PATCH | /api/admin/contacts/:id | Cập nhật lead status |

---

## 🌐 Triển Khai Production

### Option 1 – Railway (Đơn giản nhất, miễn phí)
```bash
# Cài Railway CLI
npm i -g @railway/cli

# Đăng nhập & deploy
railway login
railway init
railway up

# Thêm MongoDB plugin trên Railway dashboard
# Set environment variables trong Settings
```

### Option 2 – Render.com
1. Push code lên GitHub
2. Vào render.com → New Web Service
3. Kết nối repo, chọn:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Add environment variables
5. Thêm MongoDB Atlas (free tier)

### Option 3 – VPS (DigitalOcean / Linode)
```bash
# Trên server Ubuntu 22.04
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Cài MongoDB
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update && sudo apt install -y mongodb-org
sudo systemctl enable mongod && sudo systemctl start mongod

# Clone project
git clone <your-repo> /var/www/spiritads
cd /var/www/spiritads
npm install

# Setup .env
cp .env.example .env && nano .env

# PM2 process manager
npm install -g pm2
pm2 start server/index.js --name spiritads
pm2 startup && pm2 save

# Nginx reverse proxy
sudo apt install nginx
sudo nano /etc/nginx/sites-available/spiritads
```

Nginx config:
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/spiritads /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# SSL với Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## 🗄️ Database Schema

### User
```js
{ fullName, email, password(hashed), role: ['user','advertiser','admin'],
  isActive, isVerified, company: {name, taxCode, address, phone, website},
  phone, avatar, totalCampaigns, totalSpent, lastLogin }
```

### Campaign
```js
{ owner(ref:User), name, description, brand, productType, type, status,
  budget: {total, spent, dailyLimit}, startDate, endDate,
  targeting: {ageMin, ageMax, gender, locations, interests},
  channels[], stats: {impressions, clicks, conversions, ctr, cpc, roi},
  approvedBy(ref:User), rejectionReason }
```

### Brand
```js
{ owner(ref:User), name, description, category, origin, image, logo,
  alcoholContent, volume, price, isFeatured, isActive, rating, badge }
```

### Contact
```js
{ fullName, phone, email, company, service, message,
  status: ['new','contacted','qualified','converted','closed'],
  assignedTo(ref:User), notes }
```

---

## 🔒 Bảo Mật

- ✅ Password hashing với **bcryptjs** (12 rounds)
- ✅ **JWT** authentication (7 ngày hết hạn)
- ✅ **Rate limiting** – 100 req/15min (auth: 20 req)
- ✅ **Helmet.js** – HTTP security headers
- ✅ **CORS** – chỉ cho phép CLIENT_URL
- ✅ **express-validator** – validate tất cả inputs
- ✅ Role-based access control (user / advertiser / admin)
- ✅ MongoDB injection prevention (mongoose)

---

## 🧪 Test Nhanh với Curl

```bash
# Register
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"fullName":"Test User","email":"test@test.vn","password":"123456","role":"advertiser"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@spiritads.vn","password":"admin123456"}'

# Get brands (public)
curl http://localhost:5000/api/brands

# Health check
curl http://localhost:5000/api/health
```
