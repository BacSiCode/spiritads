require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const rateLimit = require('express-rate-limit');

const connectDB = require('./config/db');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth');
const campaignRoutes = require('./routes/campaigns');
const adminRoutes = require('./routes/admin');
const publicRoutes = require('./routes/public');

// ─── Connect Database ─────────────────────────────────────────
connectDB();

const app = express();
// ─── Traffic Monitor ──────────────────────────────────────────
const trafficLog = {
  totalRequests: 0,
  requestsPerMinute: {},
  ipTracker: {},
  recentRequests: [],
  startTime: new Date()
};

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = new Date();
  const minute = now.toISOString().slice(0, 16);

  // Đếm tổng
  trafficLog.totalRequests++;

  // Đếm theo phút
  trafficLog.requestsPerMinute[minute] =
    (trafficLog.requestsPerMinute[minute] || 0) + 1;

  // Đếm theo IP
  trafficLog.ipTracker[ip] =
    (trafficLog.ipTracker[ip] || 0) + 1;

  // Lưu 100 request gần nhất
  trafficLog.recentRequests.push({
    ip, time: now,
    method: req.method,
    path: req.path,
    ua: req.headers['user-agent']?.slice(0, 80)
  });
  if (trafficLog.recentRequests.length > 100) {
    trafficLog.recentRequests.shift();
  }

  // Cảnh báo DDoS
  const reqCount = trafficLog.ipTracker[ip];
  if (reqCount === 50)  console.log(`⚠️  WARNING: ${ip} – ${reqCount} requests`);
  if (reqCount === 200) console.log(`🚨 DDOS ALERT: ${ip} – ${reqCount} requests!`);

  next();
});

// ─── Dashboard API ────────────────────────────────────────────
app.get('/monitor', (req, res) => {
  const ipList = Object.entries(trafficLog.ipTracker)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([ip, count]) => ({ ip, count }));

  const recentMinutes = Object.entries(trafficLog.requestsPerMinute)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-10);

  const uptime = Math.floor(
    (new Date() - trafficLog.startTime) / 1000
  );

  res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="UTF-8">
      <meta http-equiv="refresh" content="3">
      <title>SpiritAds – Traffic Monitor</title>
      <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#0a1628; color:#e2e8f0; font-family:'Courier New',monospace; padding:20px; }
        h1 { color:#38bdf8; font-size:1.4rem; margin-bottom:20px; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:24px; }
        .kpi { background:#1e3a5f; border:1px solid #2563eb; border-radius:12px; padding:20px; text-align:center; }
        .kpi-val { font-size:2.5rem; font-weight:800; color:#38bdf8; }
        .kpi-label { font-size:0.8rem; color:#94a3b8; margin-top:6px; }
        .card { background:#0f2044; border:1px solid #1e3a5f; border-radius:12px; padding:20px; margin-bottom:16px; }
        .card h3 { color:#38bdf8; margin-bottom:14px; font-size:1rem; }
        table { width:100%; border-collapse:collapse; }
        th { color:#64748b; font-size:0.75rem; padding:8px; text-align:left; border-bottom:1px solid #1e3a5f; }
        td { padding:8px; font-size:0.82rem; border-bottom:1px solid #0a1628; }
        .danger { color:#f87171; font-weight:700; }
        .warning { color:#fbbf24; }
        .safe { color:#4ade80; }
        .bar { height:8px; background:#2563eb; border-radius:4px; margin-top:4px; }
        .refresh { color:#475569; font-size:0.75rem; text-align:right; margin-bottom:16px; }
        .alert { background:#7f1d1d; border:1px solid #f87171; border-radius:8px; padding:12px 16px; margin-bottom:16px; color:#fca5a5; }
      </style>
    </head>
    <body>
      <h1>📡 SpiritAds – Traffic Monitor</h1>
      <div class="refresh">🔄 Tự động refresh mỗi 3 giây – ${now.toLocaleString('vi-VN')}</div>

      ${ipList[0]?.count > 200 ? `<div class="alert">🚨 CẢNH BÁO DDOS! IP ${ipList[0].ip} đã gửi ${ipList[0].count} requests!</div>` : ''}

      <div class="grid">
        <div class="kpi">
          <div class="kpi-val">${trafficLog.totalRequests.toLocaleString()}</div>
          <div class="kpi-label">Tổng Requests</div>
        </div>
        <div class="kpi">
          <div class="kpi-val">${Object.keys(trafficLog.ipTracker).length}</div>
          <div class="kpi-label">Unique IPs</div>
        </div>
        <div class="kpi">
          <div class="kpi-val">${recentMinutes.slice(-1)[0]?.[1] || 0}</div>
          <div class="kpi-label">Requests/phút (hiện tại)</div>
        </div>
        <div class="kpi">
          <div class="kpi-val">${Math.floor(uptime/60)}m ${uptime%60}s</div>
          <div class="kpi-label">Uptime Server</div>
        </div>
      </div>

      <div class="card">
        <h3>📊 Requests theo phút (10 phút gần nhất)</h3>
        <table>
          <tr><th>Thời gian</th><th>Số requests</th><th>Biểu đồ</th></tr>
          ${recentMinutes.map(([time, count]) => `
            <tr>
              <td>${time.slice(11)}</td>
              <td class="${count > 100 ? 'danger' : count > 50 ? 'warning' : 'safe'}">${count}</td>
              <td><div class="bar" style="width:${Math.min(count, 300)/3}px"></div></td>
            </tr>
          `).join('')}
        </table>
      </div>

      <div class="card">
        <h3>🌍 Top IPs (nhiều request nhất)</h3>
        <table>
          <tr><th>IP</th><th>Requests</th><th>Mức độ</th></tr>
          ${ipList.map(({ip, count}) => `
            <tr>
              <td>${ip}</td>
              <td class="${count > 200 ? 'danger' : count > 50 ? 'warning' : 'safe'}">${count}</td>
              <td>${count > 200 ? '🚨 DDoS' : count > 50 ? '⚠️ Nghi ngờ' : '✅ Bình thường'}</td>
            </tr>
          `).join('')}
        </table>
      </div>

      <div class="card">
        <h3>🕐 20 Requests gần nhất</h3>
        <table>
          <tr><th>Thời gian</th><th>IP</th><th>Method</th><th>Path</th></tr>
          ${trafficLog.recentRequests.slice(-20).reverse().map(r => `
            <tr>
              <td>${new Date(r.time).toLocaleTimeString('vi-VN')}</td>
              <td>${r.ip}</td>
              <td>${r.method}</td>
              <td>${r.path}</td>
            </tr>
          `).join('')}
        </table>
      </div>
    </body>
    </html>
  `);
});
// ─── Security Middleware ──────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // disabled for dev; enable in prod
}));

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5000',
  credentials: true,
}));

// ─── Rate Limiting ────────────────────────────────────────────
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { success: false, message: 'Quá nhiều request. Vui lòng thử lại sau 15 phút.' },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Quá nhiều lần thử đăng nhập. Vui lòng chờ 15 phút.' },
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ─── Parsing ──────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── Logging ──────────────────────────────────────────────────
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// ─── Static Files ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// ─── API Routes ───────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/campaigns', campaignRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', publicRoutes); // brands, contact

// ─── Health check ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'SpiritAds API đang hoạt động',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV,
  });
});

// ─── SPA Fallback (serve index.html for all non-API routes) ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── Error Handler ────────────────────────────────────────────
app.use(errorHandler);

// ─── Start Server ─────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 SpiritAds Server chạy tại: http://localhost:${PORT}`);
  console.log(`📦 Môi trường: ${process.env.NODE_ENV}`);
  console.log(`🗄️  MongoDB: ${process.env.MONGO_URI}\n`);
});

module.exports = app;
