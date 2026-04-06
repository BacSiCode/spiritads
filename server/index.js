require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const morgan  = require('morgan');
const path    = require('path');

const connectDB    = require('./config/db');
const errorHandler = require('./middleware/errorHandler');
const antiDDoS     = require('./middleware/antiDDoS');

const authRoutes     = require('./routes/auth');
const campaignRoutes = require('./routes/campaigns');
const adminRoutes    = require('./routes/admin');
const publicRoutes   = require('./routes/public');

connectDB();
const app = express();

// ══════════════════════════════════════════════════════════════
//  1. ANTI-DDOS — đặt SỚM NHẤT
//     Thứ tự: Honeypot → IP Block → Slow → Conn → Bot → Rate
// ══════════════════════════════════════════════════════════════
antiDDoS.applyTo(app);

// ══════════════════════════════════════════════════════════════
//  2. Security headers
// ══════════════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CLIENT_URL || '*', credentials: true }));

// ══════════════════════════════════════════════════════════════
//  3. Per-route rate limiters
// ══════════════════════════════════════════════════════════════
app.use('/api/auth/login',    antiDDoS.authLimiter);
app.use('/api/auth/register', antiDDoS.authLimiter);
app.use('/api/contact',       antiDDoS.contactLimiter);
app.use('/api/',              antiDDoS.apiLimiter);

// ══════════════════════════════════════════════════════════════
//  4. Body parsing + logging
// ══════════════════════════════════════════════════════════════
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
if (process.env.NODE_ENV === 'development') app.use(morgan('dev'));

// ══════════════════════════════════════════════════════════════
//  5. Static files
// ══════════════════════════════════════════════════════════════
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// ══════════════════════════════════════════════════════════════
//  6. Traffic log (cho monitor dashboard)
// ══════════════════════════════════════════════════════════════
const trafficLog = {
  totalRequests:     0,
  requestsPerMinute: {},
  recentRequests:    [],
  startTime:         new Date(),
};

app.use((req, res, next) => {
  const ip     = req.headers['cf-connecting-ip']
               || req.socket.remoteAddress
               || req.ip;
  const now    = new Date();
  const minute = now.toISOString().slice(0, 16);
  trafficLog.totalRequests++;
  trafficLog.requestsPerMinute[minute] = (trafficLog.requestsPerMinute[minute] || 0) + 1;
  trafficLog.recentRequests.push({ ip, time: now, method: req.method, path: req.path, ua: req.headers['user-agent']?.slice(0, 80) });
  if (trafficLog.recentRequests.length > 200) trafficLog.recentRequests.shift();
  next();
});

// ══════════════════════════════════════════════════════════════
//  7. Monitor Dashboard
// ══════════════════════════════════════════════════════════════
app.get('/monitor', (req, res) => {
  const key = req.query.key;
  if (key !== (process.env.MONITOR_KEY || 'Phuc2026secret')) {
    return res.status(403).send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{background:#050d1a;display:flex;align-items:center;justify-content:center;height:100vh;font-family:'Segoe UI',sans-serif}
      .box{background:#0f2044;border:1px solid #1e3a5f;border-radius:20px;padding:48px 40px;text-align:center;width:360px}
      h2{color:#38bdf8;margin-bottom:8px;font-size:1.3rem}
      .sub{color:#475569;font-size:.83rem;margin-bottom:24px}
      input{padding:12px 16px;border-radius:10px;border:1.5px solid #1e3a5f;background:#1a2f4e;color:#fff;font-size:.9rem;margin-bottom:12px;width:100%;outline:none}
      input:focus{border-color:#2563eb}
      button{background:linear-gradient(135deg,#1d4ed8,#38bdf8);color:#fff;border:none;padding:12px;border-radius:10px;cursor:pointer;font-size:.9rem;width:100%;font-weight:700}
      .err{color:#f87171;margin-top:10px;font-size:.8rem}
    </style></head><body><div class="box">
      <div style="font-size:2.5rem;margin-bottom:16px">🛡️</div>
      <h2>Monitor Dashboard</h2>
      <p class="sub">Chỉ dành cho quản trị viên SpiritAds</p>
      <form method="GET" action="/monitor">
        <input type="password" name="key" placeholder="Nhập mật khẩu bảo mật...">
        <button type="submit">🔐 Xác nhận</button>
      </form>
      ${req.query.key ? '<div class="err">❌ Sai mật khẩu!</div>' : ''}
    </div></body></html>`);
  }

  const now          = new Date();
  const storeStats   = antiDDoS.store.stats();
  const recentMins   = Object.entries(trafficLog.requestsPerMinute).sort((a, b) => a[0].localeCompare(b[0])).slice(-10);
  const currentRPM   = recentMins.slice(-1)[0]?.[1] || 0;
  const uptime       = Math.floor((now - trafficLog.startTime) / 1000);
  const isProtected  = antiDDoS.isEnabled();
  const isDanger     = currentRPM > 100 || storeStats.bannedIPs > 0;

  const ipList = Object.entries(
    trafficLog.recentRequests.reduce((acc, r) => { acc[r.ip] = (acc[r.ip] || 0) + 1; return acc; }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([ip, count]) => ({ ip, count }));

  res.send(`<!DOCTYPE html><html lang="vi"><head>
    <meta charset="UTF-8"><meta http-equiv="refresh" content="3">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>SpiritAds Monitor</title>
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{background:#050d1a;color:#e2e8f0;font-family:'Segoe UI',sans-serif;padding:20px;min-height:100vh}
      .hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1e3a5f}
      .hdr h1{color:#38bdf8;font-size:1.25rem}
      .badges{display:flex;align-items:center;gap:8px}
      .pill{padding:4px 12px;border-radius:99px;font-size:.75rem;font-weight:700}
      .pill-on{background:#064e3b;color:#6ee7b7}
      .pill-off{background:#78350f;color:#fcd34d}
      .live{display:flex;align-items:center;gap:5px;font-size:.75rem;color:#4ade80}
      .dot{width:8px;height:8px;border-radius:50%;background:#4ade80;animation:pulse 1s infinite}
      @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
      .kpi{background:linear-gradient(145deg,#0f2044,#162d52);border:1px solid #1e3a5f;border-radius:14px;padding:18px;text-align:center}
      .kpi-i{font-size:1.3rem;margin-bottom:6px}
      .kpi-v{font-size:1.8rem;font-weight:800;color:#38bdf8;line-height:1}
      .kpi-l{font-size:.68rem;color:#64748b;margin-top:4px}
      .kpi.danger .kpi-v{color:#f87171}.kpi.warn .kpi-v{color:#fbbf24}.kpi.safe .kpi-v{color:#4ade80}
      .card{background:#0a1f3d;border:1px solid #1e3a5f;border-radius:14px;padding:18px;margin-bottom:14px}
      .card-t{color:#38bdf8;font-size:.88rem;font-weight:700;margin-bottom:12px}
      table{width:100%;border-collapse:collapse;font-size:.8rem}
      th{color:#475569;font-size:.68rem;padding:7px 8px;text-align:left;border-bottom:1px solid #1e3a5f;text-transform:uppercase;letter-spacing:.05em}
      td{padding:8px;border-bottom:1px solid #0a1628;color:#cbd5e1}
      tr:hover td{background:rgba(37,99,235,.07)}
      .badge{padding:2px 9px;border-radius:99px;font-size:.7rem;font-weight:700}
      .bd{background:#7f1d1d;color:#fca5a5}
      .bw{background:#78350f;color:#fcd34d}
      .bs{background:#064e3b;color:#6ee7b7}
      .bi{background:#1e3a5f;color:#93c5fd}
      .bar-w{height:7px;background:#1e3a5f;border-radius:3px;overflow:hidden;margin-top:3px}
      .bar-f{height:100%;background:linear-gradient(90deg,#2563eb,#38bdf8);border-radius:3px;transition:width .3s}
      .alert-box{background:linear-gradient(135deg,#7f1d1d,#991b1b);border:1px solid #f87171;border-radius:12px;padding:14px 18px;margin-bottom:18px;animation:ap 1s infinite}
      @keyframes ap{0%,100%{opacity:1}50%{opacity:.8}}
      .two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
      .ref{color:#334155;font-size:.68rem;text-align:right;margin-bottom:14px}
      .tag{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:6px;font-size:.7rem}
      .tag-on{background:#064e3b22;border:1px solid #064e3b;color:#6ee7b7}
      .tag-off{background:#7f1d1d22;border:1px solid #7f1d1d;color:#fca5a5}
      @media(max-width:700px){.two{grid-template-columns:1fr}}
    </style></head><body>
    <div class="hdr">
      <h1>📡 SpiritAds Monitor</h1>
      <div class="badges">
        <span class="pill ${isProtected ? 'pill-on' : 'pill-off'}">${isProtected ? '🛡️ BẬT' : '⚠️ TẮT'}</span>
        <div class="live"><div class="dot"></div>${now.toLocaleString('vi-VN')}</div>
      </div>
    </div>
    <div class="ref">🔄 Refresh mỗi 3 giây</div>

    ${isDanger && isProtected ? `<div class="alert-box">🚨 <strong>CẢNH BÁO!</strong> ${storeStats.bannedIPs} IP bị ban · RPM: ${currentRPM}</div>` : ''}

    <!-- Trạng thái từng layer -->
    <div class="card" style="margin-bottom:14px">
      <div class="card-t">🔧 Trạng thái bảo vệ</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        ${['Honeypot','IP Block','Slow Req','Conn Limit','Bot Detect','Rate Limit'].map((l,i) =>
          `<span class="tag ${isProtected ? 'tag-on' : 'tag-off'}">${isProtected ? '✓' : '✗'} ${l}</span>`
        ).join('')}
        <span class="tag ${process.env.TELEGRAM_BOT_TOKEN ? 'tag-on' : 'tag-off'}">${process.env.TELEGRAM_BOT_TOKEN ? '✓' : '✗'} Telegram</span>
      </div>
    </div>

    <div class="grid">
      <div class="kpi ${currentRPM > 100 ? 'danger' : currentRPM > 50 ? 'warn' : 'safe'}">
        <div class="kpi-i">⚡</div><div class="kpi-v">${currentRPM}</div><div class="kpi-l">Req/phút</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">📊</div><div class="kpi-v">${trafficLog.totalRequests.toLocaleString()}</div><div class="kpi-l">Tổng Requests</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">🌍</div><div class="kpi-v">${ipList.length}</div><div class="kpi-l">Unique IPs</div>
      </div>
      <div class="kpi ${storeStats.bannedIPs > 0 ? 'danger' : 'safe'}">
        <div class="kpi-i">🚫</div><div class="kpi-v">${storeStats.bannedIPs}</div><div class="kpi-l">IPs bị ban</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">🔗</div><div class="kpi-v">${storeStats.activeConns}</div><div class="kpi-l">Connections</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">🛑</div><div class="kpi-v">${storeStats.totalBlocked.toLocaleString()}</div><div class="kpi-l">Tổng bị chặn</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">⏱️</div><div class="kpi-v">${Math.floor(uptime/3600)}h${Math.floor((uptime%3600)/60)}m</div><div class="kpi-l">Uptime</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">🌡️</div><div class="kpi-v">${process.env.NODE_ENV === 'production' ? 'PROD' : 'DEV'}</div><div class="kpi-l">Môi trường</div>
      </div>
    </div>

    <div class="card">
      <div class="card-t">📈 Requests theo phút</div>
      <table><tr><th>Thời gian</th><th>Requests</th><th>Biểu đồ</th></tr>
      ${recentMins.map(([t, c]) => `<tr>
        <td>${t.slice(11)}</td>
        <td><span class="badge ${c > 100 ? 'bd' : c > 50 ? 'bw' : 'bs'}">${c}</span></td>
        <td style="width:55%"><div class="bar-w"><div class="bar-f" style="width:${Math.min(c/2,100)}%"></div></div></td>
      </tr>`).join('')}
      </table>
    </div>

    <div class="two">
      <div class="card">
        <div class="card-t">🌍 Top IPs</div>
        <table><tr><th>IP</th><th>Req</th><th>Trạng thái</th></tr>
        ${ipList.map(({ ip, count }) => `<tr>
          <td style="font-family:monospace;font-size:.72rem">${ip}</td>
          <td>${count}</td>
          <td><span class="badge ${antiDDoS.store.isBanned(ip) ? 'bd' : count > 50 ? 'bw' : 'bs'}">
            ${antiDDoS.store.isBanned(ip) ? '🚫 Banned' : count > 50 ? '⚠️ High' : '✅ OK'}
          </span></td>
        </tr>`).join('')}
        </table>
      </div>
      <div class="card">
        <div class="card-t">🕐 Requests gần nhất</div>
        <table><tr><th>Giờ</th><th>IP</th><th>Path</th></tr>
        ${trafficLog.recentRequests.slice(-15).reverse().map(r => `<tr>
          <td>${new Date(r.time).toLocaleTimeString('vi-VN')}</td>
          <td style="font-family:monospace;font-size:.7rem">${r.ip}</td>
          <td style="color:#64748b">${r.method} ${r.path.slice(0,28)}</td>
        </tr>`).join('')}
        </table>
      </div>
    </div>

    ${storeStats.topOffenders.length ? `
    <div class="card">
      <div class="card-t">🚫 IPs đang bị ban</div>
      <table><tr><th>IP</th><th>Lý do</th><th>Vi phạm</th><th>Lần ban</th><th>Hết hạn</th></tr>
      ${storeStats.topOffenders.map(b => `<tr>
        <td style="font-family:monospace">${b.ip}</td>
        <td style="color:#94a3b8;font-size:.75rem">${b.reason}</td>
        <td><span class="badge bd">${b.violations}×</span></td>
        <td><span class="badge ${b.banCount >= 3 ? 'bd' : 'bw'}">#${b.banCount}</span></td>
        <td style="font-size:.72rem;color:#64748b">${new Date(b.expiresAt).toLocaleTimeString('vi-VN')}</td>
      </tr>`).join('')}
      </table>
    </div>` : ''}

    ${storeStats.recentAttacks?.length ? `
    <div class="card">
      <div class="card-t">⚔️ Log tấn công gần nhất</div>
      <table><tr><th>Thời gian</th><th>IP</th><th>Loại</th><th>Chi tiết</th></tr>
      ${storeStats.recentAttacks.slice(0, 10).map(a => `<tr>
        <td style="font-size:.72rem">${new Date(a.time).toLocaleTimeString('vi-VN')}</td>
        <td style="font-family:monospace;font-size:.72rem">${a.ip}</td>
        <td><span class="badge bd">${a.type}</span></td>
        <td style="color:#64748b;font-size:.75rem">${a.detail}</td>
      </tr>`).join('')}
      </table>
    </div>` : ''}

  </body></html>`);
});

// ══════════════════════════════════════════════════════════════
//  8. API Routes
// ══════════════════════════════════════════════════════════════
app.use('/api/auth',      authRoutes);
app.use('/api/campaigns', campaignRoutes);
app.use('/api/admin',     adminRoutes);
app.use('/api',           publicRoutes);

// ── Admin Security API ────────────────────────────────────────
const { protect, authorize } = require('./middleware/auth');
app.get(   '/api/admin/security/status',    protect, authorize('admin'), antiDDoS.adminHandlers.getStatus);
app.post(  '/api/admin/security/ban',       protect, authorize('admin'), antiDDoS.adminHandlers.banIp);
app.delete('/api/admin/security/ban/:ip',   protect, authorize('admin'), antiDDoS.adminHandlers.unbanIp);
app.get(   '/api/admin/security/blacklist', protect, authorize('admin'), antiDDoS.adminHandlers.getBlacklist);
app.get(   '/api/admin/security/attacks',   protect, authorize('admin'), antiDDoS.adminHandlers.getAttackLog);

// ══════════════════════════════════════════════════════════════
//  9. Health check + SPA fallback
// ══════════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => res.json({
  success:   true,
  message:   'SpiritAds API đang hoạt động',
  timestamp: new Date().toISOString(),
  env:       process.env.NODE_ENV,
  uptime:    Math.floor(process.uptime()) + 's',
  protected: antiDDoS.isEnabled(),
}));

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.use(errorHandler);

// ══════════════════════════════════════════════════════════════
//  10. Start server
// ══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 SpiritAds: http://localhost:${PORT}`);
  console.log(`📦 Môi trường: ${process.env.NODE_ENV}`);
  console.log(`🗄️  MongoDB: ${process.env.MONGO_URI}`);
  console.log(`🛡️  Anti-DDoS: ${antiDDoS.isEnabled() ? '✅ BẬT' : '❌ TẮT'}`);
  console.log(`📱 Telegram: ${process.env.TELEGRAM_BOT_TOKEN ? '✅ OK' : '❌ Chưa cấu hình'}\n`);
});

module.exports = app;
