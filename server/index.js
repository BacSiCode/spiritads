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

connectDB();
const app = express();
app.set('trust proxy', true);

// ══════════════════════════════════════════════════════════════
//  ANTI-DDoS CONFIG
//  Bật/tắt bằng biến môi trường: ANTI_DDOS_PROTECTION=true/false
//  Mặc định: true (khi không có biến môi trường)
// ══════════════════════════════════════════════════════════════
const ANTI_DDOS = process.env.ANTI_DDOS_PROTECTION !== 'false';

const SECURITY_CONFIG = {
  // ── Layer 1: Rate Limiting ─────────────────────────────────
  rateLimit: {
    global:  { windowMs: 60  * 1000, max: parseInt(process.env.RL_GLOBAL_MAX  || '200') },  // 200 req/phút
    api:     { windowMs: 15  * 60000, max: parseInt(process.env.RL_API_MAX     || '300') },  // 300 req/15ph
    auth:    { windowMs: 15  * 60000, max: parseInt(process.env.RL_AUTH_MAX    || '10')  },  // 10 req/15ph
    contact: { windowMs: 60  * 60000, max: parseInt(process.env.RL_CONTACT_MAX || '5')   },  // 5 req/giờ
  },
  // ── Layer 2: Bot Detection ─────────────────────────────────
  bot: {
    blockedAgents: ['sqlmap','nikto','masscan','zgrab','nmap','dirbuster','python-requests','libwww-perl'],
    anomalyRpmThreshold: parseInt(process.env.ANOMALY_RPM || '300'),
  },
  // ── Layer 3: IP Blocking ───────────────────────────────────
  ip: {
    whitelist:      (process.env.IP_WHITELIST      || '127.0.0.1,::1').split(',').filter(Boolean),
    staticBlacklist:(process.env.IP_BLACKLIST       || '').split(',').filter(Boolean),
    banThreshold:   parseInt(process.env.IP_BAN_THRESHOLD  || '50'),
    banDurationMs:  parseInt(process.env.IP_BAN_DURATION_MS || String(30 * 60000)),
  },
  // ── Layer 4: Connection Protection ────────────────────────
  conn: {
    maxPerIp:    parseInt(process.env.MAX_CONN_PER_IP || '50'),
    maxBodyBytes: 10 * 1024 * 1024,  // 10 MB
  },
  // ── Layer 5: Slow Request ──────────────────────────────────
  slow: {
    requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS || '30000'),
  },
};

if (ANTI_DDOS) {
  console.log('\x1b[32m🛡️  Anti-DDoS: BẬT\x1b[0m');
} else {
  console.log('\x1b[33m⚠️  Anti-DDoS: TẮT (ANTI_DDOS_PROTECTION=false)\x1b[0m');
}

// ══════════════════════════════════════════════════════════════
//  IN-MEMORY STORE (IP blacklist, hit tracking, conn count)
// ══════════════════════════════════════════════════════════════
const _store = {
  blacklist:   new Map(),   // ip → { expiresAt, reason, violations }
  hitMap:      new Map(),   // ip → [timestamps]
  connMap:     new Map(),   // ip → connectionCount
  violations:  new Map(),   // ip → violationCount

  isBanned(ip) {
    const e = this.blacklist.get(ip);
    if (!e) return false;
    if (Date.now() > e.expiresAt) { this.blacklist.delete(ip); return false; }
    return true;
  },
  ban(ip, reason) {
    const v = (this.blacklist.get(ip)?.violations ?? 0) + 1;
    this.blacklist.set(ip, { expiresAt: Date.now() + SECURITY_CONFIG.ip.banDurationMs, reason, violations: v });
    console.log(`\x1b[35m🚫 AUTO-BAN: ${ip} – ${reason} (violations: ${v})\x1b[0m`);
    sendAlert('BAN', `IP ${ip} bị auto-ban.\nLý do: ${reason}`);
    autoBlockCF(ip, reason);
  },
  addViolation(ip) {
    const v = (this.violations.get(ip) ?? 0) + 1;
    this.violations.set(ip, v);
    if (v >= SECURITY_CONFIG.ip.banThreshold) this.ban(ip, `violations: ${v}`);
    return v;
  },
  recordHit(ip) {
    const now = Date.now();
    const hits = (this.hitMap.get(ip) ?? []).filter(t => now - t < 60000);
    hits.push(now);
    this.hitMap.set(ip, hits);
    return hits.length;
  },
  openConn(ip)  {
    const c = (this.connMap.get(ip) ?? 0) + 1;
    this.connMap.set(ip, c); return c;
  },
  closeConn(ip) {
    const c = Math.max(0, (this.connMap.get(ip) ?? 1) - 1);
    if (c === 0) this.connMap.delete(ip); else this.connMap.set(ip, c);
  },
  stats() {
    return {
      bannedIPs:   this.blacklist.size,
      trackedIPs:  this.hitMap.size,
      activeConns: [...this.connMap.values()].reduce((a, b) => a + b, 0),
      topBanned:   [...this.blacklist.entries()]
        .sort((a, b) => b[1].violations - a[1].violations).slice(0, 10)
        .map(([ip, info]) => ({ ip, ...info })),
    };
  },
};

// Cleanup store mỗi 5 phút
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of _store.blacklist.entries()) if (now > e.expiresAt) _store.blacklist.delete(ip);
  for (const [ip, hits] of _store.hitMap.entries()) {
    const fresh = hits.filter(t => now - t < 60000);
    if (!fresh.length) _store.hitMap.delete(ip); else _store.hitMap.set(ip, fresh);
  }
}, 5 * 60000);

// ══════════════════════════════════════════════════════════════
//  ALERT HELPERS
// ══════════════════════════════════════════════════════════════
const _alertCooldown = new Map();

async function sendAlert(level, message) {
  const key = `${level}:${message.slice(0, 40)}`;
  const last = _alertCooldown.get(key) ?? 0;
  if (Date.now() - last < 60000) return;
  _alertCooldown.set(key, Date.now());

  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  const icon = { BAN:'🚫', WARN:'⚠️', CRITICAL:'🚨' }[level] ?? '🔔';
  const text = `${icon} *SpiritAds Security – ${level}*\n${message}\n\n🕐 ${new Date().toLocaleString('vi-VN')}`;

  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'Markdown',
      }),
      signal: AbortSignal.timeout(5000),
    });
  } catch (_) {}
}

async function autoBlockCF(ip, reason) {
  if (!process.env.CF_AUTO_BLOCK_ENABLED || !process.env.CF_ZONE_ID || !process.env.CF_API_TOKEN) return;
  try {
    await fetch(`https://api.cloudflare.com/client/v4/zones/${process.env.CF_ZONE_ID}/firewall/access_rules/rules`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'block', configuration: { target: 'ip', value: ip }, notes: `Auto: ${reason}` }),
      signal: AbortSignal.timeout(8000),
    });
  } catch (_) {}
}

// ══════════════════════════════════════════════════════════════
//  HELPER: lấy real IP (ưu tiên Cloudflare header)
// ══════════════════════════════════════════════════════════════
function getRealIp(req) {
  return req.headers['cf-connecting-ip']
      || req.headers['x-forwarded-for']?.split(',')[0]?.trim()
      || req.socket.remoteAddress
      || req.ip;
}

// ══════════════════════════════════════════════════════════════
//  NOOP MIDDLEWARE — dùng khi ANTI_DDOS=false, zero overhead
// ══════════════════════════════════════════════════════════════
const noop = (_req, _res, next) => next();

// ══════════════════════════════════════════════════════════════
//  LAYER 3 — IP Blocking  (đặt đầu tiên để fail-fast)
// ══════════════════════════════════════════════════════════════
const ipBlockingMiddleware = !ANTI_DDOS ? noop : (req, res, next) => {
  const ip = getRealIp(req);
  if (SECURITY_CONFIG.ip.whitelist.includes(ip)) return next();
  if (SECURITY_CONFIG.ip.staticBlacklist.includes(ip)) {
    console.log(`🚫 [STATIC-BL] ${ip}`);
    return res.status(403).json({ success: false, message: 'Access denied' });
  }
  if (_store.isBanned(ip)) {
    const info = _store.blacklist.get(ip);
    const remain = Math.ceil(((info?.expiresAt ?? 0) - Date.now()) / 1000);
    return res.status(403).json({ success: false, message: 'IP tạm thời bị chặn.', retryAfter: remain });
  }
  next();
};

// ══════════════════════════════════════════════════════════════
//  LAYER 5 — Slow Request (Slowloris defense)
// ══════════════════════════════════════════════════════════════
const slowRequestMiddleware = !ANTI_DDOS ? noop : (req, res, next) => {
  const ip = getRealIp(req);
  req.setTimeout(SECURITY_CONFIG.slow.requestTimeoutMs, () => {
    console.log(`⌛ [SLOW-REQ] ${ip} ${req.path}`);
    _store.addViolation(ip);
    if (!res.headersSent) res.status(408).json({ success: false, message: 'Request timeout' });
    req.socket?.destroy();
  });
  next();
};

// ══════════════════════════════════════════════════════════════
//  LAYER 4 — Connection Protection
// ══════════════════════════════════════════════════════════════
const connProtectionMiddleware = !ANTI_DDOS ? noop : (req, res, next) => {
  const ip = getRealIp(req);
  const conns = _store.openConn(ip);
  res.on('finish', () => _store.closeConn(ip));
  res.on('close',  () => _store.closeConn(ip));

  if (conns > SECURITY_CONFIG.conn.maxPerIp) {
    console.log(`🔗 [CONN-LIMIT] ${ip} – ${conns} conns`);
    _store.addViolation(ip);
    return res.status(429).json({ success: false, message: 'Quá nhiều kết nối đồng thời' });
  }
  const bodySize = parseInt(req.headers['content-length'] ?? '0');
  if (bodySize > SECURITY_CONFIG.conn.maxBodyBytes) {
    return res.status(413).json({ success: false, message: 'Request body quá lớn' });
  }
  next();
};

// ══════════════════════════════════════════════════════════════
//  LAYER 2 — Bot Detection + Anomaly
// ══════════════════════════════════════════════════════════════
const botDetectionMiddleware = !ANTI_DDOS ? noop : (req, res, next) => {
  const ip = getRealIp(req);
  const ua = (req.headers['user-agent'] ?? '').toLowerCase();

  // Block empty User-Agent
  if (!ua) {
    console.log(`🤖 [BOT:empty-ua] ${ip}`);
    _store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // Block known bad agents
  if (SECURITY_CONFIG.bot.blockedAgents.some(b => ua.includes(b))) {
    console.log(`🤖 [BOT:bad-ua] ${ip} – ${ua.slice(0, 60)}`);
    _store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // Block API calls without Accept header (headless bots)
  if (req.path.startsWith('/api/') && !req.headers['accept']) {
    console.log(`🤖 [BOT:no-accept] ${ip}`);
    _store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // Anomaly detection — sliding window RPM
  const rpm = _store.recordHit(ip);
  if (rpm > SECURITY_CONFIG.bot.anomalyRpmThreshold) {
    console.log(`\x1b[31m🚨 [ANOMALY] ${ip} – ${rpm} rpm\x1b[0m`);
    sendAlert('CRITICAL', `IP ${ip} – ${rpm} req/phút (anomaly)`);
    _store.addViolation(ip);
    return res.status(429).json({ success: false, message: 'Traffic bất thường' });
  }
  if (rpm > SECURITY_CONFIG.bot.anomalyRpmThreshold * 0.7) {
    console.log(`\x1b[33m⚠️  [HIGH-TRAFFIC] ${ip} – ${rpm} rpm\x1b[0m`);
  }

  next();
};

// ══════════════════════════════════════════════════════════════
//  LAYER 1 — Rate Limiters (express-rate-limit)
// ══════════════════════════════════════════════════════════════
const makeRl = (opts, label) => !ANTI_DDOS ? noop : rateLimit({
  ...opts,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRealIp(req),
  skip: (req) => SECURITY_CONFIG.ip.whitelist.includes(getRealIp(req)),
  handler: (req, res) => {
    const ip = getRealIp(req);
    console.log(`\x1b[31m🚦 [RATE-LIMIT:${label}] ${ip} ${req.path}\x1b[0m`);
    _store.addViolation(ip);
    res.status(429).json({
      success: false,
      message: 'Quá nhiều request. Vui lòng thử lại sau.',
      retryAfter: Math.ceil(opts.windowMs / 1000),
    });
  },
});

const globalLimiter  = makeRl(SECURITY_CONFIG.rateLimit.global,  'global');
const apiLimiter     = makeRl(SECURITY_CONFIG.rateLimit.api,     'api');
const authLimiter    = makeRl(SECURITY_CONFIG.rateLimit.auth,    'auth');
const contactLimiter = makeRl(SECURITY_CONFIG.rateLimit.contact, 'contact');

// ══════════════════════════════════════════════════════════════
//  ĐẶT MIDDLEWARES THEO THỨ TỰ: IP → Slow → Conn → Bot → Rate
// ══════════════════════════════════════════════════════════════
app.use(ipBlockingMiddleware);
app.use(slowRequestMiddleware);
app.use(connProtectionMiddleware);
app.use(botDetectionMiddleware);
app.use(globalLimiter);

// ─── Traffic Monitor ──────────────────────────────────────────
const trafficLog = {
  totalRequests: 0,
  requestsPerMinute: {},
  recentRequests: [],
  startTime: new Date(),
};

app.use((req, res, next) => {
  const ip = getRealIp(req);
  const now = new Date();
  const minute = now.toISOString().slice(0, 16);
  trafficLog.totalRequests++;
  trafficLog.requestsPerMinute[minute] = (trafficLog.requestsPerMinute[minute] || 0) + 1;
  trafficLog.recentRequests.push({ ip, time: now, method: req.method, path: req.path, ua: req.headers['user-agent']?.slice(0, 80) });
  if (trafficLog.recentRequests.length > 200) trafficLog.recentRequests.shift();
  next();
});

// ─── Monitor Dashboard ────────────────────────────────────────
app.get('/monitor', (req, res) => {
  const key = req.query.key;
  if (key !== (process.env.MONITOR_KEY || 'Phuc2026secret')) {
    return res.status(403).send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
      *{margin:0;padding:0;box-sizing:border-box}body{background:#050d1a;display:flex;align-items:center;justify-content:center;height:100vh;font-family:'Segoe UI',sans-serif}
      .box{background:#0f2044;border:1px solid #1e3a5f;border-radius:20px;padding:48px 40px;text-align:center;width:360px;box-shadow:0 24px 60px rgba(0,0,0,.5)}
      h2{color:#38bdf8;margin-bottom:8px;font-size:1.3rem}.sub{color:#475569;font-size:.83rem;margin-bottom:24px}
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

  const now = new Date();
  const storeStats = _store.stats();
  const ipList = Object.entries(
    trafficLog.recentRequests.reduce((acc, r) => { acc[r.ip] = (acc[r.ip] || 0) + 1; return acc; }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([ip, count]) => ({ ip, count }));
  const recentMinutes = Object.entries(trafficLog.requestsPerMinute).sort((a, b) => a[0].localeCompare(b[0])).slice(-10);
  const uptime = Math.floor((now - trafficLog.startTime) / 1000);
  const currentRPM = recentMinutes.slice(-1)[0]?.[1] || 0;
  const isDDoS = storeStats.bannedIPs > 0 || currentRPM > 200;

  res.send(`<!DOCTYPE html><html lang="vi"><head>
    <meta charset="UTF-8"><meta http-equiv="refresh" content="3">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>SpiritAds Monitor</title>
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{background:#050d1a;color:#e2e8f0;font-family:'Segoe UI',monospace;padding:20px;min-height:100vh}
      .hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1e3a5f}
      .hdr h1{color:#38bdf8;font-size:1.25rem}
      .live{display:flex;align-items:center;gap:6px;font-size:.76rem;color:#4ade80}
      .dot{width:8px;height:8px;border-radius:50%;background:#4ade80;animation:pulse 1s infinite}
      @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
      .kpi{background:linear-gradient(145deg,#0f2044,#162d52);border:1px solid #1e3a5f;border-radius:14px;padding:18px;text-align:center}
      .kpi-i{font-size:1.3rem;margin-bottom:7px}
      .kpi-v{font-size:1.8rem;font-weight:800;color:#38bdf8;line-height:1}
      .kpi-l{font-size:.7rem;color:#64748b;margin-top:5px}
      .kpi.danger .kpi-v{color:#f87171}.kpi.warn .kpi-v{color:#fbbf24}.kpi.safe .kpi-v{color:#4ade80}
      .card{background:#0a1f3d;border:1px solid #1e3a5f;border-radius:14px;padding:18px;margin-bottom:14px}
      .card-t{color:#38bdf8;font-size:.88rem;font-weight:700;margin-bottom:12px}
      table{width:100%;border-collapse:collapse;font-size:.8rem}
      th{color:#475569;font-size:.7rem;padding:7px 8px;text-align:left;border-bottom:1px solid #1e3a5f;text-transform:uppercase}
      td{padding:8px;border-bottom:1px solid #0a1628;color:#cbd5e1}
      tr:hover td{background:rgba(37,99,235,.07)}
      .badge{padding:3px 9px;border-radius:99px;font-size:.7rem;font-weight:700}
      .bd{background:#7f1d1d;color:#fca5a5}.bw{background:#78350f;color:#fcd34d}.bs{background:#064e3b;color:#6ee7b7}.bi{background:#1e3a5f;color:#93c5fd}
      .bar-w{height:7px;background:#1e3a5f;border-radius:3px;overflow:hidden;margin-top:3px}
      .bar-f{height:100%;background:linear-gradient(90deg,#2563eb,#38bdf8);border-radius:3px}
      .alert{background:linear-gradient(135deg,#7f1d1d,#991b1b);border:1px solid #f87171;border-radius:12px;padding:14px 18px;margin-bottom:18px;animation:ap 1s infinite}
      @keyframes ap{0%,100%{opacity:1}50%{opacity:.8}}
      .two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
      .ref{color:#334155;font-size:.7rem;text-align:right;margin-bottom:14px}
      .ddos-status{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:99px;font-size:.75rem;font-weight:700}
      .ddos-on{background:#064e3b;color:#6ee7b7}.ddos-off{background:#78350f;color:#fcd34d}
      @media(max-width:700px){.two{grid-template-columns:1fr}}
    </style></head><body>
    <div class="hdr">
      <h1>📡 SpiritAds Traffic Monitor</h1>
      <div style="display:flex;align-items:center;gap:12px">
        <span class="ddos-status ${ANTI_DDOS ? 'ddos-on' : 'ddos-off'}">
          ${ANTI_DDOS ? '🛡️ Anti-DDoS: BẬT' : '⚠️ Anti-DDoS: TẮT'}
        </span>
        <div class="live"><div class="dot"></div>LIVE – ${now.toLocaleString('vi-VN')}</div>
      </div>
    </div>
    <div class="ref">🔄 Tự động refresh mỗi 3 giây</div>
    ${isDDoS && ANTI_DDOS ? `<div class="alert">🚨 <strong>CẢNH BÁO!</strong> ${storeStats.bannedIPs} IP đã bị ban · RPM: ${currentRPM}</div>` : ''}
    <div class="grid">
      <div class="kpi ${currentRPM > 100 ? 'danger' : 'safe'}">
        <div class="kpi-i">⚡</div><div class="kpi-v">${currentRPM}</div><div class="kpi-l">Requests/phút</div>
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
        <div class="kpi-i">🔗</div><div class="kpi-v">${storeStats.activeConns}</div><div class="kpi-l">Kết nối đang mở</div>
      </div>
      <div class="kpi">
        <div class="kpi-i">⏱️</div><div class="kpi-v">${Math.floor(uptime/3600)}h${Math.floor((uptime%3600)/60)}m</div><div class="kpi-l">Uptime</div>
      </div>
    </div>

    <div class="card">
      <div class="card-t">📈 Requests theo phút</div>
      <table><tr><th>Thời gian</th><th>Requests</th><th>Biểu đồ</th></tr>
      ${recentMinutes.map(([t, c]) => `<tr>
        <td>${t.slice(11)}</td>
        <td><span class="badge ${c > 100 ? 'bd' : c > 50 ? 'bw' : 'bs'}">${c}</span></td>
        <td style="width:55%"><div class="bar-w"><div class="bar-f" style="width:${Math.min(c/2,100)}%"></div></div></td>
      </tr>`).join('')}
      </table>
    </div>

    <div class="two">
      <div class="card">
        <div class="card-t">🌍 Top IPs</div>
        <table><tr><th>IP</th><th>Req</th><th>Mức độ</th></tr>
        ${ipList.map(({ ip, count }) => `<tr>
          <td style="font-family:monospace;font-size:.73rem">${ip}</td>
          <td>${count}</td>
          <td><span class="badge ${_store.isBanned(ip) ? 'bd' : count > 50 ? 'bw' : 'bs'}">
            ${_store.isBanned(ip) ? '🚫 Banned' : count > 50 ? '⚠️ High' : '✅ OK'}
          </span></td>
        </tr>`).join('')}
        </table>
      </div>
      <div class="card">
        <div class="card-t">🕐 Requests gần nhất</div>
        <table><tr><th>Giờ</th><th>IP</th><th>Path</th></tr>
        ${trafficLog.recentRequests.slice(-15).reverse().map(r => `<tr>
          <td>${new Date(r.time).toLocaleTimeString('vi-VN')}</td>
          <td style="font-family:monospace;font-size:.72rem">${r.ip}</td>
          <td style="color:#64748b">${r.method} ${r.path.slice(0,28)}</td>
        </tr>`).join('')}
        </table>
      </div>
    </div>

    ${storeStats.topBanned.length ? `
    <div class="card">
      <div class="card-t">🚫 IPs đang bị ban</div>
      <table><tr><th>IP</th><th>Lý do</th><th>Vi phạm</th><th>Hết hạn</th></tr>
      ${storeStats.topBanned.map(b => `<tr>
        <td style="font-family:monospace">${b.ip}</td>
        <td style="color:#94a3b8">${b.reason}</td>
        <td><span class="badge bd">${b.violations}×</span></td>
        <td style="font-size:.75rem;color:#64748b">${new Date(b.expiresAt).toLocaleTimeString('vi-VN')}</td>
      </tr>`).join('')}
      </table>
    </div>` : ''}

  </body></html>`);
});

// ─── Security headers ─────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CLIENT_URL || '*', credentials: true }));

// ─── Per-route rate limiters ──────────────────────────────────
app.use('/api/auth/login',    authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/contact',       contactLimiter);
app.use('/api/',              apiLimiter);

// ─── Body parsing ─────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
if (process.env.NODE_ENV === 'development') app.use(morgan('dev'));

// ─── Static files ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// ─── Routes ───────────────────────────────────────────────────
app.use('/api/auth',          authRoutes);
app.use('/api/campaigns',     campaignRoutes);
app.use('/api/admin',         adminRoutes);
app.use('/api',               publicRoutes);

// ─── Admin Security API ───────────────────────────────────────
// Thêm vào adminRoutes hoặc giữ ở đây (cần protect + authorize('admin'))
// POST /api/admin/security/ban   { ip, reason, durationMin }
// DEL  /api/admin/security/ban/:ip
// GET  /api/admin/security/status

// ─── Health check ─────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({
  success:   true,
  message:   'SpiritAds API đang hoạt động',
  timestamp: new Date().toISOString(),
  env:       process.env.NODE_ENV,
  uptime:    Math.floor(process.uptime()) + 's',
  protected: ANTI_DDOS,
}));

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.use(errorHandler);

// ─── Start ────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 SpiritAds Server: http://localhost:${PORT}`);
  console.log(`📦 Môi trường: ${process.env.NODE_ENV}`);
  console.log(`🗄️  MongoDB: ${process.env.MONGO_URI}`);
  console.log(`🛡️  Anti-DDoS: ${ANTI_DDOS ? '✅ BẬT' : '❌ TẮT'}\n`);
});

module.exports = app;