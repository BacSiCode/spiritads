// ============================================================
//  server/middleware/antiddos/index.js
//  ─── ENTRY POINT ───────────────────────────────────────────
//
//  Cách dùng trong server/index.js:
//
//    const antiDDoS = require('./middleware/antiddos');
//    antiDDoS.applyTo(app);                        // global middlewares
//    app.use('/api/auth/login',  antiDDoS.authLimiter);
//    app.use('/api/auth/register', antiDDoS.authLimiter);
//    app.use('/api/contact',     antiDDoS.contactLimiter);
//    app.use('/api/',            antiDDoS.apiLimiter);
//
// ============================================================

const cfg    = require('../../config/security.config');
const store  = require('./ipStore');
const logger = require('./securityLogger');
const {
  buildRateLimiters,
  botDetectionMiddleware,
  ipBlockingMiddleware,
  connectionProtectionMiddleware,
  slowRequestMiddleware,
} = require('./layers');

// ── Tạo rate limiters một lần duy nhất (tránh re-create mỗi request) ──
const limiters = buildRateLimiters();

// ─────────────────────────────────────────────────────────────
//  Noop middleware — dùng khi Anti-DDoS bị TẮT
//  Không có bất kỳ logic nào → zero overhead
// ─────────────────────────────────────────────────────────────
const noop = (_req, _res, next) => next();

// ─────────────────────────────────────────────────────────────
//  applyTo(app) — gắn global middlewares vào Express app
//  Thứ tự quan trọng: IP check → slow → conn → bot → global rate
// ─────────────────────────────────────────────────────────────
function applyTo(app) {
  if (!cfg.enabled) {
    // Anti-DDoS BỊ TẮT — log một lần duy nhất và return
    console.log('\x1b[33m⚠️  [SECURITY] ANTI_DDOS_PROTECTION=false — Tất cả bảo vệ đã bị tắt.\x1b[0m');
    return;
  }

  console.log('\x1b[32m🛡️  [SECURITY] Anti-DDoS kích hoạt:\x1b[0m', {
    rateLimit:          cfg.rateLimit.connectionProtection,
    botDetection:       cfg.botDetection.enabled,
    ipBlocking:         cfg.ipBlocking.enabled,
    connectionProtect:  cfg.connectionProtection.enabled,
    slowRequest:        cfg.slowRequest.enabled,
    cloudflareAutoBlock: cfg.cloudflare.enabled,
  });

  // Trust proxy (cần cho express-rate-limit + real IP)
  app.set('trust proxy', cfg.cloudflare.trustProxy ? 1 : false);

  // Layer 3 — IP Blocking (phải chạy đầu tiên để fail-fast)
  if (cfg.ipBlocking.enabled)          app.use(ipBlockingMiddleware);

  // Layer 5 — Slow Request (set timeout sớm)
  if (cfg.slowRequest.enabled)         app.use(slowRequestMiddleware);

  // Layer 4 — Connection Protection
  if (cfg.connectionProtection.enabled) app.use(connectionProtectionMiddleware);

  // Layer 2 — Bot Detection + Anomaly
  if (cfg.botDetection.enabled)        app.use(botDetectionMiddleware);

  // Layer 1 — Global rate limit (áp dụng cho toàn bộ routes)
  if (cfg.rateLimit.enabled)           app.use(limiters.global);
}

// ─────────────────────────────────────────────────────────────
//  Per-route limiters — export để dùng trên route cụ thể
//  Nếu Anti-DDoS tắt, trả về noop → không ảnh hưởng route
// ─────────────────────────────────────────────────────────────
const apiLimiter     = cfg.enabled && cfg.rateLimit.enabled ? limiters.api     : noop;
const authLimiter    = cfg.enabled && cfg.rateLimit.enabled ? limiters.auth    : noop;
const contactLimiter = cfg.enabled && cfg.rateLimit.enabled ? limiters.contact : noop;

// ─────────────────────────────────────────────────────────────
//  Admin API — thao tác thủ công qua /api/admin/security
// ─────────────────────────────────────────────────────────────
const adminHandlers = {
  // GET /api/admin/security/status
  getStatus(req, res) {
    res.json({
      success: true,
      data: {
        enabled: cfg.enabled,
        layers: {
          rateLimit:          cfg.rateLimit.enabled,
          botDetection:       cfg.botDetection.enabled,
          ipBlocking:         cfg.ipBlocking.enabled,
          connectionProtect:  cfg.connectionProtection.enabled,
          slowRequest:        cfg.slowRequest.enabled,
        },
        store: store.stats(),
      },
    });
  },

  // POST /api/admin/security/ban  { ip, reason?, durationMin? }
  banIp(req, res) {
    const { ip, reason = 'manual', durationMin = 60 } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: 'ip required' });
    store.ban(ip, reason, durationMin * 60 * 1000);
    logger.info('manual_ban', { ip, reason, durationMin, by: req.user?.email });
    res.json({ success: true, message: `Đã ban IP ${ip} trong ${durationMin} phút` });
  },

  // DELETE /api/admin/security/ban/:ip
  unbanIp(req, res) {
    const { ip } = req.params;
    store.unban(ip);
    logger.info('manual_unban', { ip, by: req.user?.email });
    res.json({ success: true, message: `Đã unban IP ${ip}` });
  },

  // GET /api/admin/security/blacklist
  getBlacklist(req, res) {
    res.json({ success: true, data: store.stats().topOffenders });
  },
};

module.exports = {
  applyTo,
  apiLimiter,
  authLimiter,
  contactLimiter,
  adminHandlers,
  store,   // expose để monitor dashboard dùng
  config:  cfg,
  isEnabled: () => cfg.enabled,
};
