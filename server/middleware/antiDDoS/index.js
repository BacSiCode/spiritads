// ============================================================
//  server/middleware/antiddos/index.js — Enterprise Grade
//
//  Dùng trong server/index.js:
//    const antiDDoS = require('./middleware/antiddos');
//    antiDDoS.applyTo(app);
//    app.use('/api/auth/login',    antiDDoS.authLimiter);
//    app.use('/api/auth/register', antiDDoS.authLimiter);
//    app.use('/api/contact',       antiDDoS.contactLimiter);
//    app.use('/api/',              antiDDoS.apiLimiter);
// ============================================================

const store  = require('./ipStore');
const logger = require('./securityLogger');
const {
  buildRateLimiters,
  honeypotMiddleware,
  ipBlockingMiddleware,
  connectionProtectionMiddleware,
  slowRequestMiddleware,
  botDetectionMiddleware,
  trafficSamplerMiddleware,
} = require('./layers');

const noop    = (_req, _res, next) => next();
let   _cfg    = null;
let   _limiters = null;

function getCfg() {
  if (!_cfg) _cfg = require('../../config/baomat._config');
  return _cfg;
}

function getLimiters() {
  if (!_limiters) _limiters = buildRateLimiters();
  return _limiters;
}

// ── applyTo(app) ──────────────────────────────────────────────
function applyTo(app) {
  const cfg = getCfg();

  if (!cfg.enabled) {
    console.log('\x1b[33m⚠️  [SECURITY] Anti-DDoS TẮT — zero protection\x1b[0m');
    return;
  }

  console.log('\x1b[32m🛡️  [SECURITY] Anti-DDoS Enterprise kích hoạt\x1b[0m');
  console.log(`   ├ Honeypot:          ✅`);
  console.log(`   ├ IP Blocking:       ${cfg.ipBlocking?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Slow Request:      ${cfg.slowRequest?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Conn Protection:   ${cfg.connectionProtection?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Bot Detection:     ${cfg.botDetection?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Rate Limit:        ${cfg.rateLimit?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Telegram Alert:    ${process.env.TELEGRAM_BOT_TOKEN ? '✅' : '❌ (chưa cấu hình)'}`);
  console.log(`   └ CF Auto-Block:     ${cfg.cloudflare?.enabled ? '✅' : '❌ (chưa cấu hình)'}`);

  app.set('trust proxy', cfg.cloudflare?.trustProxy ? 1 : false);

  // Thứ tự quan trọng!
  app.use(honeypotMiddleware);                                        // Honeypot — bẫy scanner
  if (cfg.ipBlocking?.enabled)           app.use(ipBlockingMiddleware);
  if (cfg.slowRequest?.enabled)          app.use(slowRequestMiddleware);
  if (cfg.connectionProtection?.enabled) app.use(connectionProtectionMiddleware);
  if (cfg.botDetection?.enabled)         app.use(botDetectionMiddleware);
  if (cfg.rateLimit?.enabled)            app.use(getLimiters().global);
  
  // Gửi mẫu traffic sạch về NIDS để Dashboard có màu xanh
  app.use(trafficSamplerMiddleware);
}

// ── Per-route limiters ────────────────────────────────────────
const apiLimiter     = () => { const c = getCfg(); return c.enabled && c.rateLimit?.enabled ? getLimiters().api     : noop; };
const authLimiter    = () => { const c = getCfg(); return c.enabled && c.rateLimit?.enabled ? getLimiters().auth    : noop; };
const contactLimiter = () => { const c = getCfg(); return c.enabled && c.rateLimit?.enabled ? getLimiters().contact : noop; };

// ── Admin handlers ────────────────────────────────────────────
const adminHandlers = {
  getStatus(req, res) {
    const cfg = getCfg();
    res.json({
      success: true,
      data: {
        enabled: cfg.enabled,
        telegram: !!process.env.TELEGRAM_BOT_TOKEN,
        cloudflare: cfg.cloudflare?.enabled ?? false,
        layers: {
          honeypot:          true,
          ipBlocking:        cfg.ipBlocking?.enabled,
          slowRequest:       cfg.slowRequest?.enabled,
          connProtection:    cfg.connectionProtection?.enabled,
          botDetection:      cfg.botDetection?.enabled,
          rateLimit:         cfg.rateLimit?.enabled,
        },
        config: {
          banThreshold:    cfg.ipBlocking?.banThreshold,
          banDurationMin:  Math.ceil((cfg.ipBlocking?.banDurationMs ?? 0) / 60000),
          hardBanAfter:    cfg.ipBlocking?.hardBanAfter,
          anomalyRpm:      cfg.botDetection?.anomalyRpmThreshold,
          maxConnPerIp:    cfg.connectionProtection?.maxConnPerIp,
        },
        store: store.stats(),
      },
    });
  },

  banIp(req, res) {
    const { ip, reason = 'manual_admin', durationMin = 60 } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: 'ip required' });
    store.ban(ip, reason, durationMin * 60 * 1000);
    logger.info('manual_ban', { ip, reason, durationMin, by: req.user?.email });
    res.json({ success: true, message: `Đã ban IP ${ip} trong ${durationMin} phút` });
  },

  unbanIp(req, res) {
    const { ip } = req.params;
    store.unban(ip);
    logger.info('manual_unban', { ip, by: req.user?.email });
    res.json({ success: true, message: `Đã unban IP ${ip}` });
  },

  getBlacklist(req, res) {
    res.json({ success: true, data: store.stats().topOffenders });
  },

  getAttackLog(req, res) {
    res.json({ success: true, data: store.stats().recentAttacks });
  },
};

module.exports = {
  applyTo,
  get apiLimiter()     { return apiLimiter(); },
  get authLimiter()    { return authLimiter(); },
  get contactLimiter() { return contactLimiter(); },
  adminHandlers,
  store,
  get config() { return getCfg(); },
  isEnabled: () => getCfg().enabled,
};
