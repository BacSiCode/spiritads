// ============================================================
//  server/middleware/antiddos/index.js — Container DDoS v3
// ============================================================

const store  = require('./ipStore');
const logger = require('./securityLogger');
const {
  buildRateLimiters,
  honeypotMiddleware,
  proxyDetectionMiddleware,
  fragmentDetectionMiddleware,
  behaviorMiddleware,
  subnetBlockingMiddleware,
  cloudIpDetectionMiddleware,
  ipBlockingMiddleware,
  connectionProtectionMiddleware,
  slowRequestMiddleware,
  botDetectionMiddleware,
} = require('./layers');

const behaviorEngine = require('./behaviorEngine');
const proxyDetector  = require('./proxyDetector');

const noop      = (_req, _res, next) => next();
let   _cfg      = null;
let   _limiters = null;

function getCfg()      { if (!_cfg)      _cfg      = require('../../config/baomat._config'); return _cfg; }
function getLimiters() { if (!_limiters) _limiters = buildRateLimiters(); return _limiters; }

// ── applyTo(app) ──────────────────────────────────────────────
function applyTo(app) {
  const cfg = getCfg();

  if (!cfg.enabled) {
    console.log('\x1b[33m⚠️  Anti-DDoS: TẮT\x1b[0m');
    return;
  }

  // QUAN TRỌNG: trust proxy = 1 cho Render
  app.set('trust proxy', 1);

  console.log('\x1b[32m🛡️  Anti-DDoS Behavioral Defense kích hoạt:\x1b[0m');
  console.log(`   ├ Honeypot:         ✅`);
  console.log(`   ├ IP Blocking:      ${cfg.ipBlocking?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Subnet blocking:  ✅`);
  console.log(`   ├ Cloud IP block:   ${process.env.BLOCK_CLOUD_IPS === 'true' ? '✅ BẬT' : '⏸️  TẮT'}`);
  console.log(`   ├ Behavior score:   ✅ (chống low-and-slow)`);
  console.log(`   ├ Slow Request:     ${cfg.slowRequest?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Conn Protection:  ${cfg.connectionProtection?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Bot Detection:    ${cfg.botDetection?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Rate Limit:       ${cfg.rateLimit?.enabled ? '✅' : '❌'}`);
  console.log(`   ├ Telegram:         ${process.env.TELEGRAM_BOT_TOKEN ? '✅' : '❌'}`);
  console.log(`   └ Score block at:   ${process.env.BEHAVIOR_SCORE_BLOCK || '70'}/100`);

  app.use(honeypotMiddleware);              // 0. Bẫy scanner
  app.use(ipBlockingMiddleware);            // 1. IP ban list
  app.use(subnetBlockingMiddleware);        // 2. Subnet /24
  app.use(cloudIpDetectionMiddleware);      // 3. Cloud IP
  app.use(proxyDetectionMiddleware);        // 4. Proxy/VPN/Tor detect
  app.use(fragmentDetectionMiddleware);     // 5. Packet fragmentation
  app.use(behaviorMiddleware);              // 6. Behavioral scoring
  app.use(slowRequestMiddleware);           // 7. Slowloris
  app.use(connectionProtectionMiddleware);  // 8. Conn limit
  app.use(botDetectionMiddleware);          // 9. Bot detect
  app.use(getLimiters().global);            // 10. Rate limit
}

// ── Per-route limiters ────────────────────────────────────────
Object.defineProperties(module.exports, {
  apiLimiter:     { get() { const c=getCfg(); return c.enabled&&c.rateLimit?.enabled ? getLimiters().api     : noop; } },
  authLimiter:    { get() { const c=getCfg(); return c.enabled&&c.rateLimit?.enabled ? getLimiters().auth    : noop; } },
  contactLimiter: { get() { const c=getCfg(); return c.enabled&&c.rateLimit?.enabled ? getLimiters().contact : noop; } },
});

// ── Admin handlers ────────────────────────────────────────────
const adminHandlers = {
  getStatus(req, res) {
    const cfg = getCfg();
    const s   = store.stats();
    res.json({ success: true, data: {
      enabled: cfg.enabled,
      blockCloudIps: process.env.BLOCK_CLOUD_IPS === 'true',
      telegram: !!process.env.TELEGRAM_BOT_TOKEN,
      layers: {
        honeypot: true, subnetBlocking: true,
        cloudIpDetection: process.env.BLOCK_CLOUD_IPS === 'true',
        ipBlocking: cfg.ipBlocking?.enabled,
        botDetection: cfg.botDetection?.enabled,
        rateLimit: cfg.rateLimit?.enabled,
      },
      config: {
        banThreshold:    cfg.ipBlocking?.banThreshold,
        banDurationMin:  Math.ceil((cfg.ipBlocking?.banDurationMs ?? 0) / 60000),
        hardBanAfter:    cfg.ipBlocking?.hardBanAfter,
        anomalyRpm:      cfg.botDetection?.anomalyRpmThreshold,
        globalRpmMax:    parseInt(process.env.GLOBAL_RPM_MAX || '1000'),
        maxIpsPerSubnet: parseInt(process.env.MAX_IPS_PER_SUBNET || '10'),
        maxSameUa:       parseInt(process.env.MAX_SAME_UA_PER_SUBNET || '5'),
      },
      store: s,
    }});
  },

  banIp(req, res) {
    const { ip, reason = 'manual', durationMin = 120 } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: 'ip required' });
    store.ban(ip, reason, durationMin * 60 * 1000);
    logger.info('manual_ban', { ip, reason, durationMin, by: req.user?.email });
    res.json({ success: true, message: `Đã ban IP ${ip} trong ${durationMin} phút` });
  },

  unbanIp(req, res) {
    store.unban(req.params.ip);
    logger.info('manual_unban', { ip: req.params.ip, by: req.user?.email });
    res.json({ success: true, message: `Đã unban IP ${req.params.ip}` });
  },

  banSubnet(req, res) {
    const { subnet, reason = 'manual', durationMin = 60 } = req.body;
    if (!subnet) return res.status(400).json({ success: false, message: 'subnet required' });
    store.banSubnet(subnet, reason, durationMin * 60 * 1000);
    logger.info('manual_subnet_ban', { subnet, reason, by: req.user?.email });
    res.json({ success: true, message: `Đã ban subnet ${subnet}.x trong ${durationMin} phút` });
  },

  getBlacklist(req, res) {
    res.json({ success: true, data: store.stats().topOffenders });
  },

  getAttackLog(req, res) {
    res.json({ success: true, data: store.stats().recentAttacks });
  },

  // Bật/tắt block cloud IPs ngay lập tức (không cần restart)
  toggleCloudBlock(req, res) {
    const { enabled } = req.body;
    process.env.BLOCK_CLOUD_IPS = enabled ? 'true' : 'false';
    logger.info('toggle_cloud_block', { enabled, by: req.user?.email });
    res.json({ success: true, message: `Cloud IP blocking: ${enabled ? 'BẬT' : 'TẮT'}` });
  },
};

Object.assign(module.exports, {
  applyTo,
  adminHandlers,
  store,
  get config() { return getCfg(); },
  isEnabled: () => getCfg().enabled,
});
