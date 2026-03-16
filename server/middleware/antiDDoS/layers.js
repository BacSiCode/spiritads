// ============================================================
//  server/middleware/antiddos/layers.js — Enterprise v2
//  Fix: Distributed DDoS, IP rotation, trust proxy, global throttle
// ============================================================

const rateLimit = require('express-rate-limit');
const store     = require('./ipStore');
const logger    = require('./securityLogger');

function getCfg() { return require('../../config/security.config'); }

// ══════════════════════════════════════════════════════════════
//  LẤY REAL IP — Fix hoàn toàn lỗ hổng trust proxy
// ══════════════════════════════════════════════════════════════
function getRealIp(req) {
  // Ưu tiên 1: Cloudflare (khi có domain + Cloudflare)
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp && process.env.TRUST_CF_PROXY === 'true') return cfIp.trim();

  // Ưu tiên 2: Render tự thêm X-Forwarded-For với IP thật
  // Render là trusted proxy → lấy IP đầu tiên trong chuỗi
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = forwarded.split(',')[0].trim();
    // Bỏ qua IP nội bộ/private
    if (!_isPrivateIp(first)) return first;
  }

  // Ưu tiên 3: Socket (khi chạy local)
  const socketIp = req.socket?.remoteAddress || req.ip || '0.0.0.0';
  return socketIp.replace('::ffff:', ''); // normalize IPv4-mapped IPv6
}

// Kiểm tra IP private/internal
function _isPrivateIp(ip) {
  return (
    ip === '127.0.0.1'     ||
    ip === '::1'           ||
    ip.startsWith('10.')   ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('fc') ||
    ip.startsWith('fd')
  );
}

// ══════════════════════════════════════════════════════════════
//  HONEYPOT — bẫy scanner, ban ngay 24h
// ══════════════════════════════════════════════════════════════
const HONEYPOT_PATHS = [
  '/.env','/.git','/wp-admin','/wp-login.php',
  '/admin.php','/phpmyadmin','/xmlrpc.php',
  '/config.php','/.htaccess','/shell.php',
  '/backup.sql','/db.sql','/database.sql',
  '/manager/html','/actuator','/console',
  '/.aws/credentials','/server-status',
  '/api/v1/admin','/api/v2/admin',
];

function honeypotMiddleware(req, res, next) {
  const cfg  = getCfg();
  if (!cfg.enabled) return next();

  const p = req.path.toLowerCase();
  if (HONEYPOT_PATHS.some(h => p.startsWith(h))) {
    const ip = getRealIp(req);
    logger.critical('honeypot', { ip, path: req.path });
    store.logAttack(ip, 'HONEYPOT', req.path);
    store.ban(ip, `honeypot:${req.path}`, 24 * 60 * 60 * 1000);
    return res.status(404).json({ success: false, message: 'Not found' });
  }
  next();
}

// ══════════════════════════════════════════════════════════════
//  LAYER 3 — IP Blocking
// ══════════════════════════════════════════════════════════════
function ipBlockingMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.enabled) return next();

  const ip = getRealIp(req);

  if (cfg.ipBlocking.whitelist?.includes(ip)) return next();

  if (cfg.ipBlocking.staticBlacklist?.includes(ip)) {
    logger.block('static_blacklist', { ip });
    store.totalBlocked++;
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  if (store.isBanned(ip)) {
    const info     = store.getBanInfo(ip);
    const remain   = Math.ceil(((info?.expiresAt ?? 0) - Date.now()) / 1000);
    const banCount = info?.banCount ?? 1;
    logger.block('banned_ip', { ip, banCount, remain });
    store.totalBlocked++;
    return res.status(403).json({
      success:    false,
      message:    banCount >= 3 ? 'IP bị chặn vĩnh viễn.' : 'IP tạm thời bị chặn.',
      retryAfter: remain,
    });
  }
  next();
}

// ══════════════════════════════════════════════════════════════
//  LAYER 5 — Slow Request (Slowloris defense)
// ══════════════════════════════════════════════════════════════
function slowRequestMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.slowRequest?.enabled) return next();

  const ip = getRealIp(req);
  const ms = cfg.slowRequest.requestTimeoutMs ?? 20000;

  req.setTimeout(ms, () => {
    logger.warn('slow_request', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'slow_request');
    if (!res.headersSent) res.status(408).json({ success: false, message: 'Request timeout' });
    req.socket?.destroy();
  });

  req.socket?.setTimeout(ms + 5000);
  req.socket?.once('timeout', () => req.socket.destroy());
  next();
}

// ══════════════════════════════════════════════════════════════
//  LAYER 4 — Connection Protection
// ══════════════════════════════════════════════════════════════
function connectionProtectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.connectionProtection?.enabled) return next();

  const ip    = getRealIp(req);
  const conns = store.openConn(ip);
  res.on('finish', () => store.closeConn(ip));
  res.on('close',  () => store.closeConn(ip));

  const max = cfg.connectionProtection.maxConnPerIp ?? 30;
  if (conns > max) {
    store.closeConn(ip);
    logger.block('too_many_conns', { ip, conns, max });
    store.addViolation(ip);
    _checkAutoBan(ip, `too_many_conns:${conns}`);
    return res.status(429).json({ success: false, message: 'Quá nhiều kết nối' });
  }

  const bodySize = parseInt(req.headers['content-length'] ?? '0');
  if (bodySize > (cfg.connectionProtection.maxBodySizeBytes ?? 10485760)) {
    store.closeConn(ip);
    return res.status(413).json({ success: false, message: 'Request quá lớn' });
  }
  next();
}

// ══════════════════════════════════════════════════════════════
//  LAYER 2 — Bot Detection + Anomaly
//  Nâng cấp: chống distributed attack (nhiều IP cùng tấn công)
// ══════════════════════════════════════════════════════════════

// Global counter — đếm tổng request toàn server trong 1 phút
// Dùng để phát hiện distributed DDoS (nhiều IP khác nhau)
const _globalHits = { count: 0, resetAt: Date.now() + 60000 };

function _recordGlobalHit() {
  if (Date.now() > _globalHits.resetAt) {
    _globalHits.count  = 0;
    _globalHits.resetAt = Date.now() + 60000;
  }
  _globalHits.count++;
  return _globalHits.count;
}

function botDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.botDetection?.enabled) return next();

  const ip = getRealIp(req);
  const ua = (req.headers['user-agent'] ?? '').toLowerCase();

  // 2a. Empty User-Agent
  if (!ua) {
    logger.block('empty_ua', { ip });
    store.addViolation(ip);
    _checkAutoBan(ip, 'empty_user_agent');
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2b. Known bad agents
  const badAgents = cfg.botDetection.blockedAgents ?? [];
  if (badAgents.some(b => ua.includes(b))) {
    logger.block('bad_ua', { ip, ua: ua.slice(0, 60) });
    store.logAttack(ip, 'BAD_AGENT', ua.slice(0, 60));
    store.addViolation(ip);
    _checkAutoBan(ip, `bad_agent`);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2c. Missing Accept header
  if (cfg.botDetection.blockMissingAccept && req.path.startsWith('/api/') && !req.headers['accept']) {
    logger.block('no_accept', { ip });
    store.addViolation(ip);
    _checkAutoBan(ip, 'no_accept_header');
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2d. Header fingerprint — quá ít header = bot
  const headerCount = Object.keys(req.headers).length;
  if (req.path.startsWith('/api/') && headerCount < 3) {
    logger.block('low_header_count', { ip, headerCount });
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2e. Per-IP anomaly (sliding window)
  const rpm       = store.recordHit(ip, cfg.botDetection.anomalyWindowMs ?? 60000);
  const threshold = cfg.botDetection.anomalyRpmThreshold ?? 200;

  if (rpm > threshold) {
    logger.critical('ip_anomaly', { ip, rpm, threshold });
    store.logAttack(ip, 'IP_ANOMALY', `${rpm} rpm`);
    store.addViolation(ip);
    _checkAutoBan(ip, `ip_anomaly:${rpm}rpm`);
    return res.status(429).json({ success: false, message: 'Traffic bất thường' });
  }

  // 2f. *** DISTRIBUTED DDOS DETECTION ***
  // Đếm tổng request toàn server — nếu quá cao dù IP phân tán
  const globalRpm = _recordGlobalHit();
  const globalMax = parseInt(process.env.GLOBAL_RPM_MAX || '1000');

  if (globalRpm > globalMax) {
    // Chỉ log 1 lần mỗi 30s để tránh spam
    if (!_globalHits._alerted || Date.now() - _globalHits._alertedAt > 30000) {
      logger.critical('distributed_ddos', { globalRpm, uniqueIps: store.hitMap.size });
      store.logAttack('GLOBAL', 'DISTRIBUTED_DDOS', `${globalRpm} rpm từ ${store.hitMap.size} IPs`);
      _globalHits._alerted   = true;
      _globalHits._alertedAt = Date.now();
    }
    return res.status(503).json({ success: false, message: 'Service tạm thời không khả dụng' });
  }

  // 2g. Warn khi traffic cao
  if (rpm > threshold * 0.6) logger.warn('high_traffic_ip',     { ip, rpm });
  if (globalRpm > globalMax * 0.7) logger.warn('high_traffic_global', { globalRpm });

  next();
}

// ══════════════════════════════════════════════════════════════
//  LAYER 1 — Rate Limiters
// ══════════════════════════════════════════════════════════════
function buildRateLimiters() {
  const makeRl = (options, label) => rateLimit({
    ...options,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator:    (req) => getRealIp(req),
    skip: (req) => {
      const cfg = getCfg();
      return cfg.ipBlocking?.whitelist?.includes(getRealIp(req)) ?? false;
    },
    handler: (req, res) => {
      const ip = getRealIp(req);
      logger.block('rate_limit', { ip, path: req.path, limiter: label });
      store.addViolation(ip);
      _checkAutoBan(ip, `rate_limit:${label}`);
      res.status(429).json({
        success:     false,
        message:     'Quá nhiều request.',
        retryAfter:  Math.ceil(options.windowMs / 1000),
      });
    },
  });

  const cfg = getCfg();
  return {
    global:  makeRl(cfg.rateLimit.global,  'global'),
    api:     makeRl(cfg.rateLimit.api,     'api'),
    auth:    makeRl(cfg.rateLimit.auth,    'auth'),
    contact: makeRl(cfg.rateLimit.contact, 'contact'),
  };
}

// ══════════════════════════════════════════════════════════════
//  AUTO-BAN với Hard Ban (tái phạm nhiều lần)
// ══════════════════════════════════════════════════════════════
async function _checkAutoBan(ip, reason) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.autoBanEnabled) return;

  const violations = store.getViolations(ip);
  if (violations < (cfg.ipBlocking.banThreshold ?? 30)) return;

  const banCount  = store.getBanCount(ip);
  const hardAfter = cfg.ipBlocking.hardBanAfter ?? 3;
  const duration  = banCount >= hardAfter
    ? (cfg.ipBlocking.hardBanMs      ?? 24 * 60 * 60000)  // Hard ban 24h
    : (cfg.ipBlocking.banDurationMs  ?? 60 * 60000);       // Normal ban 1h

  store.ban(ip, reason, duration);
  logger.critical('auto_banned', {
    ip, reason, violations,
    banCount: banCount + 1,
    durationMin: Math.ceil(duration / 60000),
    isHard: banCount >= hardAfter,
  });

  const { autoBlockCloudflare } = require('./securityLogger');
  await autoBlockCloudflare(ip, reason);
}

module.exports = {
  buildRateLimiters,
  honeypotMiddleware,
  ipBlockingMiddleware,
  connectionProtectionMiddleware,
  slowRequestMiddleware,
  botDetectionMiddleware,
  getRealIp,
};
