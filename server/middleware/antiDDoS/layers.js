// ============================================================
//  server/middleware/antiddos/layers.js - Enterprise Grade
// ============================================================

const rateLimit = require('express-rate-limit');
const store     = require('./ipStore');
const logger    = require('./securityLogger');
const { sendAlertToNIDS } = require('./nidsWebhook');

function getCfg() { return require('../../config/baomat._config'); }

// ─── Lấy real IP ──────────────────────────────────────────
function getRealIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  if (process.env.TRUST_CF_PROXY === 'true') {
    return req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
  }
  return req.socket.remoteAddress || req.ip;
}

// ─── HONEYPOT ─────────────────────────────────────────────
const HONEYPOT_PATHS = [
  '/.env', '/.git', '/wp-admin', '/wp-login.php',
  '/admin.php', '/phpmyadmin', '/xmlrpc.php',
  '/config.php', '/.htaccess', '/shell.php',
  '/backup.sql', '/db.sql', '/database.sql',
  '/manager/html', '/actuator', '/console',
  '/.aws/credentials', '/server-status',
];

function honeypotMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.enabled) return next();

  const path = req.path.toLowerCase();
  if (HONEYPOT_PATHS.some(p => path.startsWith(p))) {
    const ip = getRealIp(req);
    logger.critical('honeypot_triggered', { ip, path: req.path });
    store.logAttack(ip, 'HONEYPOT', req.path);
    store.ban(ip, `honeypot: ${req.path}`, 24 * 60 * 60 * 1000);
    
    // [GHOST MODE] Không chặn 404, cứ để nó đi tiếp
    return next();
  }
  next();
}

// ─── LAYER 3 - IP Blocking ────────────────────────────────
function ipBlockingMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.enabled) return next();

  const ip = getRealIp(req);
  if (cfg.ipBlocking.whitelist?.includes(ip)) return next();

  if (cfg.ipBlocking.staticBlacklist?.includes(ip)) {
    logger.block('static_blacklist', { ip });
    sendAlertToNIDS(ip, req.path, 'Phát hiện IP nằm trong Static Blacklist', { duration: 0.1, srcBytes: 200, dstBytes: 100 });
    store.totalBlocked++;
    // [GHOST MODE] Không chặn, cứ để nó đi tiếp
    return next();
  }

  if (store.isBanned(ip)) {
    const info    = store.getBanInfo(ip);
    const remain  = Math.ceil(((info?.expiresAt ?? 0) - Date.now()) / 1000);
    const banCount = info?.banCount ?? 1;
    logger.block('dynamic_blacklist', { ip, reason: info?.reason, banCount, remainSec: remain });
    sendAlertToNIDS(ip, req.path, `Phát hiện truy cập từ Dynamic Blacklist (${info?.reason || 'Unknown'})`, { duration: 0.1, srcBytes: 200, dstBytes: 100 });
    store.totalBlocked++;
    
    // [GHOST MODE] Không chặn, cứ để nó đi tiếp
    return next();
  }
  next();
}

// ─── LAYER 5 - Slow Request (Slowloris) ───────────────────
function slowRequestMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.slowRequest?.enabled) return next();

  const ip = getRealIp(req);
  const ms = cfg.slowRequest.requestTimeoutMs ?? 20000;

  req.setTimeout(ms, () => {
    logger.warn('slow_request_timeout', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'slow_request');
    // [GHOST MODE] Không gửi 408 timeout
  });

  req.socket?.setTimeout(ms + 5000);
  req.socket?.once('timeout', () => { req.socket.destroy(); });

  next();
}

// ─── LAYER 4 - Connection Protection ──────────────────────
function connectionProtectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.connectionProtection?.enabled) return next();

  const ip    = getRealIp(req);
  const conns = store.openConn(ip);
  res.on('finish', () => store.closeConn(ip));
  res.on('close',  () => store.closeConn(ip));

  const max = cfg.connectionProtection.maxConnPerIp ?? 30;
  if (conns > max) {
    logger.block('too_many_connections', { ip, conns, max });
    sendAlertToNIDS(ip, req.path, `Phát hiện Tấn công DDoS: Quá nhiều kết nối đồng thời (${conns}/${max})`, { duration: 5.5, srcBytes: 5000, dstBytes: 100 });
    store.addViolation(ip);
    _checkAutoBan(ip, `too_many_connections: ${conns}`);
    
    // [GHOST MODE] Không chặn, cứ để nó đi tiếp
    return next();
  }

  const bodySize = parseInt(req.headers['content-length'] ?? '0');
  if (bodySize > (cfg.connectionProtection.maxBodySizeBytes ?? 10485760)) {
    logger.block('oversized_body', { ip, bodySize });
    return next();
  }
  next();
}

// ─── LAYER 2 - Bot Detection + Anomaly + Fingerprint ──────
function botDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.botDetection?.enabled) return next();

  const ip = getRealIp(req);
  const ua = (req.headers['user-agent'] ?? '').toLowerCase();

  // 2a. Empty User-Agent
  if (!ua) {
    logger.block('empty_user_agent', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'empty_user_agent');
    return next();
  }

  // 2b. Known bad agents
  const blocked = cfg.botDetection.blockedAgents ?? [];
  if (blocked.some(b => ua.includes(b))) {
    logger.block('bad_user_agent', { ip, ua: ua.slice(0, 60) });
    sendAlertToNIDS(ip, req.path, 'Phát hiện Bot: User-Agent độc hại', { duration: 0.5, srcBytes: 600, dstBytes: 150 });
    store.logAttack(ip, 'BAD_AGENT', ua.slice(0, 60));
    store.addViolation(ip);
    _checkAutoBan(ip, `bad_agent: ${ua.slice(0, 40)}`);
    return next();
  }

  // 2c. Header fingerprint
  const headerCount = Object.keys(req.headers).length;
  if (req.path.startsWith('/api/') && headerCount < 3) {
    logger.block('suspicious_fingerprint', { ip, headerCount, path: req.path });
    store.addViolation(ip);
    return next();
  }

  // 2e. Anomaly - sliding window RPM
  const rpm = store.recordHit(ip, cfg.botDetection.anomalyWindowMs ?? 60000);
  const threshold = cfg.botDetection.anomalyRpmThreshold ?? 200;

  if (rpm > threshold) {
    logger.critical('anomaly_traffic', { ip, rpm, threshold });
    sendAlertToNIDS(ip, req.path, `Phát hiện Tấn công DDoS: Bất thường traffic (${rpm} RPM)`, { duration: 15.0, srcBytes: 15000, dstBytes: 1000 });
    store.logAttack(ip, 'ANOMALY', `${rpm} rpm`);
    store.addViolation(ip);
    _checkAutoBan(ip, `anomaly: ${rpm} rpm`);
    
    // [GHOST MODE] Không chặn 429, cứ để nó đi tiếp
    return next();
  }

  if (rpm > threshold * 0.6) {
    logger.warn('high_traffic', { ip, rpm, threshold });
  }

  next();
}

// ─── LAYER 1 - Rate Limiters ─────────────────────────────
function buildRateLimiters() {
  const makeRl = (options, label) => rateLimit({
    ...options,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator:    (req) => getRealIp(req),
    skip:            (req) => {
      const cfg = getCfg();
      return cfg.ipBlocking?.whitelist?.includes(getRealIp(req)) ?? false;
    },
    handler: (req, res, next) => {
      const ip = getRealIp(req);
      logger.block('rate_limit_exceeded', { ip, path: req.path, limiter: label });
      sendAlertToNIDS(ip, req.path, `Vượt quá Rate Limit (${label})`, { duration: 2.0, srcBytes: 2500, dstBytes: 150 });
      store.addViolation(ip);
      _checkAutoBan(ip, `rate_limit: ${label}`);
      
      // [GHOST MODE] Thay vì trả về 429, ta gọi next() để bỏ qua chặn
      next();
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

// ─── Auto-ban helper ─────────────────────────────────────
async function _checkAutoBan(ip, reason) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.autoBanEnabled) return;

  const violations = store.getViolations(ip);
  const threshold  = cfg.ipBlocking.banThreshold ?? 30;
  if (violations < threshold) return;

  const banCount   = store.getBanCount(ip);
  const hardBanAt  = cfg.ipBlocking.hardBanAfter ?? 3;
  const duration   = banCount >= hardBanAt
    ? (cfg.ipBlocking.hardBanMs  ?? 24 * 60 * 60000)
    : (cfg.ipBlocking.banDurationMs ?? 60 * 60000);

  store.ban(ip, reason, duration);
  logger.critical('ip_auto_banned', { ip, reason, violations, banCount: banCount + 1, durationMin: Math.ceil(duration / 60000) });

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
