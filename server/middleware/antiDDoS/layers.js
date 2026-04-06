// ============================================================
//  server/middleware/antiddos/layers.js
//  5 lớp bảo vệ độc lập — mỗi lớp là một middleware factory
//  Tất cả đều nhận cfg + store + logger để dễ test/mock
// ============================================================

const rateLimit = require('express-rate-limit');
const cfg       = require('../../config/security.config');
const store     = require('./ipStore');
const logger    = require('./securityLogger');

// ─────────────────────────────────────────────────────────────
//  Helper: lấy real IP (ưu tiên Cloudflare header)
// ─────────────────────────────────────────────────────────────
function getRealIp(req) {
  if (cfg.cloudflare.trustProxy) {
    return req.headers['cf-connecting-ip']
        || req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.ip;
  }
  return req.ip;
}

// ─────────────────────────────────────────────────────────────
//  LAYER 1 — Rate Limiting
//  Dùng express-rate-limit với custom keyGenerator (real IP)
// ─────────────────────────────────────────────────────────────
function buildRateLimiters() {
  const makeRl = (options, label) => rateLimit({
    ...options,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator:    (req) => getRealIp(req),
    skip:            (req) => cfg.ipBlocking.whitelist.includes(getRealIp(req)),
    handler:         (req, res) => {
      const ip = getRealIp(req);
      logger.block('rate_limit_exceeded', { ip, route: req.path, limiter: label });
      store.addViolation(ip);
      res.status(429).json({
        success: false,
        message: 'Quá nhiều request. Vui lòng thử lại sau.',
        retryAfter: Math.ceil(options.windowMs / 1000),
      });
    },
  });

  return {
    global:  makeRl(cfg.rateLimit.global,  'global'),
    api:     makeRl(cfg.rateLimit.api,     'api'),
    auth:    makeRl(cfg.rateLimit.auth,    'auth'),
    contact: makeRl(cfg.rateLimit.contact, 'contact'),
  };
}

// ─────────────────────────────────────────────────────────────
//  LAYER 2 — Bot Detection
//  Kiểm tra User-Agent + traffic anomaly
// ─────────────────────────────────────────────────────────────
function botDetectionMiddleware(req, res, next) {
  if (!cfg.botDetection.enabled) return next();

  const ip = getRealIp(req);
  const ua = (req.headers['user-agent'] ?? '').toLowerCase();

  // 2a. Block known bad User-Agents
  if (cfg.botDetection.blockEmptyUserAgent && ua === '') {
    logger.block('empty_user_agent', { ip, path: req.path });
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  const isBadAgent = cfg.botDetection.blockedAgents.some(b => ua.includes(b));
  if (isBadAgent) {
    logger.block('bad_user_agent', { ip, ua: ua.slice(0, 80), path: req.path });
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2b. Block API requests without Accept header (headless bots)
  if (cfg.botDetection.blockMissingAccept
    && req.path.startsWith('/api/')
    && !req.headers['accept']) {
    logger.block('missing_accept_header', { ip, path: req.path });
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2c. Traffic anomaly — sliding window RPM check
  const rpmCount = store.recordHit(ip, cfg.botDetection.anomalyWindowMs);
  if (rpmCount > cfg.botDetection.anomalyRpmThreshold) {
    logger.critical('anomaly_traffic', { ip, rpmCount, threshold: cfg.botDetection.anomalyRpmThreshold });
    store.addViolation(ip);
    // Trigger auto-ban nếu đủ vi phạm
    _checkAutoBan(ip, `anomaly_traffic: ${rpmCount} rpm`);
    return res.status(429).json({ success: false, message: 'Traffic bất thường. Truy cập bị hạn chế.' });
  }

  // 2d. Warn khi gần ngưỡng
  if (rpmCount > cfg.botDetection.anomalyRpmThreshold * 0.7) {
    logger.warn('high_traffic', { ip, rpmCount });
  }

  next();
}

// ─────────────────────────────────────────────────────────────
//  LAYER 3 — IP Blocking
//  Kiểm tra blacklist (static + dynamic) ở đầu mỗi request
// ─────────────────────────────────────────────────────────────
function ipBlockingMiddleware(req, res, next) {
  if (!cfg.ipBlocking.enabled) return next();

  const ip = getRealIp(req);

  // 3a. Whitelist — bỏ qua tất cả checks
  if (cfg.ipBlocking.whitelist.includes(ip)) return next();

  // 3b. Static blacklist (từ .env)
  if (cfg.ipBlocking.staticBlacklist.includes(ip)) {
    logger.block('static_blacklist', { ip });
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  // 3c. Dynamic blacklist (auto-ban)
  if (store.isBanned(ip)) {
    const info = store.getBanInfo(ip);
    const remainMs = (info.expiresAt ?? 0) - Date.now();
    logger.block('dynamic_blacklist', { ip, reason: info.reason, remainMin: Math.ceil(remainMs / 60000) });
    return res.status(403).json({
      success: false,
      message: 'IP đã bị tạm khóa. Thử lại sau.',
      retryAfter: Math.ceil(remainMs / 1000),
    });
  }

  next();
}

// ─────────────────────────────────────────────────────────────
//  LAYER 4 — Connection Protection
//  Giới hạn concurrent connections + body size
// ─────────────────────────────────────────────────────────────
function connectionProtectionMiddleware(req, res, next) {
  if (!cfg.connectionProtection.enabled) return next();

  const ip = getRealIp(req);

  // 4a. Concurrent connection limit
  const currentConns = store.openConn(ip);
  if (currentConns > cfg.connectionProtection.maxConnPerIp) {
    store.closeConn(ip);
    logger.block('too_many_connections', { ip, connections: currentConns });
    store.addViolation(ip);
    return res.status(429).json({ success: false, message: 'Quá nhiều kết nối đồng thời' });
  }

  // Giảm conn count khi response kết thúc
  res.on('finish', () => store.closeConn(ip));
  res.on('close',  () => store.closeConn(ip));

  // 4b. Request body size check
  const contentLength = parseInt(req.headers['content-length'] ?? '0');
  if (contentLength > cfg.connectionProtection.maxBodySizeBytes) {
    store.closeConn(ip);
    logger.block('oversized_body', { ip, contentLength, limit: cfg.connectionProtection.maxBodySizeBytes });
    return res.status(413).json({ success: false, message: 'Request body quá lớn' });
  }

  next();
}

// ─────────────────────────────────────────────────────────────
//  LAYER 5 — Slow Request Protection (Slowloris defense)
//  Set timeout cho request và header parsing
// ─────────────────────────────────────────────────────────────
function slowRequestMiddleware(req, res, next) {
  if (!cfg.slowRequest.enabled) return next();

  const ip = getRealIp(req);

  // Set request timeout — nếu client không gửi xong body trong thời gian này → drop
  req.setTimeout(cfg.slowRequest.requestTimeoutMs, () => {
    logger.warn('slow_request_timeout', { ip, path: req.path, timeoutMs: cfg.slowRequest.requestTimeoutMs });
    store.addViolation(ip);
    res.status(408).json({ success: false, message: 'Request timeout' });
    req.socket?.destroy();
  });

  // Set socket timeout
  req.socket?.setTimeout(cfg.slowRequest.requestTimeoutMs + 5000);
  req.socket?.once('timeout', () => {
    logger.warn('socket_timeout', { ip });
    req.socket.destroy();
  });

  next();
}

// ─────────────────────────────────────────────────────────────
//  Helper: Auto-ban nếu vượt threshold vi phạm
// ─────────────────────────────────────────────────────────────
async function _checkAutoBan(ip, reason) {
  if (!cfg.ipBlocking.autoBanEnabled) return;
  const violations = store.getViolations(ip);
  if (violations >= cfg.ipBlocking.banThreshold) {
    store.ban(ip, reason, cfg.ipBlocking.banDurationMs);
    logger.critical('ip_auto_banned', {
      ip,
      reason,
      violations,
      banDurationMin: Math.ceil(cfg.ipBlocking.banDurationMs / 60000),
    });
    // Trigger Cloudflare block nếu được cấu hình
    const { autoBlockCloudflare } = require('./securityLogger');
    await autoBlockCloudflare(ip, reason);
  }
}

// Export mọi thứ cần thiết
module.exports = {
  buildRateLimiters,
  botDetectionMiddleware,
  ipBlockingMiddleware,
  connectionProtectionMiddleware,
  slowRequestMiddleware,
  getRealIp,
};
