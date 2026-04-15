// ============================================================
//  server/middleware/antiddos/layers.js â€” Enterprise Grade
// ============================================================

const rateLimit = require('express-rate-limit');
const store     = require('./ipStore');
const logger    = require('./securityLogger');
const { sendAlertToNIDS } = require('./nidsWebhook');

function getCfg() { return require('../../config/baomat._config'); }

// â”€â”€ Láº¥y real IP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function getRealIp(req) {
  // Chá»‰ trust CF-Connecting-IP khi cÃ³ Cloudflare tháº­t
  // KHÃ”NG trust X-Forwarded-For vÃ¬ dá»… bá»‹ giáº£ máº¡o (k6 spoofing)
  if (process.env.TRUST_CF_PROXY === 'true') {
    return req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
  }
  return req.socket.remoteAddress || req.ip;
}

// â”€â”€ HONEYPOT â€” báº«y cÃ¡c scanner/attacker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // Ban ngay láº­p tá»©c 24 giá» â€” khÃ´ng cáº§n Ä‘áº¿m violation
    store.ban(ip, `honeypot: ${req.path}`, 24 * 60 * 60 * 1000);
    // return res.status(404).json({ success: false, message: 'Not found' }); // Chế độ giám sát: Không chặn
    return next();
  }
  next();
}

// â”€â”€ LAYER 3 â€” IP Blocking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function ipBlockingMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.enabled) return next();

  const ip = getRealIp(req);

  if (cfg.ipBlocking.whitelist?.includes(ip)) return next();

  if (cfg.ipBlocking.staticBlacklist?.includes(ip)) {
    logger.block('static_blacklist', { ip });
    sendAlertToNIDS(ip, req.path, 'Phát hi?n IP n?m trong Static Blacklist', { duration: 0.1, srcBytes: 200, dstBytes: 100 });
    store.totalBlocked++;
    // return res.status(403).json({ success: false, message: 'Access denied' }); // Chế độ giám sát: Không chặn
    return next();
  }

  if (store.isBanned(ip)) {
    const info    = store.getBanInfo(ip);
    const remain  = Math.ceil(((info?.expiresAt ?? 0) - Date.now()) / 1000);
    const banCount = info?.banCount ?? 1;
    logger.block('dynamic_blacklist', { ip, reason: info?.reason, banCount, remainSec: remain });
    sendAlertToNIDS(ip, req.path, 'Phát hi?n truy c?p t? Dynamic Blacklist (' + (info?.reason || 'Unknown') + ')', { duration: 0.1, srcBytes: 200, dstBytes: 100 });
    store.totalBlocked++;
    // return res.status(403).json({
    //   success: false,
    //   message: banCount >= 3
    //     ? 'IP bị chặn vĩnh viễn do tái phạm nhiều lần.'
    //     : 'IP tạm thời bị chặn. Thử lại sau.',
    //   retryAfter: remain,
    // }); // Chế độ giám sát: Không chặn
    return next();
  }
  next();
}

// ————————————————————————————————————————————————————————————
function slowRequestMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.slowRequest?.enabled) return next();

  const ip = getRealIp(req);
  const ms = cfg.slowRequest.requestTimeoutMs ?? 20000;

  req.setTimeout(ms, () => {
    logger.warn('slow_request_timeout', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'slow_request');
    // if (!res.headersSent) res.status(408).json({ success: false, message: 'Request timeout' }); // Chế độ giám sát: Không chặn
    req.socket?.destroy();
  });

  req.socket?.setTimeout(ms + 5000);
  req.socket?.once('timeout', () => { req.socket.destroy(); });

  next();
}

// ————————————————————————————————————————————————————————————
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
    logger.block('too_many_connections', { ip, conns, max });
    sendAlertToNIDS(ip, req.path, 'Phát hi?n T?n công DDoS: Quá nhi?u k?t n?i d?ng th?i (' + conns + '/' + max + ')', { duration: 5.5, srcBytes: 5000, dstBytes: 100 });
    store.addViolation(ip);
    _checkAutoBan(ip, `too_many_connections: ${conns}`);
    // return res.status(429).json({ success: false, message: 'Quá nhiều kết nối đồng thời' }); // Chế độ giám sát: Không chặn
    return next();
  }

  const bodySize = parseInt(req.headers['content-length'] ?? '0');
  if (bodySize > (cfg.connectionProtection.maxBodySizeBytes ?? 10485760)) {
    store.closeConn(ip);
    logger.block('oversized_body', { ip, bodySize });
    return res.status(413).json({ success: false, message: 'Request body quÃ¡ lá»›n' });
  }
  next();
}

// â”€â”€ LAYER 2 â€” Bot Detection + Anomaly + Fingerprint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2b. Known bad agents
  const blocked = cfg.botDetection.blockedAgents ?? [];
  if (blocked.some(b => ua.includes(b))) {
    logger.block('bad_user_agent', { ip, ua: ua.slice(0, 60) });
    sendAlertToNIDS(ip, req.path, 'Phát hi?n Bot: User-Agent d?c h?i', { duration: 0.5, srcBytes: 600, dstBytes: 150 });
    store.logAttack(ip, 'BAD_AGENT', ua.slice(0, 60));
    store.addViolation(ip);
    _checkAutoBan(ip, `bad_agent: ${ua.slice(0, 40)}`);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2c. Missing Accept header trÃªn API call
  if (cfg.botDetection.blockMissingAccept && req.path.startsWith('/api/') && !req.headers['accept']) {
    logger.block('missing_accept_header', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'missing_accept_header');
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2d. Header fingerprint â€” request quÃ¡ Ã­t header (bot thÆ°á»ng gá»­i ráº¥t Ã­t header)
  const headerCount = Object.keys(req.headers).length;
  if (req.path.startsWith('/api/') && headerCount < 3) {
    logger.block('suspicious_fingerprint', { ip, headerCount, path: req.path });
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2e. Anomaly â€” sliding window RPM
  const rpm = store.recordHit(ip, cfg.botDetection.anomalyWindowMs ?? 60000);
  const threshold = cfg.botDetection.anomalyRpmThreshold ?? 200;

  if (rpm > threshold) {
    logger.critical('anomaly_traffic', { ip, rpm, threshold });
    sendAlertToNIDS(ip, req.path, 'Phát hi?n T?n công DDoS: B?t thu?ng traffic (' + rpm + ' RPM)', { duration: 15.0, srcBytes: 15000, dstBytes: 1000 });
    store.logAttack(ip, 'ANOMALY', `${rpm} rpm`);
    store.addViolation(ip);
    _checkAutoBan(ip, `anomaly: ${rpm} rpm`);
    return res.status(429).json({ success: false, message: 'Traffic báº¥t thÆ°á»ng' });
  }

  if (rpm > threshold * 0.6) {
    logger.warn('high_traffic', { ip, rpm, threshold });
  }

  next();
}

// â”€â”€ LAYER 1 â€” Rate Limiters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    handler: (req, res) => {
      const ip = getRealIp(req);
      logger.block('rate_limit_exceeded', { ip, path: req.path, limiter: label });
      sendAlertToNIDS(ip, req.path, 'Vu?t quá Rate Limit (' + label + ')', { duration: 2.0, srcBytes: 2500, dstBytes: 150 });
      store.addViolation(ip);
      _checkAutoBan(ip, `rate_limit: ${label}`);
      res.status(429).json({
        success: false,
        message: 'QuÃ¡ nhiá»u request. Vui lÃ²ng thá»­ láº¡i sau.',
        retryAfter: Math.ceil(options.windowMs / 1000),
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

// â”€â”€ Auto-ban helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function _checkAutoBan(ip, reason) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.autoBanEnabled) return;

  const violations = store.getViolations(ip);
  const threshold  = cfg.ipBlocking.banThreshold ?? 30;
  if (violations < threshold) return;

  // Hard ban sau nhiá»u láº§n tÃ¡i pháº¡m
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







