// ============================================================
//  server/middleware/antiddos/layers.js Ã¢â‚¬â€ Enterprise Grade
// ============================================================

const rateLimit = require('express-rate-limit');
const store     = require('./ipStore');
const logger    = require('./securityLogger');
const { sendAlertToNIDS } = require('./nidsWebhook');

function getCfg() { return require('../../config/baomat._config'); }

// Ã¢â€â‚¬Ã¢â€â‚¬ LÃ¡ÂºÂ¥y real IP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function getRealIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  if (process.env.TRUST_CF_PROXY === 'true') {
    return req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
  }
  return req.socket.remoteAddress || req.ip;
}

// Ã¢â€â‚¬Ã¢â€â‚¬ HONEYPOT Ã¢â‚¬â€ bÃ¡ÂºÂ«y cÃƒÂ¡c scanner/attacker Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
    // Ban ngay lÃ¡ÂºÂ­p tÃ¡Â»Â©c 24 giÃ¡Â»Â Ã¢â‚¬â€ khÃƒÂ´ng cÃ¡ÂºÂ§n Ã„â€˜Ã¡ÂºÂ¿m violation
    store.ban(ip, `honeypot: ${req.path}`, 24 * 60 * 60 * 1000);
    // return res.status(404).json({ success: false, message: 'Not found' }); // Cháº¿ Ä‘á»™ giÃ¡m sÃ¡t: KhÃ´ng cháº·n
    return next();
  }
  next();
}

// Ã¢â€â‚¬Ã¢â€â‚¬ LAYER 3 Ã¢â‚¬â€ IP Blocking Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function ipBlockingMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.enabled) return next();

  const ip = getRealIp(req);

  if (cfg.ipBlocking.whitelist?.includes(ip)) return next();

  if (cfg.ipBlocking.staticBlacklist?.includes(ip)) {
    logger.block('static_blacklist', { ip });
    sendAlertToNIDS(ip, req.path, 'PhÃ¡t hi?n IP n?m trong Static Blacklist', { duration: 0.1, srcBytes: 200, dstBytes: 100 });
    store.totalBlocked++;
    // return res.status(403).json({ success: false, message: 'Access denied' }); // Cháº¿ Ä‘á»™ giÃ¡m sÃ¡t: KhÃ´ng cháº·n
    return next();
  }

  if (store.isBanned(ip)) {
    const info    = store.getBanInfo(ip);
    const remain  = Math.ceil(((info?.expiresAt ?? 0) - Date.now()) / 1000);
    const banCount = info?.banCount ?? 1;
    logger.block('dynamic_blacklist', { ip, reason: info?.reason, banCount, remainSec: remain });
    sendAlertToNIDS(ip, req.path, 'PhÃ¡t hi?n truy c?p t? Dynamic Blacklist (' + (info?.reason || 'Unknown') + ')', { duration: 0.1, srcBytes: 200, dstBytes: 100 });
    store.totalBlocked++;
    // return res.status(403).json({
    //   success: false,
    //   message: banCount >= 3
    //     ? 'IP bá»‹ cháº·n vÄ©nh viá»…n do tÃ¡i pháº¡m nhiá»u láº§n.'
    //     : 'IP táº¡m thá»i bá»‹ cháº·n. Thá»­ láº¡i sau.',
    //   retryAfter: remain,
    // }); // Cháº¿ Ä‘á»™ giÃ¡m sÃ¡t: KhÃ´ng cháº·n
    return next();
  }
  next();
}

// â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”
function slowRequestMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.slowRequest?.enabled) return next();

  const ip = getRealIp(req);
  const ms = cfg.slowRequest.requestTimeoutMs ?? 20000;

  req.setTimeout(ms, () => {
    logger.warn('slow_request_timeout', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'slow_request');
    // if (!res.headersSent) res.status(408).json({ success: false, message: 'Request timeout' }); // Cháº¿ Ä‘á»™ giÃ¡m sÃ¡t: KhÃ´ng cháº·n
    req.socket?.destroy();
  });

  req.socket?.setTimeout(ms + 5000);
  req.socket?.once('timeout', () => { req.socket.destroy(); });

  next();
}

// â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”
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
    sendAlertToNIDS(ip, req.path, 'PhÃ¡t hi?n T?n cÃ´ng DDoS: QuÃ¡ nhi?u k?t n?i d?ng th?i (' + conns + '/' + max + ')', { duration: 5.5, srcBytes: 5000, dstBytes: 100 });
    store.addViolation(ip);
    _checkAutoBan(ip, `too_many_connections: ${conns}`);
    // return res.status(429).json({ success: false, message: 'QuÃ¡ nhiá»u káº¿t ná»‘i Ä‘á»“ng thá»i' }); // Cháº¿ Ä‘á»™ giÃ¡m sÃ¡t: KhÃ´ng cháº·n
    return next();
  }

  const bodySize = parseInt(req.headers['content-length'] ?? '0');
  if (bodySize > (cfg.connectionProtection.maxBodySizeBytes ?? 10485760)) {
    store.closeConn(ip);
    logger.block('oversized_body', { ip, bodySize });
    return res.status(413).json({ success: false, message: 'Request body quÃƒÂ¡ lÃ¡Â»â€ºn' });
  }
  next();
}

// Ã¢â€â‚¬Ã¢â€â‚¬ LAYER 2 Ã¢â‚¬â€ Bot Detection + Anomaly + Fingerprint Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
    sendAlertToNIDS(ip, req.path, 'PhÃ¡t hi?n Bot: User-Agent d?c h?i', { duration: 0.5, srcBytes: 600, dstBytes: 150 });
    store.logAttack(ip, 'BAD_AGENT', ua.slice(0, 60));
    store.addViolation(ip);
    _checkAutoBan(ip, `bad_agent: ${ua.slice(0, 40)}`);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2c. Missing Accept header trÃƒÂªn API call
  if (cfg.botDetection.blockMissingAccept && req.path.startsWith('/api/') && !req.headers['accept']) {
    logger.block('missing_accept_header', { ip, path: req.path });
    store.addViolation(ip);
    _checkAutoBan(ip, 'missing_accept_header');
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2d. Header fingerprint Ã¢â‚¬â€ request quÃƒÂ¡ ÃƒÂ­t header (bot thÃ†Â°Ã¡Â»Âng gÃ¡Â»Â­i rÃ¡ÂºÂ¥t ÃƒÂ­t header)
  const headerCount = Object.keys(req.headers).length;
  if (req.path.startsWith('/api/') && headerCount < 3) {
    logger.block('suspicious_fingerprint', { ip, headerCount, path: req.path });
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // 2e. Anomaly Ã¢â‚¬â€ sliding window RPM
  const rpm = store.recordHit(ip, cfg.botDetection.anomalyWindowMs ?? 60000);
  const threshold = cfg.botDetection.anomalyRpmThreshold ?? 200;

  if (rpm > threshold) {
    logger.critical('anomaly_traffic', { ip, rpm, threshold });
    sendAlertToNIDS(ip, req.path, 'PhÃ¡t hi?n T?n cÃ´ng DDoS: B?t thu?ng traffic (' + rpm + ' RPM)', { duration: 15.0, srcBytes: 15000, dstBytes: 1000 });
    store.logAttack(ip, 'ANOMALY', `${rpm} rpm`);
    store.addViolation(ip);
    _checkAutoBan(ip, `anomaly: ${rpm} rpm`);
    return res.status(429).json({ success: false, message: 'Traffic bÃ¡ÂºÂ¥t thÃ†Â°Ã¡Â»Âng' });
  }

  if (rpm > threshold * 0.6) {
    logger.warn('high_traffic', { ip, rpm, threshold });
  }

  next();
}

// Ã¢â€â‚¬Ã¢â€â‚¬ LAYER 1 Ã¢â‚¬â€ Rate Limiters Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
      sendAlertToNIDS(ip, req.path, 'Vu?t quÃ¡ Rate Limit (' + label + ')', { duration: 2.0, srcBytes: 2500, dstBytes: 150 });
      store.addViolation(ip);
      _checkAutoBan(ip, `rate_limit: ${label}`);
      res.status(429).json({
        success: false,
        message: 'QuÃƒÂ¡ nhiÃ¡Â»Âu request. Vui lÃƒÂ²ng thÃ¡Â»Â­ lÃ¡ÂºÂ¡i sau.',
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

// Ã¢â€â‚¬Ã¢â€â‚¬ Auto-ban helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function _checkAutoBan(ip, reason) {
  const cfg = getCfg();
  if (!cfg.ipBlocking?.autoBanEnabled) return;

  const violations = store.getViolations(ip);
  const threshold  = cfg.ipBlocking.banThreshold ?? 30;
  if (violations < threshold) return;

  // Hard ban sau nhiÃ¡Â»Âu lÃ¡ÂºÂ§n tÃƒÂ¡i phÃ¡ÂºÂ¡m
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








