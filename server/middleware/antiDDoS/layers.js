// ============================================================
//  server/middleware/antiddos/layers.js — Full Defense v4
//  Chống: Proxy DDoS, packet fragmentation, low-and-slow,
//         container attack, IP rotation
// ============================================================

const rateLimit      = require('express-rate-limit');
const store          = require('./ipStore');
const logger         = require('./securityLogger');
const behaviorEngine = require('./behaviorEngine');
const proxyDetector  = require('./proxyDetector');
const fragmentDetector = require('./fragmentDetector');

function getCfg() { return require('../../config/baomat._config'); }

// ══════════════════════════════════════════════════════════════
//  LẤY REAL IP
// ══════════════════════════════════════════════════════════════
function getRealIp(req) {
  if (process.env.TRUST_CF_PROXY === 'true') {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) return cfIp.trim();
  }
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = forwarded.split(',')[0].trim();
    if (!_isPrivateIp(first)) return first;
  }
  return (req.socket?.remoteAddress || req.ip || '0.0.0.0').replace('::ffff:', '');
}

function _isPrivateIp(ip) {
  return ['127.','10.','192.168.','::1','0.0.0.0'].some(p => ip.startsWith(p))
    || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

function getSubnet(ip) { return ip.split('.').slice(0,3).join('.'); }

// ══════════════════════════════════════════════════════════════
//  HONEYPOT
// ══════════════════════════════════════════════════════════════
const HONEYPOT_PATHS = [
  '/.env','/.git','/wp-admin','/wp-login.php','/admin.php',
  '/phpmyadmin','/xmlrpc.php','/.htaccess','/shell.php',
  '/backup.sql','/db.sql','/database.sql','/actuator',
  '/.aws','/server-status','/console','/manager/html',
];

function honeypotMiddleware(req, res, next) {
  const cfg = getCfg();
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
//  PROXY DETECTION — Phát hiện proxy/VPN/Tor
// ══════════════════════════════════════════════════════════════
function proxyDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.enabled) return next();
  if (process.env.BLOCK_PROXY !== 'true') return next(); // Chỉ bật khi đang bị tấn công

  const ip     = getRealIp(req);
  if (cfg.ipBlocking?.whitelist?.includes(ip)) return next();

  const result = proxyDetector.analyze(req);

  if (result.isProxy) {
    logger.block('proxy_detected', { ip, score: result.score, flags: result.flags });
    store.logAttack(ip, 'PROXY', result.flags.join('|'));
    store.addViolation(ip);
    _checkAutoBan(ip, `proxy:score=${result.score}`);
    store.totalBlocked++;
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  if (result.isSuspect) {
    logger.warn('proxy_suspect', { ip, score: result.score, flags: result.flags });
    store.addViolation(ip);
    req._proxyScore = result.score;
  }

  next();
}

// ══════════════════════════════════════════════════════════════
//  FRAGMENT DETECTION — Phát hiện packet splitting
// ══════════════════════════════════════════════════════════════
function fragmentDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.enabled) return next();

  const ip     = getRealIp(req);
  const result = fragmentDetector.analyzeRequest(req, ip);

  if (result.score >= 50) {
    logger.block('fragment_attack', { ip, score: result.score, flags: result.flags });
    store.logAttack(ip, 'FRAGMENT', result.flags.join('|'));
    store.addViolation(ip);
    _checkAutoBan(ip, `fragment:score=${result.score}`);
    store.totalBlocked++;
    return res.status(400).json({ success: false, message: 'Bad request' });
  }

  if (result.score >= 25) {
    store.addViolation(ip);
    req._fragmentScore = result.score;
  }

  // Track slow body
  fragmentDetector.trackBodyReceiving(req, ip);

  next();
}

// ══════════════════════════════════════════════════════════════
//  BEHAVIORAL SCORING — Chống low-and-slow + IP rotation
// ══════════════════════════════════════════════════════════════
function behaviorMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.enabled) return next();

  const ip = getRealIp(req);
  if (cfg.ipBlocking?.whitelist?.includes(ip)) return next();

  const result = behaviorEngine.analyze(req, ip);
  const { score, subnetScore } = result;

  const scoreBlock  = parseInt(process.env.BEHAVIOR_SCORE_BLOCK  || '70');
  const scoreWarn   = parseInt(process.env.BEHAVIOR_SCORE_WARN   || '50');
  const subnetBlock = parseInt(process.env.SUBNET_SCORE_BLOCK    || '30');

  // Cộng thêm điểm từ proxy và fragment detection
  const totalScore = score
    + (req._proxyScore    ?? 0) * 0.3
    + (req._fragmentScore ?? 0) * 0.3;

  // Subnet distributed attack
  if (subnetScore >= subnetBlock) {
    const subnet = getSubnet(ip);
    if (!store.isSubnetBanned(subnet)) {
      logger.critical('subnet_distributed', { subnet, subnetScore, ip });
      store.logAttack(ip, 'DISTRIBUTED', `subnet ${subnet}.x score=${subnetScore}`);
      store.banSubnet(subnet, `distributed:score=${subnetScore}`, 30 * 60 * 1000);
    }
    store.totalBlocked++;
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  if (totalScore >= scoreBlock) {
    logger.critical('behavior_block', { ip, score: totalScore });
    store.logAttack(ip, 'BEHAVIOR', `score=${Math.round(totalScore)}`);
    store.addViolation(ip);
    _checkAutoBan(ip, `behavior:${Math.round(totalScore)}`);
    return res.status(429).json({ success: false, message: 'Suspicious traffic' });
  }

  if (totalScore >= scoreWarn) {
    logger.warn('behavior_warn', { ip, score: totalScore });
    store.addViolation(ip);
  }

  req._behaviorScore = totalScore;
  req._realIp        = ip;
  next();
}

// ══════════════════════════════════════════════════════════════
//  SUBNET BLOCKING
// ══════════════════════════════════════════════════════════════
const CLOUD_RANGES = [
  '104.131.','104.236.','159.203.','165.227.','167.99.',
  '174.138.','188.166.','198.199.','206.189.',
  '45.33.','45.56.','45.79.','50.116.','66.175.',
  '45.32.','45.63.','45.76.','45.77.','66.42.',
  '104.156.','149.28.','207.246.',
  '51.68.','51.75.','51.77.','51.89.','54.36.',
  '135.125.','141.94.','145.239.',
  '5.9.','23.88.','46.4.','49.12.','65.21.',
  '78.46.','85.10.','88.198.','95.216.',
  '116.202.','128.140.','135.181.','138.201.',
  '142.132.','144.76.','148.251.','157.90.',
  '159.69.','162.55.','167.235.','168.119.',
  '176.9.','178.63.','188.40.','195.201.',
];

function subnetBlockingMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.enabled) return next();

  const ip     = getRealIp(req);
  const subnet = getSubnet(ip);

  if (store.isSubnetBanned(subnet)) {
    store.totalBlocked++;
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const subnetCount  = store.recordSubnetHit(subnet);
  const maxPerSubnet = parseInt(process.env.MAX_IPS_PER_SUBNET || '10');

  if (subnetCount > maxPerSubnet) {
    store.banSubnet(subnet, `subnet_flood:${subnetCount}`, 60 * 60 * 1000);
    logger.critical('subnet_flood', { ip, subnet, count: subnetCount });
    store.logAttack(ip, 'SUBNET_FLOOD', `${subnet}.x — ${subnetCount} IPs`);
    return res.status(403).json({ success: false, message: 'Access denied' });
  }
  next();
}

function cloudIpDetectionMiddleware(req, res, next) {
  if (process.env.BLOCK_CLOUD_IPS !== 'true') return next();
  const ip = getRealIp(req);
  if (CLOUD_RANGES.some(r => ip.startsWith(r))) {
    store.logAttack(ip, 'CLOUD_IP', ip);
    store.totalBlocked++;
    return res.status(403).json({ success: false, message: 'Access denied' });
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
    store.totalBlocked++;
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  if (store.isBanned(ip)) {
    const info     = store.getBanInfo(ip);
    const remain   = Math.ceil(((info?.expiresAt ?? 0) - Date.now()) / 1000);
    const banCount = info?.banCount ?? 1;
    store.totalBlocked++;
    return res.status(403).json({
      success: false,
      message: banCount >= 3 ? 'IP bị chặn vĩnh viễn.' : 'IP tạm thời bị chặn.',
      retryAfter: remain,
    });
  }
  next();
}

// ══════════════════════════════════════════════════════════════
//  LAYER 5 — Slow Request
// ══════════════════════════════════════════════════════════════
function slowRequestMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.slowRequest?.enabled) return next();
  const ip = getRealIp(req);
  const ms = cfg.slowRequest.requestTimeoutMs ?? 15000;

  req.setTimeout(ms, () => {
    store.addViolation(ip);
    _checkAutoBan(ip, 'slow_request');
    if (!res.headersSent) res.status(408).json({ success: false, message: 'Timeout' });
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

  const max = cfg.connectionProtection.maxConnPerIp ?? 25;
  if (conns > max) {
    store.closeConn(ip);
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
//  LAYER 2 — Bot Detection + Global DDoS
// ══════════════════════════════════════════════════════════════
const _globalHits = { count: 0, resetAt: Date.now() + 60000, _alerted: false, _alertedAt: 0 };

function botDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.botDetection?.enabled) return next();

  const ip = getRealIp(req);
  const ua = (req.headers['user-agent'] ?? '').toLowerCase();

  if (!ua) {
    store.addViolation(ip);
    _checkAutoBan(ip, 'empty_ua');
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  if ((cfg.botDetection.blockedAgents ?? []).some(b => ua.includes(b))) {
    store.logAttack(ip, 'BAD_AGENT', ua.slice(0, 60));
    store.addViolation(ip);
    _checkAutoBan(ip, 'bad_agent');
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  if (cfg.botDetection.blockMissingAccept && req.path.startsWith('/api/') && !req.headers['accept']) {
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  if (req.path.startsWith('/api/') && Object.keys(req.headers).length < 3) {
    store.addViolation(ip);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  // Global DDoS check
  if (Date.now() > _globalHits.resetAt) {
    _globalHits.count = 0;
    _globalHits.resetAt = Date.now() + 60000;
    _globalHits._alerted = false;
  }
  _globalHits.count++;

  const globalMax = parseInt(process.env.GLOBAL_RPM_MAX || '1000');
  if (_globalHits.count > globalMax) {
    if (!_globalHits._alerted || Date.now() - _globalHits._alertedAt > 30000) {
      logger.critical('global_ddos', { rpm: _globalHits.count, ips: store.hitMap.size });
      store.logAttack('GLOBAL', 'GLOBAL_DDOS', `${_globalHits.count} rpm`);
      _globalHits._alerted   = true;
      _globalHits._alertedAt = Date.now();
    }
    return res.status(503).json({ success: false, message: 'Service tạm thời không khả dụng' });
  }
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
      logger.block('rate_limit', { ip, limiter: label });
      store.addViolation(ip);
      _checkAutoBan(ip, `rate_limit:${label}`);
      res.status(429).json({ success: false, message: 'Quá nhiều request.', retryAfter: Math.ceil(options.windowMs / 1000) });
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
//  AUTO-BAN
// ══════════════════════════════════════════════════════════════
async function _checkAutoBan(ip, reason) {
  const cfg        = getCfg();
  if (!cfg.ipBlocking?.autoBanEnabled) return;
  const violations = store.getViolations(ip);
  if (violations < (cfg.ipBlocking.banThreshold ?? 20)) return;

  const banCount  = store.getBanCount(ip);
  const hardAfter = cfg.ipBlocking.hardBanAfter ?? 3;
  const duration  = banCount >= hardAfter
    ? (cfg.ipBlocking.hardBanMs     ?? 24 * 60 * 60000)
    : (cfg.ipBlocking.banDurationMs ?? 2  * 60 * 60000);

  store.ban(ip, reason, duration);
  logger.critical('auto_banned', { ip, reason, violations, banCount: banCount + 1, durationMin: Math.ceil(duration / 60000) });

  const { autoBlockCloudflare } = require('./securityLogger');
  await autoBlockCloudflare(ip, reason);
}

module.exports = {
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
  getRealIp,
};
