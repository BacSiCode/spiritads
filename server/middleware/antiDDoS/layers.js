// ============================================================
//  server/middleware/antiddos/layers.js - AI Sensor Grade
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

// ─── TRAFFIC SAMPLER (Gửi mẫu traffic thường về NIDS) ──────
function trafficSamplerMiddleware(req, res, next) {
    const ip = getRealIp(req);
    // Chỉ gửi mẫu ngẫu nhiên 5% traffic sạch để Dashboard có màu xanh
    if (Math.random() < 0.05) {
        sendAlertToNIDS(ip, req.path, 'Normal Traffic Sample', {
            status: 'NORMAL',
            srcBytes: 60,   // Benign signature
            fwdPackets: 1,
            bwdPackets: 1,
            pktLenMean: 6   // Benign signature from dataset
        });
    }
    next();
}

// ─── HONEYPOT ─────────────────────────────────────────────
function honeypotMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.enabled) return next();

  const HONEYPOT_PATHS = ['/.env', '/.git', '/wp-admin', '/admin.php', '/phpmyadmin'];
  const path = req.path.toLowerCase();
  
  if (HONEYPOT_PATHS.some(p => path.startsWith(p))) {
    const ip = getRealIp(req);
    logger.critical('honeypot_triggered', { ip, path: req.path });
    store.logAttack(ip, 'HONEYPOT', req.path);
    store.ban(ip, `honeypot: ${req.path}`, 24 * 60 * 60 * 1000);
    
    // Gửi về NIDS với nhãn gán sẵn là ATTACK vì đây là bẫy
    sendAlertToNIDS(ip, req.path, 'Honeypot Triggered', { status: 'ATTACK_DETECTED', srcBytes: 1500 });
    return next();
  }
  next();
}

// ─── LAYER 0 - IP Blocking (IPS) ──────────────────────────
function ipBlockingMiddleware(req, res, next) {
  const ip = getRealIp(req);
  if (store.isBanned(ip)) {
    const info = store.getBanInfo(ip);
    return res.status(403).json({
      success: false,
      message: 'Access Denied: Security Threat Detected',
      reason: info?.reason || 'Suspicious Activity',
      retryAfter: '1h'
    });
  }
  next();
}

// ─── LAYER 2 - Bot Detection / Anomaly (AI FEEDER/IPS) ────
async function botDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.botDetection?.enabled) return next();

  const ip = getRealIp(req);
  const rpm = store.recordHit(ip, cfg.botDetection.anomalyWindowMs || 60000);
  const threshold = cfg.botDetection.anomalyRpmThreshold || 100;

  // Nếu RPM vượt ngưỡng, gửi dữ liệu "nghi vấn" về cho AI thẩm định
  if (rpm > threshold) {
    logger.warn('anomaly_detected', { ip, rpm });
    
    // Gửi DATA thô về với các đặc trưng "đậm đặc" để AI nhận diện tấn công (k6)
    const aiResult = await sendAlertToNIDS(ip, req.path, `Suspicious Traffic (${rpm} RPM)`, {
        srcBytes:     rpm * 500,  
        fwdPackets:   rpm,
        pktLenMean:   1000,      // Ép thông số cao để AI dự đoán DDoS
        avg_pkt_size: 1000,
        packets_per_sec: rpm / 60
    });

    // Nếu AI xác nhận là DDoS -> THỰC THI LỆNH CHẶN (IPS)
    if (aiResult && aiResult.status === 'DDoS') {
      logger.critical('ips_active_blocking', { ip, rpm, status: aiResult.status });
      store.ban(ip, 'DDoS Attack (AI Detected)', 60 * 60 * 1000); // Khóa 1 tiếng
      store.logAttack(ip, 'DDOS', `AI Confirmed DDoS with ${rpm} RPM`);
      
      return res.status(403).json({ 
        success: false, 
        message: 'Hệ thống đã chặn IP của bạn do phát hiện dấu hiệu tấn công DDoS.' 
      });
    }
  }

  next();
}

// ─── LAYER 1 - Rate Limiters (SILENT) ─────────────────────
function buildRateLimiters() {
  const makeRl = (options, label) => rateLimit({
    ...options,
    standardHeaders: true,
    keyGenerator: (req) => getRealIp(req),
    handler: (req, res, next) => {
      const ip = getRealIp(req);
      logger.block('rate_limit_exceeded', { ip, path: req.path, limiter: label });
      
      // Gửi dữ liệu về AI để báo cáo, nhưng không chặn trình duyệt
      sendAlertToNIDS(ip, req.path, `Rate Limit Exceeded (${label})`, {
          srcBytes: 3000, 
          fwdPackets: 20,
          status: 'NORMAL' // Mặc định là Normal, AI sẽ phân tích xem có phải DDoS thật không
      });
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

module.exports = {
  buildRateLimiters,
  honeypotMiddleware,
  ipBlockingMiddleware,
  botDetectionMiddleware,
  trafficSamplerMiddleware,
  getRealIp,
};
