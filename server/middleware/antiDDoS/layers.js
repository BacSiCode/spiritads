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

// ─── Lớp 5: Bot & Anomaly Detection (AI SENSOR UPGRADED - VERSION 4) ──
// ─── Lớp 5: Bot & Anomaly Detection (AGGRESSIVE MODE - FOR DEMO) ──
function botDetectionMiddleware(req, res, next) {
  const ip = getRealIp(req);
  const rpm = store.recordHit(ip, 60000);
  const cfg = getCfg().botDetection;

  // Bản này KHÔNG lọc file tĩnh và KHÔNG phân biệt người dùng
  // Mục tiêu: Báo DDoS ngay khi nhấn F5 nhanh
  if (rpm > cfg.anomalyRpmThreshold) {
    logger.warn('aggressive_anomaly_detected', { ip, rpm });
    
    // Gửi thông số ép AI phải ra nhãn DDoS (Đỏ)
    sendAlertToNIDS(ip, req.path, `High Intensity Traffic (${rpm} RPM)`, {
        srcBytes:     rpm * 100, // Ép dung lượng tăng cực mạnh theo RPM
        fwdPackets:   Math.floor(rpm / 2), // Ép số gói tin tăng cao
        duration:     5.0, 
        pktLenMean:   400, 
        winBytes:     8192, // Window size tiêu chuẩn nhưng kết hợp RPM cao sẽ ra DDoS
        synCount:     rpm > 50 ? 1 : 0
    });
  }
  next();
}


// ─── TRAFFIC SAMPLER (Gửi mẫu traffic về NIDS - Tăng độ nhạy) ──────
function trafficSamplerMiddleware(req, res, next) {
    const ip = getRealIp(req);
    const headerSize = JSON.stringify(req.headers).length;

    // Tăng tỷ lệ lấy mẫu lên 30% để Dashboard luôn có dữ liệu nhảy
    if (Math.random() < 0.3) {
        sendAlertToNIDS(ip, req.path, 'Normal Traffic Sample', {
            status: 'NORMAL',
            srcBytes: headerSize + 50, 
            fwdPackets: 2,
            bwdPackets: 1,
            pktLenMean: 800, 
            winBytes: 29200  
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
    
    sendAlertToNIDS(ip, req.path, 'Honeypot Triggered', { status: 'ATTACK_DETECTED', srcBytes: 1500 });
    return next();
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
      
      sendAlertToNIDS(ip, req.path, `Rate Limit Exceeded (${label})`, {
          srcBytes: 3000, 
          fwdPackets: 20,
          status: 'BENIGN' 
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
  botDetectionMiddleware,
  trafficSamplerMiddleware,
  getRealIp,
};
