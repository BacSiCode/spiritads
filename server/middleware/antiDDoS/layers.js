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

// ─── Lớp 5: Bot & Anomaly Detection (AI SENSOR UPGRADED) ──────
function botDetectionMiddleware(req, res, next) {
  const ip = getRealIp(req);
  const rpm = store.trackRpm(ip);
  const cfg = getCfg().botDetection;

  // Lấy dữ liệu THẬT từ request (Cảm biến thực thụ)
  const headerSize = JSON.stringify(req.headers).length;
  const bodySize = req.headers['content-length'] ? parseInt(req.headers['content-length']) : 0;
  const totalRealBytes = headerSize + bodySize;
  const startTime = req._startTime || Date.now();
  const realDuration = (Date.now() - startTime) / 1000; // Đổi ra giây

  if (rpm > cfg.anomalyRpmThreshold) {
    logger.warn('anomaly_detected', { ip, rpm, bytes: totalRealBytes });
    
    // Gửi DỮ LIỆU THẬT về AI (Không dùng công thức RPM giả lập nữa)
    sendAlertToNIDS(ip, req.path, `Suspicious Traffic (${rpm} RPM)`, {
        src_bytes:  totalRealBytes,
        fwd_packets: rpm > 100 ? 5 : 2, // Giả lập số packet dựa trên tải trọng
        duration:  realDuration > 0 ? realDuration : 0.001,
        pkt_len_mean: Math.min(totalRealBytes / 2, 1200),
        win_bytes:  29200
    });
  }
  next();
}

// ─── TRAFFIC SAMPLER (Gửi mẫu traffic thật về NIDS) ───────────
function trafficSamplerMiddleware(req, res, next) {
    const ip = getRealIp(req);
    // Lấy dữ liệu THẬT của người dùng bình thường
    const headerSize = JSON.stringify(req.headers).length;
    const bodySize = req.headers['content-length'] ? parseInt(req.headers['content-length']) : 0;
    const totalRealBytes = headerSize + bodySize;

    if (Math.random() < 0.05) {
        sendAlertToNIDS(ip, req.path, 'Normal Traffic Sample', {
            status: 'NORMAL',
            srcBytes: totalRealBytes, 
            fwdPackets: 2,
            bwdPackets: 1,
            pktLenMean: Math.min(totalRealBytes / 2, 60),
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
    
    // Gửi về NIDS với nhãn gán sẵn là ATTACK vì đây là bẫy
    sendAlertToNIDS(ip, req.path, 'Honeypot Triggered', { status: 'ATTACK_DETECTED', srcBytes: 1500 });
    return next();
  }
  next();
}

// ─── LAYER 2 - Bot Detection / Anomaly (AI FEEDER) ───────
function botDetectionMiddleware(req, res, next) {
  const cfg = getCfg();
  if (!cfg.botDetection?.enabled) return next();

  const ip = getRealIp(req);
  const rpm = store.recordHit(ip, cfg.botDetection.anomalyWindowMs || 60000);
  const threshold = cfg.botDetection.anomalyRpmThreshold || 200;

  // Nếu RPM vượt ngưỡng, gửi dữ liệu "nghi vấn" về cho AI thẩm định
  if (rpm > threshold) {
    logger.warn('anomaly_detected', { ip, rpm });
    
    // Gửi DATA thô về, để AI (Decision Tree) tự quyết định status
    sendAlertToNIDS(ip, req.path, `Suspicious Traffic (${rpm} RPM)`, {
        srcBytes:  rpm * 10,  // Giả lập traffic tăng cao
        fwdPackets: Math.floor(rpm / 10),
        duration:  5.0,
        synCount:  rpm > 500 ? 1 : 0
    });
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
  botDetectionMiddleware,
  trafficSamplerMiddleware,
  getRealIp,
};
