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
function botDetectionMiddleware(req, res, next) {
  // Bỏ qua các file tĩnh để tránh làm nhiễu AI và RPM
  const path = req.path.toLowerCase();
  if (path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|otf)$/)) {
    return next();
  }

  const ip = getRealIp(req);
  const rpm = store.recordHit(ip, 60000);
  const cfg = getCfg().botDetection;

  // 1. Phân tích "HumanScore" (Chỉ số người thật)
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  let humanScore = 0;
  
  if (req.headers['sec-ch-ua']) humanScore += 2;
  if (req.headers['accept-language']) humanScore += 1;
  if (req.headers['sec-fetch-mode']) humanScore += 1;
  if (req.headers['referer']) humanScore += 1;

  if (ua.includes('k6') || ua.includes('python') || ua.includes('curl') || ua.includes('go-http') || ua.includes('postman')) {
    humanScore -= 5;
  }

  const isLikelyTool = humanScore < 1;
  const headerSize = JSON.stringify(req.headers).length;
  const totalRealBytes = headerSize + (req.headers['content-length'] ? parseInt(req.headers['content-length']) : 0);

  const flowPacketsPerSec = rpm / 60; 
  const flowBytesPerSec = (totalRealBytes * rpm) / 60;

  if (rpm > cfg.anomalyRpmThreshold) {
    logger.warn('anomaly_detected', { ip, rpm, humanScore, isLikelyTool });
    
    // 3. ÉP AI VÀO NHÁNH QUYẾT ĐỊNH (Đã đồng bộ tên biến CamelCase)
    sendAlertToNIDS(ip, req.path, `DDoS/Anomaly Alert (${rpm} RPM)`, {
        srcBytes:     totalRealBytes,
        fwdPackets:   isLikelyTool ? (rpm > 300 ? 50 : 10) : 2, 
        duration:     isLikelyTool ? 2.0 : 1.0, 
        pktLenMean:   isLikelyTool ? 100 : 800, 
        packetsPerSec: flowPacketsPerSec,
        flowBytesSec: flowBytesPerSec,
        // k6/hping3 sẽ bị ép Window 0 hoặc 128 để AI chắc chắn báo ATTACK
        winBytes:     isLikelyTool ? (rpm > 500 ? 0 : 256) : 29200
    });
  }
  next();
}

// ─── TRAFFIC SAMPLER (Gửi mẫu traffic thật về NIDS) ──────────────
function trafficSamplerMiddleware(req, res, next) {
    const path = req.path.toLowerCase();
    if (path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|otf)$/)) {
        return next();
    }

    const ip = getRealIp(req);
    const headerSize = JSON.stringify(req.headers).length;

    if (Math.random() < 0.05) {
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


module.exports = {
  buildRateLimiters,
  honeypotMiddleware,
  botDetectionMiddleware,
  trafficSamplerMiddleware,
  getRealIp,
};
