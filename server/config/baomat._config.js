// ============================================================
//  server/config/baomat._config.js - Cấu hình "Tàng Hình"
// ============================================================

module.exports = {
    enabled: true, 
  
    // 1. Chặn IP - Đã kích hoạt để bảo vệ server khỏi DDoS
    ipBlocking: {
      enabled: true,
      autoBanEnabled: true,
      banThreshold: 9999,
      banDurationMs: 3600000,
      hardBanAfter: 99,
      hardBanMs: 86400000,
      trustProxy: true,
      whitelist: [],
    },
  
    // 2. Tốc độ Request (Rate Limit) - Đã TẮT BLOCKING
    rateLimit: {
      enabled: false,            // Không bao giờ hiện "Quá nhiều request" nữa
      global: { windowMs: 60000, max: 10000 },
      api: { windowMs: 15 * 60000, max: 10000 },
      auth: { windowMs: 15 * 60000, max: 10000 },
      contact: { windowMs: 60 * 60000, max: 10000 }
    },
  
    // 3. Bảo vệ kết nối - Đã TẮT BLOCKING
    connectionProtection: {
      enabled: false,           // Không giới hạn kết nối đồng thời
      maxConnPerIp: 9999,
      maxBodySizeBytes: 10485760,
    },
  
    // 4. Phát hiện Traffic bất thường - Đã đẩy ngưỡng lên cực cao
    botDetection: {
      enabled: true,            // Vẫn để True để nó BÁO CÁO về NIDS cho bạn xem
      blockMissingAccept: false,
      anomalyRpmThreshold: 100,    // Hạ xuống 100 để "bắt" k6 và các tool tấn công sớm hơn
      anomalyWindowMs: 60000,
      blockedAgents: []         // Không chặn bất kỳ Agent nào
    },
  
    // 5. Chống Request chậm
    slowRequest: {
      enabled: false,           // Tắt luôn để không bị timeout khi test
      requestTimeoutMs: 60000,
    },
  
    cloudflare: {
      enabled: false,
      trustProxy: true,
    }
  };
