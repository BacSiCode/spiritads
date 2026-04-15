// ============================================================
//  server/config/baomat._config.js - Cấu hình bảo mật Enterprise
// ============================================================

module.exports = {
    enabled: true, // Bật hệ thống bảo vệ
  
    // 1. Chặn IP
    ipBlocking: {
      enabled: true,
      autoBanEnabled: true,      // Tự động ban khi vi phạm nhiều lần
      banThreshold: 50,          // Số lần vi phạm tối đa trước khi ban
      banDurationMs: 3600000,    // Ban 1 tiếng cho lần đầu
      hardBanAfter: 5,           // Sau 5 lần ban tạm thời sẽ ban vĩnh viễn (24h)
      hardBanMs: 86400000,
      trustProxy: true,          // Tin tưởng Forwarded Headers từ Render/Cloudflare
      whitelist: ['127.0.0.1'],  // IP không bao giờ bị chặn
    },
  
    // 2. Tốc độ Request (Rate Limit) - Đã nới lỏng theo yêu cầu người dùng
    rateLimit: {
      enabled: true,
      global: {
        windowMs: 60000,         // 1 phút
        max: 500,                // Cho phép 500 request/phút (Nới lỏng từ 100)
      },
      api: {
        windowMs: 15 * 60000,
        max: 1000,               // API cho phép 1000 request mỗi 15 phút
      },
      auth: {
        windowMs: 15 * 60000,
        max: 50,                 // Login/Register cho phép 50 lần thử (Nới lỏng từ 20)
      },
      contact: {
        windowMs: 60 * 60000,
        max: 20,
      }
    },
  
    // 3. Bảo vệ kết nối (DDoS lớp 4)
    connectionProtection: {
      enabled: true,
      maxConnPerIp: 100,         // Tối đa 100 kết nối đồng thời (Nới lỏng từ 30)
      maxBodySizeBytes: 10485760, // 10MB
    },
  
    // 4. Phát hiện Bot và Traffic bất thường (DDoS lớp 7)
    botDetection: {
      enabled: true,
      blockMissingAccept: false, // Tắt cái này để tránh chặn các request đơn giản
      anomalyRpmThreshold: 1000, // Nới lỏng lên 1000 RPM (Từ 200) để tránh "yếu"
      anomalyWindowMs: 60000,
      blockedAgents: [
        'sqlmap', 'nikto', 'dirbuster', 'nmap', 'python-requests', 'curl'
      ]
    },
  
    // 5. Chống Request chậm (Slowloris)
    slowRequest: {
      enabled: true,
      requestTimeoutMs: 30000,   // 30 giây
    },
  
    // Cloudflare Integration (Nếu có dùng)
    cloudflare: {
      enabled: false,
      trustProxy: true,
    }
  };
