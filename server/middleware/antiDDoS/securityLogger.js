// ============================================================
//  server/middleware/antiddos/securityLogger.js 
// ============================================================

const fs = require('fs');
const path = require('path');

// Đảm bảo có thư mục logs
const logDir = path.join(__dirname, '../../../logs');
if (!fs.existsSync(logDir)) {
    try {
        fs.mkdirSync(logDir, { recursive: true });
    } catch(e) {}
}

const logFile = path.join(logDir, 'security.log');

function writeLog(level, type, data) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        type,
        ...data
    };
    
    const line = JSON.stringify(logEntry) + '\n';
    
    // In ra console để theo dõi trên Render logs
    const color = level === 'CRITICAL' ? '\x1b[31m' : level === 'BLOCK' ? '\x1b[33m' : '\x1b[36m';
    console.log(`${color}[SECURITY][${level}] ${type}\x1b[0m`, data);

    // Ghi vào file (tùy chọn, Render thường dùng stdout)
    try {
        fs.appendFileSync(logFile, line);
    } catch(e) {}
}

const logger = {
    info:     (type, data) => writeLog('INFO',     type, data),
    warn:     (type, data) => writeLog('WARN',     type, data),
    block:    (type, data) => writeLog('BLOCK',    type, data),
    critical: (type, data) => writeLog('CRITICAL', type, data),

    // Cloudflare integration placeholder
    async autoBlockCloudflare(ip, reason) {
        if (!process.env.CF_ZONE_ID || !process.env.CF_API_KEY) {
            // console.log(`[CF] Cloudflare credentials not set. Skipping block for ${ip}`);
            return;
        }
        // Logic thực tế gọi API Cloudflare sẽ ở đây
    }
};

module.exports = logger;
