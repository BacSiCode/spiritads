// ============================================================
//  server/middleware/antiddos/securityLogger.js 
// ============================================================

const axios = require('axios');
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

async function sendTelegramAlert(level, type, data) {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) return;

    const message = `🛡 <b>[SPIRITADS SECURITY]</b>\n` +
                    `⚠️ <b>Level:</b> ${level}\n` +
                    `🔥 <b>Type:</b> ${type}\n` +
                    `🌐 <b>IP:</b> ${data.ip || 'Unknown'}\n` +
                    `📍 <b>Path:</b> ${data.path || '/'}\n` +
                    `📝 <b>Detail:</b> <pre>${JSON.stringify(data, null, 2)}</pre>\n` +
                    `⏰ <b>Time:</b> ${new Date().toLocaleString('vi-VN')}`;

    try {
        await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
            chat_id: chatId,
            text: message,
            parse_mode: 'HTML'
        });
    } catch (error) {
        console.error('[Telegram Alert Failed]', error.message);
    }
}

function writeLog(level, type, data) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        type,
        ...data
    };
    
    const line = JSON.stringify(logEntry) + '\n';
    
    // In ra console 
    const color = level === 'CRITICAL' ? '\x1b[31m' : level === 'BLOCK' ? '\x1b[33m' : '\x1b[36m';
    console.log(`${color}[SECURITY][${level}] ${type}\x1b[0m`, data);

    // Tự động báo về Telegram nếu là cảnh báo quan trọng
    if (level === 'CRITICAL' || level === 'BLOCK') {
        sendTelegramAlert(level, type, data);
    }

    // Ghi vào file 
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
            return;
        }
        // Logic thực tế gọi API Cloudflare sẽ ở đây
        sendTelegramAlert('CLOUDFARE', 'AUTO_BLOCK', { ip, reason });
    }
};

module.exports = logger;
