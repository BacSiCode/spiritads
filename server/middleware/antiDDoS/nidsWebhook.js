const axios = require('axios');

// Lấy URL từ biến môi trường (Render) hoặc dùng local fallback
const NIDS_API_URL = process.env.NIDS_WEBHOOK_URL || 'http://192.168.1.29:5000/api/logs';

async function sendAlertToNIDS(ip, path, description, requestData = {}) {
  // Nếu chưa cấu hình URL thực tế và đang chạy trên server production thì bỏ qua
  if (!process.env.NIDS_WEBHOOK_URL && process.env.NODE_ENV === 'production') {
    return;
  }
  try {
    const payload = {
      ip: ip,
      path: path,
      status: 'ATTACK_DETECTED',
      protocol: 'tcp',
      service: 'http',
      duration: requestData.duration || 1.0,
      src_bytes: requestData.srcBytes || 800,
      dst_bytes: requestData.dstBytes || 1200,
      description: description
    };
    await axios.post(NIDS_API_URL, payload, { timeout: 3000 });
  } catch (error) {
    // Ignore errors so website won't stall if NIDS is offline
    console.log('[NIDS Webhook Failed]', error.message);
  }
}

module.exports = { sendAlertToNIDS };
