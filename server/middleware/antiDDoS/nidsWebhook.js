const axios = require('axios');

// Lấy URL từ biến môi trường (Render) hoặc dùng local fallback
const NIDS_API_URL = process.env.NIDS_WEBHOOK_URL || 'http://localhost:5000/api/logs';

async function sendAlertToNIDS(ip, path, description, requestData = {}) {
  if (!process.env.NIDS_WEBHOOK_URL && process.env.NODE_ENV === 'production') {
    return;
  }
  try {
    const payload = {
      ip: ip,
      path: path,
      description: description,
      status: requestData.status || 'NORMAL', // Default to normal, let AI decide
      
      // ML Features mapping
      port:       requestData.port       || 80,
      duration:   requestData.duration   || 1.0,
      src_bytes:  requestData.srcBytes   || 800,
      bwd_packets: requestData.bwdPackets || 1,
      fwd_packets: requestData.fwdPackets || 2,
      pkt_len_mean: requestData.pktLenMean || 500,
      syn_count:   requestData.synCount   || 0,
      win_bytes:   requestData.winBytes   || 8192
    };
    await axios.post(NIDS_API_URL, payload, { timeout: 3000 });
  } catch (error) {
    console.log('[NIDS Webhook Failed]', error.message);
  }
}

module.exports = { sendAlertToNIDS };
