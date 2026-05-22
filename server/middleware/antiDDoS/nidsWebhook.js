const axios = require('axios');

// Lấy URL từ biến môi trường (Render) hoặc dùng local fallback
const NIDS_API_URL = process.env.NIDS_WEBHOOK_URL || 'http://localhost:5005/api/logs';

async function sendAlertToNIDS(ip, path, description, requestData = {}) {
  // Use local fallback if env is missing
  const targetUrl = process.env.NIDS_WEBHOOK_URL || 'http://localhost:5005/api/logs';
  
  try {
    const payload = {
      ip: ip || '::1',
      path: path || '/',
      description: description || 'No description',
      status: requestData.status || 'NORMAL',
      
      // ML Features mapping (aligned with flask_app requirements)
      port:       parseInt(requestData.port)       || 80,
      duration:   parseFloat(requestData.duration) || 1.0,
      src_bytes:  parseFloat(requestData.srcBytes) || 800,
      bwd_packets: parseInt(requestData.bwdPackets) || 1,
      fwd_packets: parseInt(requestData.fwdPackets) || 2,
      pkt_len_mean: parseFloat(requestData.pktLenMean) || 6,
      syn_count:   parseInt(requestData.synCount)   || 0,
      win_bytes:   parseInt(requestData.winBytes)   || 8192
    };

    console.log(`\x1b[36m[NIDS Webhook]\x1b[0m Sending: ${payload.ip} -> ${payload.path} to ${targetUrl}`);
    const response = await axios.post(targetUrl, payload, { timeout: 3000 });
    console.log(`\x1b[32m[NIDS Webhook Success]\x1b[0m Status: ${response.data.status}`);
    return response.data;
  } catch (error) {
    console.log(`\x1b[31m[NIDS Webhook Failed]\x1b[0m ${error.message} (Target: ${targetUrl})`);
    return null;
  }
}

module.exports = { sendAlertToNIDS };
