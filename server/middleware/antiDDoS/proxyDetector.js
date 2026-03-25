// ============================================================
//  server/middleware/antiddos/proxyDetector.js
//  Phát hiện: Proxy, VPN, Tor, Residential Proxy, Datacenter IP
// ============================================================

// ══════════════════════════════════════════════════════════════
//  PROXY HEADER SIGNATURES
//  Proxy thường để lại dấu vết trong headers
// ══════════════════════════════════════════════════════════════
const PROXY_HEADERS = [
  'x-forwarded-for',
  'x-forwarded',
  'x-cluster-client-ip',
  'forwarded-for',
  'forwarded',
  'via',
  'x-real-ip',
  'x-proxy-id',
  'mt-proxy-id',
  'x-tinyproxy',
  'x-original-url',
  'x-rewrite-url',
  'x-custom-ip-authorization',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-remote-ip',
  'x-remote-addr',
  'x-originating-ip',
  'x-wap-profile',
];

// ══════════════════════════════════════════════════════════════
//  KNOWN PROXY/VPN ASN PREFIXES
//  Residential proxy thường dùng các dải IP này
// ══════════════════════════════════════════════════════════════
const PROXY_RANGES = [
  // Tor exit nodes (common ranges)
  '185.220.', '185.107.', '185.129.',
  '195.176.', '199.249.', '162.247.',
  '185.100.', '171.25.',  '176.10.',
  // Common VPN providers
  '104.128.', '198.54.',  '23.106.',
  '45.142.',  '185.159.', '194.165.',
  // Common proxy services
  '91.108.',  '149.154.', '91.242.',
  '194.165.', '185.220.',
];

// ══════════════════════════════════════════════════════════════
//  BROWSER FINGERPRINT SCORING
//  Browser thật có nhiều headers hơn và theo thứ tự nhất định
// ══════════════════════════════════════════════════════════════
const BROWSER_REQUIRED_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'user-agent',
];

const BROWSER_HEADER_ORDER = {
  chrome: ['host','connection','cache-control','upgrade-insecure-requests','user-agent','accept','accept-encoding','accept-language'],
  firefox: ['host','user-agent','accept','accept-language','accept-encoding','connection'],
  safari: ['host','accept','user-agent','accept-language','accept-encoding','connection'],
};

class ProxyDetector {
  constructor() {
    // Cache kết quả detect (tránh re-analyze cùng IP)
    this.cache    = new Map(); // ip → { score, isProxy, reason, cachedAt }
    this.cacheTTL = 5 * 60000; // cache 5 phút

    setInterval(() => this._cleanup(), 10 * 60000);
  }

  // ── Phân tích request để detect proxy ──────────────────────
  analyze(req) {
    const ip  = this._getIp(req);
    const now = Date.now();

    // Check cache
    const cached = this.cache.get(ip);
    if (cached && now - cached.cachedAt < this.cacheTTL) return cached;

    const result = this._doAnalyze(req, ip);
    this.cache.set(ip, { ...result, cachedAt: now });
    return result;
  }

  _doAnalyze(req, ip) {
    let score   = 0;
    const flags = [];

    // ── 1. Proxy headers (0-40 điểm) ─────────────────────────
    const proxyHeadersFound = PROXY_HEADERS.filter(h => req.headers[h] !== undefined);

    // Via header = definitely proxy
    if (req.headers['via']) {
      score += 30;
      flags.push(`via_header:${req.headers['via'].slice(0,30)}`);
    }

    // Nhiều proxy headers = proxy chain
    if (proxyHeadersFound.length > 2) {
      score += proxyHeadersFound.length * 5;
      flags.push(`proxy_headers:${proxyHeadersFound.length}`);
    }

    // X-Forwarded-For có nhiều IP = proxy chain
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const ips = xff.split(',').map(s => s.trim());
      if (ips.length > 2) {
        score += 20;
        flags.push(`proxy_chain:${ips.length}_hops`);
      }
    }

    // ── 2. Known proxy IP ranges (0-50 điểm) ─────────────────
    if (PROXY_RANGES.some(r => ip.startsWith(r))) {
      score += 50;
      flags.push('known_proxy_range');
    }

    // ── 3. Browser fingerprint (0-30 điểm) ───────────────────
    const ua = (req.headers['user-agent'] || '').toLowerCase();

    // Missing browser headers
    const missingBrowserHeaders = BROWSER_REQUIRED_HEADERS.filter(h => !req.headers[h]);
    if (missingBrowserHeaders.length > 0) {
      score += missingBrowserHeaders.length * 8;
      flags.push(`missing_headers:${missingBrowserHeaders.join(',')}`);
    }

    // UA nói là Chrome nhưng thiếu headers của Chrome
    if (ua.includes('chrome') && !req.headers['accept-language']) {
      score += 25;
      flags.push('chrome_without_accept_language');
    }

    // UA nói là browser nhưng Accept header không phải HTML
    if ((ua.includes('mozilla') || ua.includes('chrome') || ua.includes('safari')) &&
        req.headers['accept'] &&
        !req.headers['accept'].includes('text/html') &&
        !req.headers['accept'].includes('*/*')) {
      score += 15;
      flags.push('browser_ua_non_html_accept');
    }

    // ── 4. Connection patterns (0-20 điểm) ───────────────────
    // Proxy thường dùng HTTP/1.0 hoặc close connection
    if (req.headers['connection'] === 'close') {
      score += 10;
      flags.push('connection_close');
    }

    // Pragma: no-cache thường là proxy artifact
    if (req.headers['pragma'] === 'no-cache' && req.headers['cache-control'] === 'no-cache') {
      score += 5;
      flags.push('proxy_cache_headers');
    }

    // ── 5. ASN pattern — datacenter IP (0-20 điểm) ────────────
    // IP bắt đầu bằng các range của datacenter phổ biến
    const dcRanges = [
      '104.', '45.', '167.', '198.', '172.', '142.',
      '157.', '162.', '185.', '188.', '193.', '194.',
      '195.', '199.', '202.', '203.', '209.', '213.',
    ];
    if (dcRanges.some(r => ip.startsWith(r))) {
      // Chỉ tính nếu có dấu hiệu khác
      if (score > 20) {
        score += 10;
        flags.push('datacenter_ip_range');
      }
    }

    const isProxy  = score >= 50;
    const isSuspect = score >= 30;

    return { ip, score, isProxy, isSuspect, flags, proxyHeadersFound };
  }

  _getIp(req) {
    if (process.env.TRUST_CF_PROXY === 'true') {
      return req.headers['cf-connecting-ip'] || req.socket?.remoteAddress || req.ip;
    }
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const first = xff.split(',')[0].trim();
      if (!this._isPrivate(first)) return first;
    }
    return (req.socket?.remoteAddress || req.ip || '0.0.0.0').replace('::ffff:', '');
  }

  _isPrivate(ip) {
    return ['127.','10.','192.168.','::1'].some(p => ip.startsWith(p));
  }

  stats() {
    return {
      cached: this.cache.size,
      proxiesDetected: [...this.cache.values()].filter(v => v.isProxy).length,
    };
  }

  _cleanup() {
    const now = Date.now();
    for (const [ip, v] of this.cache.entries()) {
      if (now - v.cachedAt > this.cacheTTL * 2) this.cache.delete(ip);
    }
  }
}

module.exports = new ProxyDetector();
