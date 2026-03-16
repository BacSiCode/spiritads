// ============================================================
//  server/middleware/antiddos/fragmentDetector.js
//  Phát hiện: Packet fragmentation, chunked body attack,
//             HTTP smuggling, slow body attack
// ============================================================

class FragmentDetector {
  constructor() {
    // Track các session đang nhận data (ip → session info)
    this.sessions   = new Map();
    // Track pattern gửi chunked từ cùng IP
    this.chunkStats = new Map(); // ip → { totalChunks, totalRequests, suspiciousCount }

    setInterval(() => this._cleanup(), 5 * 60000);
  }

  // ── Phân tích request có dấu hiệu fragmentation ────────────
  analyzeRequest(req, ip) {
    const flags  = [];
    let   score  = 0;

    // 1. Transfer-Encoding: chunked với body nhỏ = suspicious
    const te = req.headers['transfer-encoding'];
    if (te && te.toLowerCase().includes('chunked')) {
      const contentLength = parseInt(req.headers['content-length'] ?? '0');
      if (contentLength > 0 && contentLength < 100) {
        score += 20;
        flags.push(`tiny_chunked_body:${contentLength}b`);
      }
      // Track chunked requests từ IP này
      this._trackChunk(ip);
      const chunkData = this.chunkStats.get(ip);
      if (chunkData && chunkData.totalChunks > 20) {
        score += 15;
        flags.push(`many_chunked:${chunkData.totalChunks}`);
      }
    }

    // 2. Content-Length bất thường nhỏ với nhiều request
    const cl = parseInt(req.headers['content-length'] ?? '-1');
    if (cl >= 0 && cl < 20 && req.method === 'POST') {
      score += 15;
      flags.push(`tiny_post_body:${cl}b`);
    }

    // 3. Expect: 100-continue thường dùng để probe server
    if (req.headers['expect'] === '100-continue') {
      score += 10;
      flags.push('expect_100_continue');
    }

    // 4. Content-Type không khớp với path
    const ct   = req.headers['content-type'] || '';
    const path = req.path;
    if (req.method === 'POST' && !ct && path.startsWith('/api/')) {
      score += 10;
      flags.push('post_without_content_type');
    }

    // 5. Range header trên non-static path (HTTP range attack)
    if (req.headers['range'] && path.startsWith('/api/')) {
      score += 25;
      flags.push('range_header_on_api');
    }

    // 6. HTTP method bất thường
    const normalMethods = ['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'];
    if (!normalMethods.includes(req.method)) {
      score += 30;
      flags.push(`unusual_method:${req.method}`);
    }

    // 7. Path traversal patterns
    if (path.includes('../') || path.includes('..\\') || path.includes('%2e%2e')) {
      score += 40;
      flags.push('path_traversal');
    }

    // 8. Double encoding
    if (path.includes('%25') || path.includes('%2525')) {
      score += 35;
      flags.push('double_encoding');
    }

    // 9. Null bytes
    if (path.includes('\x00') || path.includes('%00')) {
      score += 50;
      flags.push('null_bytes');
    }

    return { score, flags, isFragmented: score >= 30 };
  }

  // ── Theo dõi body đang nhận (slow body attack) ─────────────
  trackBodyReceiving(req, ip) {
    const sessionKey = `${ip}:${Date.now()}`;
    const startTime  = Date.now();
    const contentLen = parseInt(req.headers['content-length'] ?? '0');

    if (contentLen === 0) return;

    this.sessions.set(sessionKey, { ip, startTime, contentLen, received: 0 });

    let received = 0;
    req.on('data', (chunk) => {
      received += chunk.length;
      const session = this.sessions.get(sessionKey);
      if (session) session.received = received;
    });

    req.on('end', () => {
      const session   = this.sessions.get(sessionKey);
      const elapsed   = Date.now() - startTime;
      this.sessions.delete(sessionKey);

      // Nếu nhận rất chậm (< 1KB/s) = slow body attack
      if (session && elapsed > 5000 && received > 0) {
        const bytesPerSec = (received / elapsed) * 1000;
        if (bytesPerSec < 1024) { // < 1 KB/s
          return { slowBody: true, bytesPerSec, elapsed };
        }
      }
    });
  }

  _trackChunk(ip) {
    const data = this.chunkStats.get(ip) ?? { totalChunks: 0, firstSeen: Date.now() };
    data.totalChunks++;
    this.chunkStats.set(ip, data);
  }

  getChunkStats(ip) { return this.chunkStats.get(ip) ?? null; }

  _cleanup() {
    const now = Date.now();
    // Xóa session cũ hơn 2 phút
    for (const [key, s] of this.sessions.entries()) {
      if (now - s.startTime > 2 * 60000) this.sessions.delete(key);
    }
    // Xóa chunk stats cũ hơn 10 phút
    for (const [ip, data] of this.chunkStats.entries()) {
      if (now - data.firstSeen > 10 * 60000) this.chunkStats.delete(ip);
    }
  }
}

module.exports = new FragmentDetector();
