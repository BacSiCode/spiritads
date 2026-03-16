// ============================================================
//  server/middleware/antiddos/behaviorEngine.js
//  Chống: Low-and-Slow DDoS, IP rotation dưới threshold,
//         Container attack với IP sạch
// ============================================================

// ══════════════════════════════════════════════════════════════
//  SLIDING WINDOW COUNTER — đếm chính xác hơn fixed window
// ══════════════════════════════════════════════════════════════
class SlidingWindow {
  constructor(windowMs, buckets = 10) {
    this.windowMs   = windowMs;
    this.buckets    = buckets;
    this.bucketMs   = windowMs / buckets;
    this.data       = new Map(); // key → Array(buckets)
  }

  increment(key) {
    const now        = Date.now();
    const bucketIdx  = Math.floor((now % this.windowMs) / this.bucketMs);
    if (!this.data.has(key)) this.data.set(key, new Array(this.buckets).fill({ count: 0, time: 0 }));

    const arr = this.data.get(key);
    // Reset bucket cũ nếu đã hết window
    if (now - arr[bucketIdx].time > this.windowMs) {
      arr[bucketIdx] = { count: 0, time: now };
    }
    arr[bucketIdx].count++;
    return this.getCount(key);
  }

  getCount(key) {
    const now = Date.now();
    const arr = this.data.get(key);
    if (!arr) return 0;
    return arr.reduce((sum, b) => sum + (now - b.time < this.windowMs ? b.count : 0), 0);
  }

  cleanup() {
    const now = Date.now();
    for (const [key, arr] of this.data.entries()) {
      const total = arr.reduce((s, b) => s + (now - b.time < this.windowMs ? b.count : 0), 0);
      if (total === 0) this.data.delete(key);
    }
  }
}

// ══════════════════════════════════════════════════════════════
//  BEHAVIOR SCORE ENGINE
//  Mỗi IP có điểm score 0-100, càng cao càng nguy hiểm
//  → Không cần trigger threshold cứng
// ══════════════════════════════════════════════════════════════
class BehaviorEngine {
  constructor() {
    // Score map: ip → { score, history, firstSeen, lastSeen }
    this.scores       = new Map();
    this.patterns     = new Map(); // ip → request pattern data

    // Sliding windows cho nhiều mốc thời gian
    this.win10s  = new SlidingWindow(10  * 1000, 5);   // 10 giây
    this.win1m   = new SlidingWindow(60  * 1000, 10);  // 1 phút
    this.win5m   = new SlidingWindow(5 * 60000,  10);  // 5 phút
    this.win1h   = new SlidingWindow(60 * 60000, 12);  // 1 giờ

    // Global windows
    this.globalWin1m = new SlidingWindow(60000, 10);
    this.globalWin5m = new SlidingWindow(5 * 60000, 10);

    // Subnet tracking
    this.subnetScores = new Map(); // subnet/24 → cumulativeScore

    setInterval(() => this._cleanup(), 10 * 60000);
  }

  // ── Phân tích request và tính score ──────────────────────────
  analyze(req, ip) {
    const ua      = req.headers['user-agent'] || '';
    const path    = req.path;
    const method  = req.method;
    const now     = Date.now();

    // Cập nhật sliding windows
    const c10s = this.win10s.increment(ip);
    const c1m  = this.win1m.increment(ip);
    const c5m  = this.win5m.increment(ip);
    const c1h  = this.win1h.increment(ip);

    this.globalWin1m.increment('__global__');
    this.globalWin5m.increment('__global__');

    // Khởi tạo pattern data
    if (!this.patterns.has(ip)) {
      this.patterns.set(ip, {
        firstSeen:    now,
        paths:        [],
        methods:      [],
        uas:          new Set(),
        intervals:    [],
        lastReqTime:  now,
        score:        0,
        scoreHistory: [],
      });
    }

    const p = this.patterns.get(ip);

    // Tính interval giữa các request
    const interval = now - p.lastReqTime;
    p.lastReqTime  = now;
    if (p.intervals.length < 50) p.intervals.push(interval);
    else { p.intervals.shift(); p.intervals.push(interval); }

    p.paths.push(path);
    if (p.paths.length > 50) p.paths.shift();
    p.uas.add(ua.slice(0, 80));

    // ── Tính điểm nguy hiểm ──────────────────────────────────
    let score = 0;

    // 1. Tốc độ request (0-30 điểm)
    if (c10s  > 5)  score += 10;   // > 5 req/10s = đáng ngờ
    if (c10s  > 10) score += 10;   // > 10 req/10s = nguy hiểm
    if (c1m   > 30) score += 10;   // > 30 req/phút = threshold thấp
    if (c1m   > 40) score += 10;   // > 40 req/phút
    if (c5m   > 100) score += 10;  // > 100 req/5 phút
    if (c1h   > 500) score += 10;  // > 500 req/giờ

    // 2. Pattern đều đặn bất thường (bot gửi đều nhau) (0-20 điểm)
    if (p.intervals.length >= 5) {
      const avg      = p.intervals.reduce((a, b) => a + b, 0) / p.intervals.length;
      const variance = p.intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / p.intervals.length;
      const stdDev   = Math.sqrt(variance);
      // Bot thường có stdDev rất thấp (request đều đặn)
      if (stdDev < 100 && avg < 2000 && p.intervals.length >= 10) score += 15;
      if (stdDev < 50  && avg < 1000 && p.intervals.length >= 10) score += 5;
    }

    // 3. Path lặp lại (bot thường tấn công 1 endpoint) (0-15 điểm)
    if (p.paths.length >= 10) {
      const pathCounts = {};
      p.paths.forEach(pt => pathCounts[pt] = (pathCounts[pt] || 0) + 1);
      const maxPathRepeat = Math.max(...Object.values(pathCounts));
      const repeatRatio   = maxPathRepeat / p.paths.length;
      if (repeatRatio > 0.8) score += 15;  // 80%+ request vào cùng 1 path
      else if (repeatRatio > 0.6) score += 8;
    }

    // 4. Headers thiếu (0-15 điểm)
    if (!req.headers['accept'])           score += 5;
    if (!req.headers['accept-language'])  score += 5;
    if (!req.headers['accept-encoding'])  score += 5;

    // 5. UA robot (0-10 điểm)
    const robotUas = ['python','java','go-http','axios','node-fetch','got/','undici'];
    if (robotUas.some(r => ua.toLowerCase().includes(r))) score += 10;

    // 6. Thời gian hoạt động bất thường (0-10 điểm)
    // Bot thường chạy 24/7, không có pattern nghỉ
    const hour = new Date().getHours();
    if (c5m > 50 && (hour >= 1 && hour <= 5)) score += 10; // tấn công ban đêm

    // Lưu score
    p.score = Math.min(score, 100);
    p.scoreHistory.push({ time: now, score: p.score });
    if (p.scoreHistory.length > 20) p.scoreHistory.shift();

    this.scores.set(ip, p.score);

    // Cộng dồn vào subnet score
    const subnet = ip.split('.').slice(0, 3).join('.');
    const subScore = (this.subnetScores.get(subnet) ?? 0) + (score > 30 ? 1 : 0);
    this.subnetScores.set(subnet, subScore);

    return {
      score:       p.score,
      c10s, c1m, c5m, c1h,
      subnet,
      subnetScore: subScore,
      intervals:   p.intervals.slice(-5),
    };
  }

  getScore(ip) { return this.scores.get(ip) ?? 0; }

  getSubnetScore(subnet) { return this.subnetScores.get(subnet) ?? 0; }

  _cleanup() {
    this.win10s.cleanup();
    this.win1m.cleanup();
    this.win5m.cleanup();
    this.win1h.cleanup();
    const now = Date.now();
    for (const [ip, p] of this.patterns.entries()) {
      if (now - p.lastReqTime > 30 * 60000) {
        this.patterns.delete(ip);
        this.scores.delete(ip);
      }
    }
    for (const [subnet] of this.subnetScores.entries()) {
      if ((this.subnetScores.get(subnet) ?? 0) === 0) this.subnetScores.delete(subnet);
    }
  }

  // Stats cho monitor
  topSuspicious(n = 10) {
    return [...this.scores.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([ip, score]) => {
        const p = this.patterns.get(ip);
        return {
          ip, score,
          c1m:      this.win1m.getCount(ip),
          c1h:      this.win1h.getCount(ip),
          firstSeen: p?.firstSeen ? new Date(p.firstSeen).toLocaleTimeString('vi-VN') : '?',
        };
      });
  }
}

module.exports = new BehaviorEngine();
