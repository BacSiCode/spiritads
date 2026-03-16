// ============================================================
//  server/middleware/antiddos/ipStore.js
//  In-memory store cho IP tracking, blacklist, connection count
//  Dùng Map để tốc độ O(1) — không cần Redis với traffic < 50k req/day
// ============================================================

class IpStore {
  constructor() {
    // blacklist: Map<ip, { bannedAt: number, reason: string, violations: number }>
    this.blacklist = new Map();

    // hitMap: Map<ip, number[]>  — timestamps của requests trong sliding window
    this.hitMap = new Map();

    // connMap: Map<ip, number>  — số connection đang mở
    this.connMap = new Map();

    // violationMap: Map<ip, number>  — tổng số lần vi phạm
    this.violationMap = new Map();

    // Cleanup mỗi 5 phút
    this._cleanupInterval = setInterval(() => this._cleanup(), 5 * 60 * 1000);
    this._cleanupInterval.unref?.(); // không giữ process sống nếu không có việc khác
  }

  // ── Blacklist ──────────────────────────────────────────────

  ban(ip, reason = 'auto', durationMs = 30 * 60 * 1000) {
    const current = this.blacklist.get(ip);
    this.blacklist.set(ip, {
      bannedAt:   Date.now(),
      expiresAt:  Date.now() + durationMs,
      reason,
      violations: (current?.violations ?? 0) + 1,
    });
  }

  unban(ip) {
    this.blacklist.delete(ip);
  }

  isBanned(ip) {
    const entry = this.blacklist.get(ip);
    if (!entry) return false;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.blacklist.delete(ip);
      return false;
    }
    return true;
  }

  getBanInfo(ip) {
    return this.blacklist.get(ip) ?? null;
  }

  // ── Hit tracking (sliding window) ──────────────────────────

  recordHit(ip, windowMs = 60000) {
    const now  = Date.now();
    const hits = (this.hitMap.get(ip) ?? []).filter(t => now - t < windowMs);
    hits.push(now);
    this.hitMap.set(ip, hits);
    return hits.length;
  }

  getHitCount(ip, windowMs = 60000) {
    const now  = Date.now();
    const hits = (this.hitMap.get(ip) ?? []).filter(t => now - t < windowMs);
    return hits.length;
  }

  // ── Connections ────────────────────────────────────────────

  openConn(ip) {
    this.connMap.set(ip, (this.connMap.get(ip) ?? 0) + 1);
    return this.connMap.get(ip);
  }

  closeConn(ip) {
    const c = Math.max(0, (this.connMap.get(ip) ?? 1) - 1);
    if (c === 0) this.connMap.delete(ip);
    else this.connMap.set(ip, c);
  }

  getConnCount(ip) {
    return this.connMap.get(ip) ?? 0;
  }

  // ── Violations ─────────────────────────────────────────────

  addViolation(ip) {
    const v = (this.violationMap.get(ip) ?? 0) + 1;
    this.violationMap.set(ip, v);
    return v;
  }

  getViolations(ip) {
    return this.violationMap.get(ip) ?? 0;
  }

  // ── Stats (cho monitor dashboard) ─────────────────────────

  stats() {
    return {
      bannedIPs:    this.blacklist.size,
      trackedIPs:   this.hitMap.size,
      activeConns:  [...this.connMap.values()].reduce((a, b) => a + b, 0),
      topOffenders: [...this.blacklist.entries()]
        .sort((a, b) => b[1].violations - a[1].violations)
        .slice(0, 10)
        .map(([ip, info]) => ({ ip, ...info })),
    };
  }

  // ── Internal cleanup ───────────────────────────────────────

  _cleanup() {
    const now = Date.now();

    // Xóa expired bans
    for (const [ip, info] of this.blacklist.entries()) {
      if (info.expiresAt && now > info.expiresAt) this.blacklist.delete(ip);
    }

    // Xóa stale hit windows (> 5 phút không có request)
    for (const [ip, hits] of this.hitMap.entries()) {
      const fresh = hits.filter(t => now - t < 5 * 60 * 1000);
      if (fresh.length === 0) this.hitMap.delete(ip);
      else this.hitMap.set(ip, fresh);
    }
  }

  destroy() {
    clearInterval(this._cleanupInterval);
  }
}

// Singleton — dùng chung cho toàn app
module.exports = new IpStore();
