// ============================================================
//  server/middleware/antiddos/ipStore.js - In-Memory Storage
// ============================================================

class IPStore {
    constructor() {
      this.violations = new Map(); // ip -> count
      this.bans = new Map();       // ip -> { reason, expiresAt, banCount }
      this.connections = new Map(); // ip -> count
      this.hits = new Map();        // ip -> [{ timestamp }]
      this.attacks = [];            // recent attack logs
      this.totalBlocked = 0;
  
      // Định kỳ dọn dẹp bộ nhớ (10 phút một lần)
      setInterval(() => this.cleanup(), 10 * 60 * 1000);
    }
  
    // --- Violation & Ban Logic ---
    addViolation(ip) {
      const count = (this.violations.get(ip) || 0) + 1;
      this.violations.set(ip, count);
      return count;
    }
  
    getViolations(ip) {
      return this.violations.get(ip) || 0;
    }
  
    ban(ip, reason, durationMs) {
      const info = this.bans.get(ip) || { banCount: 0 };
      this.bans.set(ip, {
        reason,
        expiresAt: Date.now() + durationMs,
        banCount: info.banCount + 1
      });
      // Khi đã ban thì reset số lần vi phạm để tính lại từ đầu sau khi hết ban
      this.violations.delete(ip);
    }
  
    unban(ip) {
      this.bans.delete(ip);
    }
  
    isBanned(ip) {
      const info = this.bans.get(ip);
      if (!info) return false;
      if (Date.now() > info.expiresAt) {
        this.bans.delete(ip);
        return false;
      }
      return true;
    }
  
    getBanInfo(ip) {
      return this.bans.get(ip);
    }
  
    getBanCount(ip) {
      return this.bans.get(ip)?.banCount || 0;
    }
  
    // --- Connection Tracking ---
    openConn(ip) {
      const count = (this.connections.get(ip) || 0) + 1;
      this.connections.set(ip, count);
      return count;
    }
  
    closeConn(ip) {
      const count = (this.connections.get(ip) || 0) - 1;
      if (count <= 0) this.connections.delete(ip);
      else this.connections.set(ip, count);
    }
  
    // --- Traffic Analysis (RPM) ---
    recordHit(ip, windowMs) {
      const now = Date.now();
      let userHits = this.hits.get(ip) || [];
      userHits = userHits.filter(h => now - h.timestamp < windowMs);
      userHits.push({ timestamp: now });
      this.hits.set(ip, userHits);
      return userHits.length;
    }
  
    // --- Logging ---
    logAttack(ip, type, detail) {
      this.attacks.unshift({
        time: new Date().toISOString(),
        ip,
        type,
        detail
      });
      if (this.attacks.length > 100) this.attacks.pop();
    }
  
    // --- Maintenance ---
    cleanup() {
      const now = Date.now();
      // Xóa các IP đã hết hạn ban
      for (const [ip, info] of this.bans.entries()) {
        if (now > info.expiresAt) this.bans.delete(ip);
      }
      // Xóa các IP lâu không hoạt động (> 1 giờ)
      if (this.violations.size > 5000) this.violations.clear();
      if (this.hits.size > 5000) this.hits.clear();
    }
  
    stats() {
      return {
        activeBans: this.bans.size,
        totalBlocked: this.totalBlocked,
        recentAttacks: this.attacks,
        topOffenders: Array.from(this.bans.entries())
          .sort((a, b) => b[1].banCount - a[1].banCount)
          .slice(0, 10)
          .map(([ip, info]) => ({ ip, ...info }))
      };
    }
  }
  
  module.exports = new IPStore();
