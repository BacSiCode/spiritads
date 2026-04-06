// ============================================================
//  server/middleware/antiddos/ipStore.js  — Enterprise Grade
// ============================================================

class IpStore {
  constructor() {
    this.blacklist     = new Map(); // ip → { bannedAt, expiresAt, reason, violations, banCount }
    this.hitMap        = new Map(); // ip → [timestamps]
    this.connMap       = new Map(); // ip → number
    this.violationMap  = new Map(); // ip → number
    this.attackLog     = [];        // { time, ip, type, detail }
    this.totalBlocked  = 0;

    this._cleanupInterval = setInterval(() => this._cleanup(), 5 * 60 * 1000);
    this._cleanupInterval.unref?.();
  }

  // ── Blacklist ──────────────────────────────────────────────

  ban(ip, reason = 'auto', durationMs = 30 * 60 * 1000) {
    const current  = this.blacklist.get(ip);
    const banCount = (current?.banCount ?? 0) + 1;
    this.blacklist.set(ip, {
      bannedAt:   Date.now(),
      expiresAt:  Date.now() + durationMs,
      reason,
      violations: this.violationMap.get(ip) ?? 0,
      banCount,
    });
    this.totalBlocked++;
  }

  unban(ip) {
    this.blacklist.delete(ip);
    this.violationMap.delete(ip);
  }

  isBanned(ip) {
    const e = this.blacklist.get(ip);
    if (!e) return false;
    if (Date.now() > e.expiresAt) { this.blacklist.delete(ip); return false; }
    return true;
  }

  getBanInfo(ip) { return this.blacklist.get(ip) ?? null; }

  getBanCount(ip) { return this.blacklist.get(ip)?.banCount ?? 0; }

  // ── Violations ─────────────────────────────────────────────

  addViolation(ip) {
    const v = (this.violationMap.get(ip) ?? 0) + 1;
    this.violationMap.set(ip, v);
    return v;
  }

  getViolations(ip) { return this.violationMap.get(ip) ?? 0; }

  // ── Hit tracking (sliding window) ──────────────────────────

  recordHit(ip, windowMs = 60000) {
    const now  = Date.now();
    const hits = (this.hitMap.get(ip) ?? []).filter(t => now - t < windowMs);
    hits.push(now);
    this.hitMap.set(ip, hits);
    return hits.length;
  }

  // ── Connections ────────────────────────────────────────────

  openConn(ip) {
    const c = (this.connMap.get(ip) ?? 0) + 1;
    this.connMap.set(ip, c);
    return c;
  }

  closeConn(ip) {
    const c = Math.max(0, (this.connMap.get(ip) ?? 1) - 1);
    if (c === 0) this.connMap.delete(ip);
    else this.connMap.set(ip, c);
  }

  // ── Attack log ─────────────────────────────────────────────

  logAttack(ip, type, detail = '') {
    this.attackLog.push({ time: new Date(), ip, type, detail });
    if (this.attackLog.length > 500) this.attackLog.shift();
  }

  // ── Stats ──────────────────────────────────────────────────

  stats() {
    return {
      bannedIPs:    this.blacklist.size,
      trackedIPs:   this.hitMap.size,
      activeConns:  [...this.connMap.values()].reduce((a, b) => a + b, 0),
      totalBlocked: this.totalBlocked,
      topOffenders: [...this.blacklist.entries()]
        .sort((a, b) => b[1].violations - a[1].violations)
        .slice(0, 10)
        .map(([ip, info]) => ({ ip, ...info })),
      recentAttacks: this.attackLog.slice(-20).reverse(),
    };
  }

  // ── Cleanup ────────────────────────────────────────────────

  _cleanup() {
    const now = Date.now();
    for (const [ip, info] of this.blacklist.entries())
      if (now > info.expiresAt) this.blacklist.delete(ip);
    for (const [ip, hits] of this.hitMap.entries()) {
      const fresh = hits.filter(t => now - t < 5 * 60 * 1000);
      if (!fresh.length) this.hitMap.delete(ip);
      else this.hitMap.set(ip, fresh);
    }
  }

  destroy() { clearInterval(this._cleanupInterval); }
}

module.exports = new IpStore();
