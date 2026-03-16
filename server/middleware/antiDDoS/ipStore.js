// ============================================================
//  server/middleware/antiddos/ipStore.js — Container DDoS v3
// ============================================================

class IpStore {
  constructor() {
    this.blacklist    = new Map(); // ip → { expiresAt, reason, violations, banCount }
    this.hitMap       = new Map(); // ip → [timestamps]
    this.connMap      = new Map(); // ip → number
    this.violationMap = new Map(); // ip → number
    this.attackLog    = [];
    this.totalBlocked = 0;

    // ── Subnet tracking (chống container DDoS) ──────────────
    this.subnetMap    = new Map(); // subnet/24 → Set of unique IPs
    this.subnetBanned = new Map(); // subnet → { expiresAt, reason }
    this.subnetHits   = new Map(); // subnet → [timestamps]

    // ── UA fingerprint per subnet ────────────────────────────
    this.subnetUaMap  = new Map(); // subnet:uaHash → Set of IPs

    this._cleanupInterval = setInterval(() => this._cleanup(), 5 * 60 * 1000);
    this._cleanupInterval.unref?.();
  }

  // ── IP Blacklist ───────────────────────────────────────────

  ban(ip, reason = 'auto', durationMs = 2 * 60 * 60 * 1000) {
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

  getBanInfo(ip)  { return this.blacklist.get(ip) ?? null; }
  getBanCount(ip) { return this.blacklist.get(ip)?.banCount ?? 0; }

  // ── Violations ─────────────────────────────────────────────

  addViolation(ip) {
    const v = (this.violationMap.get(ip) ?? 0) + 1;
    this.violationMap.set(ip, v);
    return v;
  }
  getViolations(ip) { return this.violationMap.get(ip) ?? 0; }

  // ── Hit tracking ───────────────────────────────────────────

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

  // ── Subnet tracking (Container DDoS) ──────────────────────

  recordSubnetHit(subnet) {
    // Đếm unique IPs trong subnet/24 trong 1 phút
    const now    = Date.now();
    const key    = `subnet:${subnet}`;
    const hits   = (this.subnetHits.get(key) ?? []).filter(t => now - t < 60000);
    hits.push(now);
    this.subnetHits.set(key, hits);
    return hits.length;
  }

  banSubnet(subnet, reason, durationMs = 60 * 60 * 1000) {
    this.subnetBanned.set(subnet, {
      expiresAt: Date.now() + durationMs,
      reason,
      bannedAt: Date.now(),
    });
    this.totalBlocked++;
    console.log(`\x1b[35m🚫 SUBNET-BAN: ${subnet}.x – ${reason}\x1b[0m`);
  }

  isSubnetBanned(subnet) {
    const e = this.subnetBanned.get(subnet);
    if (!e) return false;
    if (Date.now() > e.expiresAt) { this.subnetBanned.delete(subnet); return false; }
    return true;
  }

  // ── UA fingerprint per subnet ─────────────────────────────

  recordUaInSubnet(subnet, uaHash) {
    const key = `${subnet}:${uaHash}`;
    if (!this.subnetUaMap.has(key)) this.subnetUaMap.set(key, new Set());
    // Dùng timestamp thay vì IP để tránh memory leak
    this.subnetUaMap.get(key).add(Date.now());
  }

  getUaCountInSubnet(subnet, uaHash) {
    const key  = `${subnet}:${uaHash}`;
    const hits = this.subnetUaMap.get(key);
    if (!hits) return 0;
    // Chỉ đếm trong 1 phút gần nhất
    const now = Date.now();
    const fresh = [...hits].filter(t => now - t < 60000);
    this.subnetUaMap.set(key, new Set(fresh));
    return fresh.length;
  }

  // ── Attack log ─────────────────────────────────────────────

  logAttack(ip, type, detail = '') {
    this.attackLog.push({ time: new Date(), ip, type, detail });
    if (this.attackLog.length > 500) this.attackLog.shift();
  }

  // ── Stats ──────────────────────────────────────────────────

  stats() {
    return {
      bannedIPs:      this.blacklist.size,
      bannedSubnets:  this.subnetBanned.size,
      trackedIPs:     this.hitMap.size,
      activeConns:    [...this.connMap.values()].reduce((a, b) => a + b, 0),
      totalBlocked:   this.totalBlocked,
      topOffenders:   [...this.blacklist.entries()]
        .sort((a, b) => b[1].violations - a[1].violations)
        .slice(0, 10)
        .map(([ip, info]) => ({ ip, ...info })),
      bannedSubnetList: [...this.subnetBanned.entries()]
        .map(([subnet, info]) => ({ subnet, ...info }))
        .slice(0, 10),
      recentAttacks:  this.attackLog.slice(-30).reverse(),
    };
  }

  // ── Cleanup ────────────────────────────────────────────────

  _cleanup() {
    const now = Date.now();
    for (const [ip, e]      of this.blacklist.entries())   if (now > e.expiresAt)  this.blacklist.delete(ip);
    for (const [s, e]       of this.subnetBanned.entries()) if (now > e.expiresAt) this.subnetBanned.delete(s);
    for (const [ip, hits]   of this.hitMap.entries()) {
      const fresh = hits.filter(t => now - t < 5 * 60 * 1000);
      if (!fresh.length) this.hitMap.delete(ip); else this.hitMap.set(ip, fresh);
    }
    for (const [key, hits]  of this.subnetHits.entries()) {
      const fresh = hits.filter(t => now - t < 5 * 60 * 1000);
      if (!fresh.length) this.subnetHits.delete(key); else this.subnetHits.set(key, fresh);
    }
  }

  destroy() { clearInterval(this._cleanupInterval); }
}

module.exports = new IpStore();
