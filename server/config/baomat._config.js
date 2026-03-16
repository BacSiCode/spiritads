// ============================================================
//  server/config/security.config.js
//  Central config cho toàn bộ Anti-DDoS / Anti-DoS system
// ============================================================

const parseBoolean = (val) => val === 'true' || val === true;

const securityConfig = {
  // ── Master switch ──────────────────────────────────────────
  enabled: parseBoolean(process.env.ANTI_DDOS_PROTECTION ?? 'true'),

  // ── Layer 1: Rate Limiting ─────────────────────────────────
  rateLimit: {
    enabled: parseBoolean(process.env.RATE_LIMIT_ENABLED ?? 'true'),

    global: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS    ?? '60000'),   // 1 phút
      max:      parseInt(process.env.RATE_LIMIT_GLOBAL_MAX   ?? '200'),      // req/window
    },

    api: {
      windowMs: 15 * 60 * 1000,   // 15 phút
      max:      parseInt(process.env.RATE_LIMIT_API_MAX ?? '300'),
    },

    auth: {
      windowMs: 15 * 60 * 1000,
      max:      parseInt(process.env.RATE_LIMIT_AUTH_MAX ?? '10'),
    },

    contact: {
      windowMs: 60 * 60 * 1000,   // 1 giờ
      max:      parseInt(process.env.RATE_LIMIT_CONTACT_MAX ?? '5'),
    },
  },

  // ── Layer 2: Bot Detection ─────────────────────────────────
  botDetection: {
    enabled: parseBoolean(process.env.BOT_DETECTION_ENABLED ?? 'true'),

    blockEmptyUserAgent:  parseBoolean(process.env.BLOCK_EMPTY_UA     ?? 'true'),
    blockMissingAccept:   parseBoolean(process.env.BLOCK_NO_ACCEPT    ?? 'true'),
    anomalyRpmThreshold:  parseInt(process.env.ANOMALY_RPM_THRESHOLD  ?? '300'),
    anomalyWindowMs:      parseInt(process.env.ANOMALY_WINDOW_MS      ?? '60000'),

    // User-Agents bị block
    blockedAgents: (process.env.BLOCKED_USER_AGENTS ?? [
      'sqlmap', 'nikto', 'masscan', 'zgrab',
      'nmap', 'dirbuster', 'python-requests',
      'go-http-client', 'curl/', 'libwww-perl',
    ].join(',')).split(',').map(s => s.trim().toLowerCase()),
  },

  // ── Layer 3: IP Blocking ───────────────────────────────────
  ipBlocking: {
    enabled:        parseBoolean(process.env.IP_BLOCKING_ENABLED    ?? 'true'),
    autoBanEnabled: parseBoolean(process.env.AUTO_BAN_ENABLED       ?? 'true'),

    // Sau bao nhiêu vi phạm thì ban
    banThreshold: parseInt(process.env.IP_BAN_THRESHOLD ?? '50'),
    // Ban bao lâu (ms)
    banDurationMs: parseInt(process.env.IP_BAN_DURATION_MS ?? String(30 * 60 * 1000)), // 30 phút

    // Danh sách IP tĩnh bị block vĩnh viễn (từ .env, phân cách bằng dấu phẩy)
    staticBlacklist: (process.env.IP_STATIC_BLACKLIST ?? '').split(',').filter(Boolean),

    // Danh sách IP luôn được phép (whitelist)
    whitelist: (process.env.IP_WHITELIST ?? '127.0.0.1,::1').split(',').filter(Boolean),
  },

  // ── Layer 4: Connection Protection ────────────────────────
  connectionProtection: {
    enabled:           parseBoolean(process.env.CONN_PROTECTION_ENABLED ?? 'true'),
    maxConnPerIp:      parseInt(process.env.MAX_CONN_PER_IP             ?? '50'),
    maxBodySizeBytes:  parseInt(process.env.MAX_BODY_SIZE_BYTES         ?? String(10 * 1024 * 1024)), // 10MB
  },

  // ── Layer 5: Slow Request Protection ──────────────────────
  slowRequest: {
    enabled:          parseBoolean(process.env.SLOW_REQUEST_ENABLED      ?? 'true'),
    requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS            ?? '30000'),   // 30s
    headerTimeoutMs:  parseInt(process.env.HEADER_TIMEOUT_MS             ?? '10000'),   // 10s
  },

  // ── Logging & Monitoring ───────────────────────────────────
  logging: {
    enabled:        parseBoolean(process.env.SECURITY_LOGGING_ENABLED   ?? 'true'),
    logBlocked:     parseBoolean(process.env.LOG_BLOCKED_REQUESTS       ?? 'true'),
    logAnomalies:   parseBoolean(process.env.LOG_ANOMALIES              ?? 'true'),
    slackWebhook:   process.env.SLACK_WEBHOOK_URL   ?? null,
    discordWebhook: process.env.DISCORD_WEBHOOK_URL ?? null,
    alertCooldownMs: parseInt(process.env.ALERT_COOLDOWN_MS             ?? '60000'),   // 1 alert/phút
  },

  // ── Cloudflare integration ─────────────────────────────────
  cloudflare: {
    enabled:        parseBoolean(process.env.CF_AUTO_BLOCK_ENABLED ?? 'false'),
    zoneId:         process.env.CF_ZONE_ID     ?? null,
    apiToken:       process.env.CF_API_TOKEN   ?? null,
    // Trust CF-Connecting-IP header khi đứng sau Cloudflare
    trustProxy:     parseBoolean(process.env.TRUST_CF_PROXY       ?? 'true'),
  },
};

module.exports = securityConfig;
