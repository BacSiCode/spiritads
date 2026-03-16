// ============================================================
//  server/config/security.config.js — Enterprise v2
// ============================================================

const bool = (v, def = true) => v === undefined ? def : (v === 'true' || v === true);

module.exports = {
  enabled: bool(process.env.ANTI_DDOS_PROTECTION, true),

  rateLimit: {
    enabled: bool(process.env.RATE_LIMIT_ENABLED, true),
    global:  { windowMs: 60000,       max: parseInt(process.env.RL_GLOBAL_MAX  || '120') },
    api:     { windowMs: 15 * 60000,  max: parseInt(process.env.RL_API_MAX     || '150') },
    auth:    { windowMs: 15 * 60000,  max: parseInt(process.env.RL_AUTH_MAX    || '8')   },
    contact: { windowMs: 60 * 60000,  max: parseInt(process.env.RL_CONTACT_MAX || '5')   },
  },

  botDetection: {
    enabled:              bool(process.env.BOT_DETECTION_ENABLED, true),
    blockEmptyUserAgent:  bool(process.env.BLOCK_EMPTY_UA,   true),
    blockMissingAccept:   bool(process.env.BLOCK_NO_ACCEPT,  true),
    anomalyRpmThreshold:  parseInt(process.env.ANOMALY_RPM   || '150'),
    anomalyWindowMs:      60000,
    blockedAgents: [
      'sqlmap','nikto','masscan','zgrab','nmap','dirbuster',
      'python-requests','libwww-perl','go-http-client',
      'scrapy','petalbot','semrushbot','ahrefsbot',
      'dotbot','mj12bot','blexbot','wget','curl/',
    ],
  },

  ipBlocking: {
    enabled:        bool(process.env.IP_BLOCKING_ENABLED, true),
    autoBanEnabled: bool(process.env.AUTO_BAN_ENABLED,    true),
    banThreshold:   parseInt(process.env.IP_BAN_THRESHOLD    || '20'),   // giảm xuống 20
    banDurationMs:  parseInt(process.env.IP_BAN_DURATION_MS  || String(2 * 60 * 60000)), // 2 giờ
    hardBanAfter:   parseInt(process.env.HARD_BAN_AFTER      || '3'),
    hardBanMs:      parseInt(process.env.HARD_BAN_MS         || String(24 * 60 * 60000)),
    staticBlacklist: (process.env.IP_BLACKLIST  || '').split(',').filter(Boolean),
    whitelist:       (process.env.IP_WHITELIST  || '127.0.0.1,::1').split(',').filter(Boolean),
  },

  connectionProtection: {
    enabled:          bool(process.env.CONN_PROTECTION_ENABLED, true),
    maxConnPerIp:     parseInt(process.env.MAX_CONN_PER_IP     || '25'),  // giảm xuống 25
    maxBodySizeBytes: 10 * 1024 * 1024,
  },

  slowRequest: {
    enabled:          bool(process.env.SLOW_REQUEST_ENABLED, true),
    requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS || '15000'), // giảm xuống 15s
  },

  logging: {
    enabled:         bool(process.env.SECURITY_LOGGING_ENABLED, true),
    logBlocked:      bool(process.env.LOG_BLOCKED_REQUESTS,     true),
    logAnomalies:    bool(process.env.LOG_ANOMALIES,            true),
    alertCooldownMs: parseInt(process.env.ALERT_COOLDOWN_MS     || '30000'), // giảm xuống 30s
    slackWebhook:    process.env.SLACK_WEBHOOK_URL  || null,
    discordWebhook:  process.env.DISCORD_WEBHOOK_URL || null,
  },

  cloudflare: {
    enabled:    bool(process.env.CF_AUTO_BLOCK_ENABLED, false),
    zoneId:     process.env.CF_ZONE_ID   || null,
    apiToken:   process.env.CF_API_TOKEN || null,
    trustProxy: bool(process.env.TRUST_CF_PROXY, false),
  },
};
