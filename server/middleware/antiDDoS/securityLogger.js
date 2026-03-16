// ============================================================
//  server/middleware/antiddos/securityLogger.js
//  Log security events + gửi webhook alert
// ============================================================

const cfg = require('../../config/security.config');

const LEVELS = { INFO: 'INFO', WARN: 'WARN', BLOCK: 'BLOCK', CRITICAL: 'CRITICAL' };

// Cooldown tracker để không spam alert
const alertCooldowns = new Map();

function formatTimestamp() {
  return new Date().toISOString();
}

function shouldSendAlert(key) {
  const last = alertCooldowns.get(key) ?? 0;
  const now  = Date.now();
  if (now - last < cfg.logging.alertCooldownMs) return false;
  alertCooldowns.set(key, now);
  return true;
}

// ── Core log function ──────────────────────────────────────────
function log(level, event, data = {}) {
  if (!cfg.logging.enabled) return;
  if (level === LEVELS.BLOCK  && !cfg.logging.logBlocked)   return;
  if (level === LEVELS.WARN   && !cfg.logging.logAnomalies) return;

  const entry = {
    ts:    formatTimestamp(),
    level,
    event,
    ...data,
  };

  // Console output với color codes
  const colors = {
    INFO:     '\x1b[36m',   // cyan
    WARN:     '\x1b[33m',   // yellow
    BLOCK:    '\x1b[31m',   // red
    CRITICAL: '\x1b[35m',   // magenta
  };
  const reset = '\x1b[0m';
  const icons = { INFO: 'ℹ️', WARN: '⚠️', BLOCK: '🚫', CRITICAL: '🚨' };

  console.log(
    `${colors[level]}${icons[level]} [${entry.ts}] [SECURITY:${level}] ${event}${reset}`,
    Object.keys(data).length ? JSON.stringify(data) : ''
  );

  // Webhook alert cho WARN/BLOCK/CRITICAL
  if ([LEVELS.WARN, LEVELS.BLOCK, LEVELS.CRITICAL].includes(level)) {
    const alertKey = `${level}:${event}:${data.ip ?? ''}`;
    if (shouldSendAlert(alertKey)) {
      sendWebhookAlert(level, event, entry).catch(() => {});
    }
  }
}

// ── Webhook sender ─────────────────────────────────────────────
async function sendWebhookAlert(level, event, data) {
  const emoji = { WARN: '⚠️', BLOCK: '🚫', CRITICAL: '🚨' }[level] ?? '🔔';
  const text  = [
    `${emoji} *SpiritAds Security – ${level}*`,
    `Event: \`${event}\``,
    data.ip      ? `IP: \`${data.ip}\``           : null,
    data.reason  ? `Reason: ${data.reason}`        : null,
    data.rpmCount ? `Rate: ${data.rpmCount} req/min` : null,
    `Time: ${data.ts}`,
  ].filter(Boolean).join('\n');

  const payload = { text };

  const webhooks = [
    cfg.logging.slackWebhook,
    cfg.logging.discordWebhook,
  ].filter(Boolean);

  for (const url of webhooks) {
    try {
      await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
        signal:  AbortSignal.timeout(5000),
      });
    } catch (_) { /* không làm gì – alert không quan trọng hơn serving request */ }
  }
}

// ── Cloudflare auto-block ──────────────────────────────────────
async function autoBlockCloudflare(ip, reason) {
  const { cloudflare } = cfg;
  if (!cloudflare.enabled || !cloudflare.zoneId || !cloudflare.apiToken) return;

  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${cloudflare.zoneId}/firewall/access_rules/rules`,
      {
        method:  'POST',
        headers: {
          'Authorization': `Bearer ${cloudflare.apiToken}`,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify({
          mode:          'block',
          configuration: { target: 'ip', value: ip },
          notes:         `SpiritAds auto-block: ${reason}`,
        }),
        signal: AbortSignal.timeout(8000),
      }
    );
    if (res.ok) log(LEVELS.INFO, 'cf_auto_block_success', { ip, reason });
    else         log(LEVELS.WARN, 'cf_auto_block_failed',  { ip, status: res.status });
  } catch (err) {
    log(LEVELS.WARN, 'cf_auto_block_error', { ip, error: err.message });
  }
}

module.exports = {
  log,
  LEVELS,
  autoBlockCloudflare,
  // Shortcuts
  info:     (event, data) => log(LEVELS.INFO,     event, data),
  warn:     (event, data) => log(LEVELS.WARN,     event, data),
  block:    (event, data) => log(LEVELS.BLOCK,    event, data),
  critical: (event, data) => log(LEVELS.CRITICAL, event, data),
};
