// ============================================================
//  server/middleware/antiddos/securityLogger.js — Enterprise
// ============================================================

const LEVELS = { INFO: 'INFO', WARN: 'WARN', BLOCK: 'BLOCK', CRITICAL: 'CRITICAL' };
const alertCooldowns = new Map();

function getCfg() { return require('../../config/baomat._config'); }

function shouldSendAlert(key) {
  const cfg  = getCfg();
  const last = alertCooldowns.get(key) ?? 0;
  const now  = Date.now();
  if (now - last < (cfg.logging?.alertCooldownMs ?? 60000)) return false;
  alertCooldowns.set(key, now);
  return true;
}

// ── Core log ──────────────────────────────────────────────────
function log(level, event, data = {}) {
  const cfg = getCfg();
  if (!cfg.logging?.enabled) return;
  if (level === LEVELS.BLOCK    && !cfg.logging?.logBlocked)   return;
  if (level === LEVELS.WARN     && !cfg.logging?.logAnomalies) return;

  const colors = { INFO:'\x1b[36m', WARN:'\x1b[33m', BLOCK:'\x1b[31m', CRITICAL:'\x1b[35m' };
  const icons  = { INFO:'ℹ️ ', WARN:'⚠️ ', BLOCK:'🚫', CRITICAL:'🚨' };
  const reset  = '\x1b[0m';
  const ts     = new Date().toISOString();

  console.log(
    `${colors[level]}${icons[level]} [${ts}] [${level}] ${event}${reset}`,
    Object.keys(data).length ? JSON.stringify(data) : ''
  );

  if ([LEVELS.WARN, LEVELS.BLOCK, LEVELS.CRITICAL].includes(level)) {
    const key = `${level}:${event}:${data.ip ?? ''}`;
    if (shouldSendAlert(key)) {
      _sendAllAlerts(level, event, { ...data, ts }).catch(() => {});
    }
  }
}

// ── Send to all channels ───────────────────────────────────────
async function _sendAllAlerts(level, event, data) {
  const cfg   = getCfg();
  const emoji = { WARN:'⚠️', BLOCK:'🚫', CRITICAL:'🚨' }[level] ?? '🔔';
  const lines = [
    `${emoji} *SpiritAds Security – ${level}*`,
    `Event: \`${event}\``,
    data.ip        ? `IP: \`${data.ip}\``                  : null,
    data.reason    ? `Reason: ${data.reason}`               : null,
    data.rpmCount  ? `Rate: ${data.rpmCount} req/min`       : null,
    data.banCount  ? `Ban lần thứ: #${data.banCount}`       : null,
    `🕐 ${new Date(data.ts).toLocaleString('vi-VN')}`,
  ].filter(Boolean).join('\n');

  // Telegram
  await _sendTelegram(lines, cfg).catch(() => {});

  // Slack / Discord webhook
  const webhooks = [cfg.logging?.slackWebhook, cfg.logging?.discordWebhook].filter(Boolean);
  for (const url of webhooks) {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: lines }),
      signal: AbortSignal.timeout(5000),
    }).catch(() => {});
  }
}

async function _sendTelegram(text, cfg) {
  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
    signal: AbortSignal.timeout(5000),
  });
}

// ── Cloudflare auto-block ──────────────────────────────────────
async function autoBlockCloudflare(ip, reason) {
  const cfg = getCfg();
  if (!cfg.cloudflare?.enabled || !cfg.cloudflare?.zoneId || !cfg.cloudflare?.apiToken) return;
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${cfg.cloudflare.zoneId}/firewall/access_rules/rules`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${cfg.cloudflare.apiToken}`,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify({
          mode: 'block',
          configuration: { target: 'ip', value: ip },
          notes: `SpiritAds auto-block: ${reason}`,
        }),
        signal: AbortSignal.timeout(8000),
      }
    );
    if (res.ok) log(LEVELS.INFO, 'cf_blocked', { ip, reason });
    else        log(LEVELS.WARN, 'cf_block_failed', { ip, status: res.status });
  } catch (err) {
    log(LEVELS.WARN, 'cf_block_error', { ip, error: err.message });
  }
}

module.exports = {
  log, LEVELS, autoBlockCloudflare,
  info:     (e, d) => log(LEVELS.INFO,     e, d),
  warn:     (e, d) => log(LEVELS.WARN,     e, d),
  block:    (e, d) => log(LEVELS.BLOCK,    e, d),
  critical: (e, d) => log(LEVELS.CRITICAL, e, d),
};
