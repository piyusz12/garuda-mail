/**
 * Formatters — Data formatting helpers
 */

export function formatIP(bytes) {
  if (!bytes || bytes.length < 4) return '0.0.0.0';
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

export function formatIPFromUint32(num) {
  return `${(num >>> 24) & 0xff}.${(num >>> 16) & 0xff}.${(num >>> 8) & 0xff}.${num & 0xff}`;
}

export function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = ts instanceof Date ? ts : new Date(ts * 1000);
  return d.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  });
}

export function formatDuration(ms) {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export function truncateMiddle(str, maxLen = 32) {
  if (!str || str.length <= maxLen) return str;
  const half = Math.floor((maxLen - 3) / 2);
  return str.slice(0, half) + '...' + str.slice(-half);
}

export function getRiskColor(score) {
  if (score >= 90) return 'var(--accent-magenta)';
  if (score >= 70) return 'var(--accent-red)';
  if (score >= 40) return 'var(--accent-amber)';
  return 'var(--accent-emerald)';
}

export function getRiskCategory(score) {
  if (score >= 90) return 'Critical';
  if (score >= 70) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
}

export function getRiskBadgeClass(score) {
  if (score >= 90) return 'badge-critical';
  if (score >= 70) return 'badge-high';
  if (score >= 40) return 'badge-medium';
  return 'badge-low';
}

/**
 * Security-critical: synchronously escapes a value for safe interpolation
 * into HTML text nodes and (double-quoted) attribute values. Used everywhere
 * attacker-influenced data (PCAP-derived hostnames, certificate fields,
 * filenames, search queries) is rendered via innerHTML templates.
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Returns a string containing only characters that are safe to place inside
 * an HTML attribute or URL context. Used as a defense-in-depth sanitizer for
 * protocol-derived identifiers (IPs, JA4 fingerprints, cipher names).
 */
export function sanitizeToken(value, allowed = /[^A-Za-z0-9._:/\-@ ]/g) {
  if (value === null || value === undefined) return '';
  return String(value).replace(allowed, '');
}

export function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return Math.abs(hash);
}

export function hexDump(bytes, maxLen = 64) {
  if (!bytes) return '';
  const arr = Array.from(bytes.slice(0, maxLen));
  return arr.map(b => b.toString(16).padStart(2, '0')).join(' ');
}
