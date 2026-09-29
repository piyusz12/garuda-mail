/* ─── Garuda Mail — Formatting Utilities ───────────────────────── */

/** Format bytes to human-readable string */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(1)} GB`;
}

/** Format date to localized display string */
export function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

/** Format date and time */
export function formatDateTime(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Format timestamp to HH:MM:SS */
export function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

/** Format precise timestamp with milliseconds */
export function formatPreciseTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

/** Relative time (e.g. "2 minutes ago") */
export function formatRelativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return formatDate(dateStr);
}

/** Format duration in seconds to human-readable */
export function formatDuration(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(2)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

/** Truncate string with ellipsis */
export function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : str;
}

/** Get severity color CSS variable name */
export function getSeverityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'var(--color-severity-critical)',
    high: 'var(--color-severity-high)',
    medium: 'var(--color-severity-medium)',
    low: 'var(--color-severity-low)',
    informational: 'var(--color-severity-info)',
    healthy: 'var(--color-severity-healthy)',
  };
  return map[severity.toLowerCase()] || 'var(--color-text-muted)';
}

/** Get risk level label from score */
export function getRiskLabel(score: number): string {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

/** Get policy status label */
export function getPolicyStatusLabel(status: string): string {
  const map: Record<string, string> = {
    compliant: 'COMPLIANT',
    acceptable: 'ACCEPTABLE',
    deprecated: 'DEPRECATED',
    insecure: 'INSECURE',
  };
  return map[status] || status.toUpperCase();
}

/** Get policy status color */
export function getPolicyStatusColor(status: string): string {
  const map: Record<string, string> = {
    compliant: 'var(--color-severity-healthy)',
    acceptable: 'var(--color-severity-low)',
    deprecated: 'var(--color-severity-high)',
    insecure: 'var(--color-severity-critical)',
  };
  return map[status] || 'var(--color-text-muted)';
}
