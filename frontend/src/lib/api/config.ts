/**
 * Garuda Mail — Centralized API & Backend Configuration
 * Single source of truth for backend endpoints, base URLs, and timeout defaults.
 */

export const API_CONFIG = {
  BACKEND_BASE_URL:
    process.env.BACKEND_API_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    'http://localhost:8000',
  DEFAULT_TIMEOUT_MS: 15_000,
  ENDPOINTS: {
    HEALTH: '/api/health',
    SESSIONS: '/api/sessions',
    FINDINGS: '/api/findings',
    DASHBOARD: '/api/dashboard',
    POSTURE: '/api/posture',
    ANOMALIES: '/api/anomalies',
    JOBS: '/api/jobs',
    CBOM_EXPORT: '/api/cbom/export',
    REPORTS: '/api/reports',
    INVESTIGATIONS: '/api/investigations',
    JA4: '/api/ja4',
    PCAP_UPLOAD: '/api/pcap/upload',
  },
} as const;

export function getBackendUrl(endpoint: string): string {
  const base = API_CONFIG.BACKEND_BASE_URL.replace(/\/+$/, '');
  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${base}${path}`;
}
