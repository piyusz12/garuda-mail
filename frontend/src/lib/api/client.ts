/* ─── Garuda Mail — Centralized API Client ─────────────────────── */
/* All API calls go through this layer. In mock mode, returns mock data. */

import type {
  AnalysisJob, SessionRecord, SessionDetail, Finding,
  CertificateRecord, Anomaly, CbomAsset, RiskAssessment,
  Report, DashboardData, SystemStatus, Ja4Fingerprint,
  Investigation, PostureMetrics,
} from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
// Explicit truthy parsing: only enable mock mode when the flag is unset or
// explicitly set to a truthy value ("1", "true"). Previously any string other
// than exactly "false" (e.g. a typo like "flase") silently enabled mocks.
const USE_MOCK = (() => {
  const v = process.env.NEXT_PUBLIC_USE_MOCK_DATA;
  return v === undefined ? true : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
})();

/* ── Generic Fetch ── */

const DEFAULT_TIMEOUT_MS = 15_000;

async function apiFetch<T>(path: string, options?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options ?? {};

  // Abort signal with timeout so hung backend requests fail fast instead of
  // leaving UI spinners stuck indefinitely.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  // Respect an externally-provided signal too (e.g. React unmount cancels).
  const externalSignal = init.signal;
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`API Error ${res.status}: ${res.statusText}`);
    return res.json();
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error(`API request timed out after ${timeoutMs}ms: ${path}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/* ── Mock Data Loaders ── */

// Cache the dynamic imports so repeated calls don't re-resolve modules and
// each page navigation doesn't pay the import-lookup cost again.
let _mockModule: Promise<typeof import('@/lib/mock/data')> | null = null;
let _mockDetails: Promise<typeof import('@/lib/mock/details')> | null = null;

async function getMockModule() {
  if (!_mockModule) _mockModule = import('@/lib/mock/data');
  return _mockModule;
}

async function getMockDetails() {
  if (!_mockDetails) _mockDetails = import('@/lib/mock/details');
  return _mockDetails;
}

/* ── API Methods ── */

export const api = {
  // Dashboard
  async getDashboard(): Promise<DashboardData> {
    if (USE_MOCK) return (await getMockModule()).mockDashboard;
    return apiFetch('/api/dashboard');
  },

  // Sessions
  async getSessions(): Promise<SessionRecord[]> {
    if (USE_MOCK) return (await getMockModule()).mockSessions;
    return apiFetch('/api/sessions');
  },

  async getSession(id: string): Promise<SessionDetail | null> {
    if (USE_MOCK) {
      const { buildSessionDetail } = await getMockDetails();
      return buildSessionDetail(id);
    }
    return apiFetch(`/api/sessions/${id}`);
  },

  // Findings
  async getFindings(): Promise<Finding[]> {
    if (USE_MOCK) return (await getMockModule()).mockFindings;
    return apiFetch('/api/findings');
  },

  async getFinding(id: string): Promise<Finding | null> {
    if (USE_MOCK) {
      const { mockFindings } = await getMockModule();
      return mockFindings.find((f: Finding) => f.id === id) || null;
    }
    return apiFetch(`/api/findings/${id}`);
  },

  // Certificates
  async getCertificates(): Promise<CertificateRecord[]> {
    if (USE_MOCK) return (await getMockModule()).mockCertificates;
    return apiFetch('/api/certificates');
  },

  async getCertificate(id: string): Promise<CertificateRecord | null> {
    if (USE_MOCK) {
      const { mockCertificates } = await getMockModule();
      return mockCertificates.find((c: CertificateRecord) => c.id === id) || null;
    }
    return apiFetch(`/api/certificates/${id}`);
  },

  // Anomalies
  async getAnomalies(): Promise<Anomaly[]> {
    if (USE_MOCK) return (await getMockModule()).mockAnomalies;
    return apiFetch('/api/anomalies');
  },

  // Risk
  async getRisk(): Promise<RiskAssessment> {
    if (USE_MOCK) return (await getMockModule()).mockRisk;
    return apiFetch('/api/risk');
  },

  // Posture
  async getPosture(): Promise<PostureMetrics> {
    if (USE_MOCK) return (await getMockModule()).mockPosture;
    return apiFetch('/api/posture');
  },

  // CBOM
  async getCbom(): Promise<CbomAsset[]> {
    if (USE_MOCK) return (await getMockModule()).mockCbom;
    return apiFetch('/api/cbom');
  },

  // Reports
  async getReports(): Promise<Report[]> {
    if (USE_MOCK) return (await getMockModule()).mockReports;
    return apiFetch('/api/reports');
  },

  // Analyses
  async getAnalyses(): Promise<AnalysisJob[]> {
    if (USE_MOCK) return (await getMockModule()).mockAnalyses;
    return apiFetch('/api/jobs');
  },

  // System Status
  async getSystemStatus(): Promise<SystemStatus> {
    if (USE_MOCK) return (await getMockModule()).mockSystemStatus;
    return apiFetch('/api/status');
  },

  // Investigations
  async getInvestigations(): Promise<Investigation[]> {
    if (USE_MOCK) {
      const { mockInvestigations } = await getMockDetails();
      return mockInvestigations;
    }
    return apiFetch('/api/investigations');
  },

  async getInvestigation(id: string): Promise<Investigation | null> {
    if (USE_MOCK) {
      const { mockInvestigations } = await getMockDetails();
      return mockInvestigations.find((i: Investigation) => i.id === id) || null;
    }
    return apiFetch(`/api/investigations/${id}`);
  },

  // JA4
  async getJa4Fingerprints(): Promise<Ja4Fingerprint[]> {
    if (USE_MOCK) {
      const { mockJa4Fingerprints } = await getMockDetails();
      return mockJa4Fingerprints;
    }
    return apiFetch('/api/ja4');
  },

  // Upload
  async uploadPcap(file: File, onProgress?: (progress: number) => void): Promise<AnalysisJob> {
    if (USE_MOCK) {
      // Simulate upload with progress
      return new Promise((resolve) => {
        let progress = 0;
        const interval = setInterval(() => {
          progress += Math.random() * 15 + 5;
          if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            import('@/lib/mock/data').then(({ mockAnalyses }) => {
              resolve(mockAnalyses[0]);
            });
          } else {
            onProgress?.(Math.round(progress));
          }
        }, 400);
      });
    }
    const formData = new FormData();
    formData.append('file', file);
    return apiFetch('/api/pcap/upload', { method: 'POST', body: formData, headers: {} });
  },
};
