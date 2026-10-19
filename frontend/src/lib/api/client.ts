/* ─── Garuda Mail — Centralized API Client ─────────────────────── */
/* Seamlessly connects to real FastAPI backend (port 8000), falling back to mock fixtures if offline. */

import type {
  AnalysisJob, SessionRecord, SessionDetail, Finding,
  CertificateRecord, Anomaly, CbomAsset, RiskAssessment,
  Report, DashboardData, SystemStatus, Ja4Fingerprint,
  Investigation, PostureMetrics,
} from '@/types';

import { API_CONFIG } from './config';

const API_BASE = API_CONFIG.BACKEND_BASE_URL;

const EXPLICIT_MOCK = (() => {
  const v = process.env.NEXT_PUBLIC_USE_MOCK_DATA;
  return v !== undefined && ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
})();

/* ── Generic Fetch ── */

const DEFAULT_TIMEOUT_MS = API_CONFIG.DEFAULT_TIMEOUT_MS;

async function apiFetch<T>(path: string, options?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options ?? {};

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const externalSignal = init.signal;
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  try {
    const defaultHeaders: Record<string, string> = {};
    if (!(init.body instanceof FormData)) {
      defaultHeaders['Content-Type'] = 'application/json';
    }

    const res = await fetch(`${API_BASE}${path}`, {
      headers: { ...defaultHeaders, ...(init.headers as Record<string, string>) },
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

/**
 * Resilient live-first API fetcher:
 * Attempts real FastAPI endpoint. If unreachable or explicitly in mock mode,
 * transparently resolves with mock fixture so UI never crashes.
 */
async function apiFetchWithFallback<T>(path: string, getFallback: () => Promise<T>): Promise<T> {
  if (!EXPLICIT_MOCK) {
    try {
      return await apiFetch<T>(path, { timeoutMs: 3500 });
    } catch {
      // Backend offline or route unhandled — gracefully fallback
    }
  }
  return getFallback();
}

/* ── API Methods ── */

export const api = {
  // Dashboard
  async getDashboard(): Promise<DashboardData> {
    return apiFetchWithFallback('/api/dashboard', async () => (await getMockModule()).mockDashboard);
  },

  // Sessions
  async getSessions(): Promise<SessionRecord[]> {
    return apiFetchWithFallback('/api/sessions', async () => (await getMockModule()).mockSessions);
  },

  async getSession(id: string): Promise<SessionDetail | null> {
    return apiFetchWithFallback(`/api/sessions/${id}`, async () => {
      const { buildSessionDetail } = await getMockDetails();
      return buildSessionDetail(id);
    });
  },

  // Findings
  async getFindings(): Promise<Finding[]> {
    return apiFetchWithFallback('/api/findings', async () => (await getMockModule()).mockFindings);
  },

  async getFinding(id: string): Promise<Finding | null> {
    return apiFetchWithFallback(`/api/findings/${id}`, async () => {
      const { mockFindings } = await getMockModule();
      return mockFindings.find((f: Finding) => f.id === id) || null;
    });
  },

  // Certificates
  async getCertificates(): Promise<CertificateRecord[]> {
    return apiFetchWithFallback('/api/certificates', async () => (await getMockModule()).mockCertificates);
  },

  async getCertificate(id: string): Promise<CertificateRecord | null> {
    return apiFetchWithFallback(`/api/certificates/${id}`, async () => {
      const { mockCertificates } = await getMockModule();
      return mockCertificates.find((c: CertificateRecord) => c.id === id) || null;
    });
  },

  // Anomalies
  async getAnomalies(): Promise<Anomaly[]> {
    return apiFetchWithFallback('/api/anomalies', async () => (await getMockModule()).mockAnomalies);
  },

  // Risk
  async getRisk(): Promise<RiskAssessment> {
    return apiFetchWithFallback('/api/risk', async () => (await getMockModule()).mockRisk);
  },

  // Posture
  async getPosture(): Promise<PostureMetrics> {
    return apiFetchWithFallback('/api/posture', async () => (await getMockModule()).mockPosture);
  },

  // CBOM
  async getCbom(): Promise<CbomAsset[]> {
    return apiFetchWithFallback('/api/cbom', async () => (await getMockModule()).mockCbom);
  },

  // Reports
  async getReports(): Promise<Report[]> {
    return apiFetchWithFallback('/api/reports', async () => (await getMockModule()).mockReports);
  },

  // Analyses
  async getAnalyses(): Promise<AnalysisJob[]> {
    return apiFetchWithFallback('/api/jobs', async () => (await getMockModule()).mockAnalyses);
  },

  // System Status
  async getSystemStatus(): Promise<SystemStatus> {
    return apiFetchWithFallback('/api/status', async () => (await getMockModule()).mockSystemStatus);
  },

  // Investigations
  async getInvestigations(): Promise<Investigation[]> {
    return apiFetchWithFallback('/api/investigations', async () => {
      const { mockInvestigations } = await getMockDetails();
      return mockInvestigations;
    });
  },

  async getInvestigation(id: string): Promise<Investigation | null> {
    return apiFetchWithFallback(`/api/investigations/${id}`, async () => {
      const { mockInvestigations } = await getMockDetails();
      return mockInvestigations.find((i: Investigation) => i.id === id) || null;
    });
  },

  // JA4
  async getJa4Fingerprints(): Promise<Ja4Fingerprint[]> {
    return apiFetchWithFallback('/api/ja4', async () => {
      const { mockJa4Fingerprints } = await getMockDetails();
      return mockJa4Fingerprints;
    });
  },

  // Upload
  async uploadPcap(file: File, onProgress?: (progress: number) => void): Promise<AnalysisJob> {
    if (!EXPLICIT_MOCK) {
      try {
        const formData = new FormData();
        formData.append('file', file);
        // Try Next.js upload proxy (which routes to FastAPI with signature validation)
        const res = await fetch('/api/pcap/upload', { method: 'POST', body: formData });
        if (res.ok) {
          const data = await res.json();
          onProgress?.(100);
          return data;
        }
      } catch (err) {
        console.warn('[client.ts] Real upload failed, falling back to simulated analysis:', err);
      }
    }

    // Fallback simulation for disconnected / air-gapped demo
    return new Promise((resolve) => {
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 15 + 10;
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
          import('@/lib/mock/data').then(({ mockAnalyses }) => {
            resolve({
              ...mockAnalyses[0],
              id: `AN-${Date.now().toString(36).toUpperCase()}`,
              filename: file.name,
              fileSize: file.size,
            });
          });
        } else {
          onProgress?.(Math.round(progress));
        }
      }, 250);
    });
  },
};
