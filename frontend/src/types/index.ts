/* ─── Garuda Mail — Core TypeScript Definitions ───────────────────── */

// ── Severity & Status ──

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type AnalysisStatus = 'queued' | 'validating' | 'reading' | 'reconstructing' | 'identifying' | 'analyzing_tls' | 'analyzing_certs' | 'running_rules' | 'running_ai' | 'calculating_risk' | 'completed' | 'failed';

export type FindingStatus = 'open' | 'reviewed' | 'mitigated' | 'accepted' | 'false_positive';

export type SystemServiceStatus = 'connected' | 'processing' | 'degraded' | 'offline';

export type CertificateStatus = 'valid' | 'expiring' | 'expired' | 'weak' | 'invalid' | 'incomplete' | 'unknown';

export type DetectionSource = 'rule_engine' | 'ai_anomaly' | 'combined';

// ── Analysis ──

export interface AnalysisJob {
  id: string;
  filename: string;
  fileSize: number;
  status: AnalysisStatus;
  progress: number; // 0-100
  sessionsCount: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  overallRisk: number;
  startedAt: string;
  completedAt: string | null;
  error: string | null;
}

export interface AnalysisProgress {
  stage: AnalysisStatus;
  stageLabel: string;
  percent: number;
  currentAction: string;
}

// ── Sessions ──

export interface SessionRecord {
  id: string;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  destHostname: string | null;
  duration: number; // seconds
  packets: number;
  bytes: number;
  tlsVersion: string | null;
  starttls: boolean;
  risk: Severity;
  riskScore: number;
  findingsCount: number;
  anomalyScore: number | null;
  timestamp: string;
  ja4: string | null;
}

export interface SessionDetail extends SessionRecord {
  tls: TlsAnalysis | null;
  certificate: CertificateRecord | null;
  findings: Finding[];
  anomalies: Anomaly[];
  timeline: SessionTimelineEvent[];
  packetRecords: PacketRecord[];
}

export interface SessionTimelineEvent {
  timestamp: string;
  event: string;
  detail: string;
  type: 'tcp' | 'smtp' | 'imap' | 'pop3' | 'tls' | 'certificate' | 'anomaly' | 'data';
}

// ── TLS ──

export interface TlsAnalysis {
  version: string;
  versionNumeric: number;
  cipherSuite: string;
  keyExchange: string;
  authentication: string;
  encryption: string;
  hash: string;
  forwardSecrecy: boolean;
  sni: string | null;
  alpn: string[];
  extensions: string[];
  policyStatus: 'compliant' | 'acceptable' | 'deprecated' | 'insecure';
}

// ── Certificates ──

export interface CertificateRecord {
  id: string;
  subject: string;
  subjectAltNames: string[];
  issuer: string;
  serialNumber: string;
  algorithm: string;
  keySize: number;
  keyType: string;
  validFrom: string;
  validUntil: string;
  daysRemaining: number;
  chainLength: number;
  chainValid: boolean;
  status: CertificateStatus;
  relatedSessionIds: string[];
}

// ── Findings ──

export interface Evidence {
  sessionId: string;
  packets: string; // e.g. "1823-1825"
  observed: string;
  sourceIp: string;
  destIp: string;
  destHostname: string | null;
  timestamp: string;
  raw?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  detectionSource: DetectionSource;
  confidence: number; // 0-100
  ruleId: string | null;
  status: FindingStatus;
  evidence: Evidence[];
  technicalDetails: string;
  whyItMatters: string;
  remediation: string;
  remediationPriority: Severity;
  standardsMapping: StandardMapping[];
  affectedAssets: string[];
  relatedSessionIds: string[];
  timestamp: string;
}

export interface StandardMapping {
  standard: string;
  reference: string;
  severity: string;
  recommendation: string;
}

// ── Risk ──

export interface RiskAssessment {
  overallScore: number; // 0-100
  ruleContribution: number;
  aiAnomalyContribution: number;
  contextContribution: number;
  confidenceContribution: number;
  dimensions: RiskDimension[];
}

export interface RiskDimension {
  name: string;
  score: number;
  weight: number;
  description: string;
}

// ── AI Anomaly ──

export interface Anomaly {
  id: string;
  sessionId: string;
  anomalyScore: number; // 0-100
  confidence: number;
  ja4: string | null;
  protocol: string;
  reasoningSignals: string[];
  featureContributions: FeatureContribution[];
  timestamp: string;
}

export interface FeatureContribution {
  feature: string;
  value: number;
  importance: number;
  direction: 'increase' | 'decrease';
}

// ── JA4 ──

export interface Ja4Fingerprint {
  fingerprint: string;
  frequency: number;
  firstSeen: string;
  lastSeen: string;
  associatedSessions: string[];
  rarity: 'common' | 'uncommon' | 'rare' | 'unknown';
}

// ── Packets ──

export interface PacketRecord {
  number: number;
  timestamp: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: string;
  length: number;
  flags: string;
  summary: string;
  headers?: Record<string, string>;
  payload?: string;
}

// ── CBOM ──

export interface CbomAsset {
  id: string;
  asset: string;
  protocol: string;
  tlsVersion: string;
  cipher: string;
  keyAlgorithm: string;
  keySize: number;
  certificate: string | null;
  ja4: string | null;
  risk: Severity;
  children?: CbomAsset[];
}

// ── Reports ──

export interface Report {
  id: string;
  type: 'executive' | 'technical' | 'json';
  title: string;
  analysisId: string;
  generatedAt: string;
  format: 'PDF' | 'HTML' | 'JSON';
  size: number;
  status: 'generating' | 'ready' | 'failed';
}

// ── Investigation ──

export interface Investigation {
  id: string;
  title: string;
  description: string;
  status: 'active' | 'closed' | 'archived';
  createdAt: string;
  updatedAt: string;
  sessionIds: string[];
  findingIds: string[];
  notes: InvestigationNote[];
}

export interface InvestigationNote {
  id: string;
  content: string;
  author: string;
  createdAt: string;
}

// ── Posture ──

export interface PostureMetrics {
  tlsPosture: PostureItem;
  certificateHealth: PostureItem;
  forwardSecrecy: PostureItem;
  starttlsAdoption: PostureItem;
  cryptoCompliance: PostureItem;
  aiAnomalyActivity: PostureItem;
}

export interface PostureItem {
  label: string;
  score: number; // 0-100
  status: 'good' | 'warning' | 'critical';
  detail: string;
}

// ── System ──

export interface SystemStatus {
  backend: SystemServiceStatus;
  analysisEngine: SystemServiceStatus;
  aiEngine: SystemServiceStatus;
  database: SystemServiceStatus;
  reportEngine: SystemServiceStatus;
}

// ── Dashboard ──

export interface DashboardData {
  risk: RiskAssessment;
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    total: number;
  };
  sessionsAnalyzed: number;
  affectedAssets: number;
  posture: PostureMetrics;
  recentFindings: Finding[];
  recentAnalyses: AnalysisJob[];
}

// ── MTA-STS / DANE ──

export type ComplianceStatus = 'compliant' | 'potential_violation' | 'match' | 'mismatch' | 'insufficient_evidence' | 'unavailable';

export interface MtaStsResult {
  domain: string;
  status: ComplianceStatus;
  mode: string | null;
  mxPatterns: string[];
}

export interface DaneResult {
  domain: string;
  status: ComplianceStatus;
  tlsaRecords: number;
  certificateMatch: boolean | null;
}
