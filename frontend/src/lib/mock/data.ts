/* ─── Garuda Mail — Mock Data ─────────────────────────────────────── */
/* Realistic forensic mock data for development and demo mode        */

import type {
  AnalysisJob, SessionRecord, Finding, CertificateRecord,
  Anomaly, Ja4Fingerprint, RiskAssessment, PostureMetrics,
  DashboardData, SystemStatus, CbomAsset, Report,
  Investigation, SessionDetail, SessionTimelineEvent, PacketRecord,
  TlsAnalysis, Evidence, StandardMapping, FeatureContribution,
} from '@/types';

// ── Risk Assessment ──

export const mockRisk: RiskAssessment = {
  overallScore: 78,
  ruleContribution: 62,
  aiAnomalyContribution: 41,
  contextContribution: 28,
  confidenceContribution: 89,
  dimensions: [
    { name: 'Protocol Security', score: 72, weight: 0.3, description: 'TLS version and cipher strength across all sessions' },
    { name: 'Certificate Health', score: 81, weight: 0.25, description: 'X.509 validity, chain integrity, and key strength' },
    { name: 'Configuration Compliance', score: 68, weight: 0.2, description: 'STARTTLS enforcement and MTA-STS adherence' },
    { name: 'Behavioral Anomaly', score: 41, weight: 0.15, description: 'AI-detected deviations from expected traffic patterns' },
    { name: 'Cryptographic Posture', score: 85, weight: 0.1, description: 'Forward secrecy adoption and key exchange quality' },
  ],
};

// ── Posture ──

export const mockPosture: PostureMetrics = {
  tlsPosture: { label: 'TLS Posture', score: 74, status: 'warning', detail: '89% TLS 1.2+, 3 sessions on TLS 1.0' },
  certificateHealth: { label: 'Certificate Health', score: 82, status: 'warning', detail: '2 certificates expiring within 30 days' },
  forwardSecrecy: { label: 'Forward Secrecy', score: 91, status: 'good', detail: '91% of sessions use ECDHE or DHE key exchange' },
  starttlsAdoption: { label: 'STARTTLS Adoption', score: 87, status: 'good', detail: '87% of SMTP sessions initiated STARTTLS upgrade' },
  cryptoCompliance: { label: 'Cryptographic Compliance', score: 69, status: 'warning', detail: '7 sessions using deprecated cipher suites' },
  aiAnomalyActivity: { label: 'AI Anomaly Activity', score: 34, status: 'critical', detail: '9 anomalies detected across 248 sessions' },
};

// ── Sessions ──

export const mockSessions: SessionRecord[] = [
  { id: 'SMTP-0192', protocol: 'SMTP', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, destHostname: 'mail.example.com', duration: 4.83, packets: 341, bytes: 128490, tlsVersion: 'TLS 1.2', starttls: true, risk: 'high', riskScore: 78, findingsCount: 3, anomalyScore: 67, timestamp: '2026-09-28T09:01:02Z', ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1' },
  { id: 'SMTP-0193', protocol: 'SMTP', sourceIp: '192.168.1.20', sourcePort: 45124, destIp: '198.51.100.25', destPort: 25, destHostname: 'smtp01.enterprise.local', duration: 2.14, packets: 189, bytes: 67230, tlsVersion: 'TLS 1.0', starttls: true, risk: 'critical', riskScore: 94, findingsCount: 5, anomalyScore: 12, timestamp: '2026-09-28T09:03:17Z', ja4: 't10d1516h2_8daaf6152771_b2a1c3d4e5f6' },
  { id: 'IMAP-0087', protocol: 'IMAP', sourceIp: '192.168.1.45', sourcePort: 52891, destIp: '203.0.113.50', destPort: 993, destHostname: 'imap.example.com', duration: 12.67, packets: 892, bytes: 456780, tlsVersion: 'TLS 1.3', starttls: false, risk: 'low', riskScore: 18, findingsCount: 0, anomalyScore: 8, timestamp: '2026-09-28T09:05:41Z', ja4: 't13d1517h2_a023bc45d678_f1a2b3c4d5e6' },
  { id: 'POP3-0034', protocol: 'POP3', sourceIp: '192.168.1.102', sourcePort: 38901, destIp: '198.51.100.30', destPort: 995, destHostname: 'pop3.legacy-mail.internal', duration: 1.91, packets: 78, bytes: 23410, tlsVersion: 'TLS 1.1', starttls: false, risk: 'high', riskScore: 72, findingsCount: 2, anomalyScore: null, timestamp: '2026-09-28T09:08:55Z', ja4: 't11d1516h2_c4d5e6f7a8b9_d1e2f3a4b5c6' },
  { id: 'SMTP-0194', protocol: 'SMTP', sourceIp: '10.0.2.15', sourcePort: 49201, destIp: '203.0.113.55', destPort: 587, destHostname: 'relay.partner-org.com', duration: 3.42, packets: 267, bytes: 98120, tlsVersion: 'TLS 1.2', starttls: true, risk: 'medium', riskScore: 45, findingsCount: 1, anomalyScore: 52, timestamp: '2026-09-28T09:12:33Z', ja4: 't12d1516h2_e5f6a7b8c9d0_a1b2c3d4e5f6' },
  { id: 'SMTP-0195', protocol: 'SMTP', sourceIp: '192.168.1.20', sourcePort: 45200, destIp: '203.0.113.50', destPort: 587, destHostname: 'mail.example.com', duration: 5.11, packets: 412, bytes: 167340, tlsVersion: 'TLS 1.3', starttls: true, risk: 'low', riskScore: 12, findingsCount: 0, anomalyScore: 5, timestamp: '2026-09-28T09:15:02Z', ja4: 't13d1517h2_a023bc45d678_f1a2b3c4d5e6' },
  { id: 'IMAP-0088', protocol: 'IMAP', sourceIp: '192.168.1.78', sourcePort: 53210, destIp: '198.51.100.25', destPort: 143, destHostname: 'imap-legacy.enterprise.local', duration: 8.34, packets: 523, bytes: 234560, tlsVersion: null, starttls: false, risk: 'critical', riskScore: 98, findingsCount: 4, anomalyScore: 78, timestamp: '2026-09-28T09:18:44Z', ja4: null },
  { id: 'SMTP-0196', protocol: 'SMTP', sourceIp: '10.0.2.20', sourcePort: 49300, destIp: '203.0.113.60', destPort: 25, destHostname: 'mx.vendor-mail.net', duration: 6.78, packets: 489, bytes: 201340, tlsVersion: 'TLS 1.2', starttls: true, risk: 'medium', riskScore: 38, findingsCount: 1, anomalyScore: 29, timestamp: '2026-09-28T09:22:11Z', ja4: 't12d1516h2_b3c4d5e6f7a8_c1d2e3f4a5b6' },
];

// ── Findings ──

export const mockFindings: Finding[] = [
  {
    id: 'TLS-001', title: 'Deprecated TLS Version Detected', description: 'Session SMTP-0193 negotiated TLS 1.0, which has known cryptographic vulnerabilities and is deprecated by NIST SP 800-52 Rev 2 and PCI DSS 4.0.',
    severity: 'critical', category: 'Protocol Security', detectionSource: 'rule_engine', confidence: 100, ruleId: 'RULE-TLS-DEPRECATED-001', status: 'open',
    evidence: [{ sessionId: 'SMTP-0193', packets: '1823-1825', observed: 'TLS 1.0 (0x0301)', sourceIp: '192.168.1.20', destIp: '198.51.100.25', destHostname: 'smtp01.enterprise.local', timestamp: '2026-09-28T09:03:18Z' }],
    technicalDetails: 'The TLS ClientHello proposed TLS 1.2 as maximum version, but the server selected TLS 1.0 (protocol_version: 0x0301). The resulting session used TLS_RSA_WITH_AES_128_CBC_SHA, which lacks forward secrecy and uses CBC mode susceptible to padding oracle attacks.',
    whyItMatters: 'TLS 1.0 is vulnerable to BEAST, POODLE, and related attacks. Any data transmitted over this session, including authentication credentials and email content, may be interceptable by a sufficiently positioned adversary.',
    remediation: 'Disable TLS 1.0 and TLS 1.1 on smtp01.enterprise.local. Configure the server to require TLS 1.2 as minimum with approved cipher suites. Verify configuration with a post-change PCAP analysis.',
    remediationPriority: 'critical',
    standardsMapping: [
      { standard: 'NIST SP 800-52 Rev 2', reference: 'Section 3.1', severity: 'SHALL NOT', recommendation: 'TLS 1.0 shall not be used' },
      { standard: 'PCI DSS 4.0', reference: 'Requirement 4.2.1', severity: 'Required', recommendation: 'Only strong cryptography protocols are used' },
    ],
    affectedAssets: ['smtp01.enterprise.local'], relatedSessionIds: ['SMTP-0193'], timestamp: '2026-09-28T09:03:18Z',
  },
  {
    id: 'TLS-002', title: 'Missing Forward Secrecy', description: 'Session SMTP-0193 used TLS_RSA_WITH_AES_128_CBC_SHA which does not provide forward secrecy.',
    severity: 'high', category: 'Cryptographic Weakness', detectionSource: 'rule_engine', confidence: 100, ruleId: 'RULE-FS-MISSING-001', status: 'open',
    evidence: [{ sessionId: 'SMTP-0193', packets: '1824', observed: 'TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)', sourceIp: '192.168.1.20', destIp: '198.51.100.25', destHostname: 'smtp01.enterprise.local', timestamp: '2026-09-28T09:03:18Z' }],
    technicalDetails: 'The negotiated cipher suite uses static RSA key exchange. If the server\'s private key is compromised, all past sessions encrypted with this key can be retroactively decrypted.',
    whyItMatters: 'Without forward secrecy (PFS), a future compromise of the server\'s RSA private key enables decryption of all previously recorded sessions. This is especially critical for email systems where traffic may be archived by adversaries.',
    remediation: 'Configure the server to prefer ECDHE-based cipher suites. Disable RSA key exchange cipher suites. Recommended: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.',
    remediationPriority: 'high',
    standardsMapping: [{ standard: 'NIST SP 800-52 Rev 2', reference: 'Section 3.3.1', severity: 'SHOULD', recommendation: 'Ephemeral key exchange should be used' }],
    affectedAssets: ['smtp01.enterprise.local'], relatedSessionIds: ['SMTP-0193'], timestamp: '2026-09-28T09:03:18Z',
  },
  {
    id: 'CERT-001', title: 'Certificate Expiring Within 30 Days', description: 'The X.509 certificate presented by mail.example.com expires in 18 days.',
    severity: 'high', category: 'Certificate Management', detectionSource: 'rule_engine', confidence: 100, ruleId: 'RULE-CERT-EXPIRY-001', status: 'open',
    evidence: [{ sessionId: 'SMTP-0192', packets: '1830-1835', observed: 'Certificate valid until 2026-10-16T23:59:59Z', sourceIp: '192.168.1.20', destIp: '203.0.113.50', destHostname: 'mail.example.com', timestamp: '2026-09-28T09:01:04Z' }],
    technicalDetails: 'Certificate Subject: CN=mail.example.com, O=Example Corp. Issuer: CN=DigiCert SHA2 Extended Validation Server CA. Serial: 0A:1B:2C:3D. Not After: 2026-10-16T23:59:59Z.',
    whyItMatters: 'Certificate expiration will cause TLS connections to fail, preventing secure email delivery. Clients will reject the connection or display warnings, potentially causing email outage.',
    remediation: 'Renew the certificate for mail.example.com before 2026-10-16. Verify the renewed certificate includes all required SANs. Deploy and verify with a post-change scan.',
    remediationPriority: 'high',
    standardsMapping: [{ standard: 'CA/Browser Forum', reference: 'Baseline Requirements', severity: 'Required', recommendation: 'Certificates must be renewed before expiration' }],
    affectedAssets: ['mail.example.com'], relatedSessionIds: ['SMTP-0192', 'SMTP-0195'], timestamp: '2026-09-28T09:01:04Z',
  },
  {
    id: 'STARTTLS-001', title: 'Plaintext Email Session Without Encryption', description: 'IMAP session IMAP-0087 on port 143 did not negotiate STARTTLS, transmitting credentials and email content in cleartext.',
    severity: 'critical', category: 'Encryption Failure', detectionSource: 'rule_engine', confidence: 100, ruleId: 'RULE-STARTTLS-MISSING-001', status: 'open',
    evidence: [{ sessionId: 'IMAP-0088', packets: '1-78', observed: 'No TLS negotiation observed on IMAP port 143', sourceIp: '192.168.1.78', destIp: '198.51.100.25', destHostname: 'imap-legacy.enterprise.local', timestamp: '2026-09-28T09:18:44Z' }],
    technicalDetails: 'The IMAP session on port 143 completed authentication (LOGIN command) and mailbox operations without any encryption. User credentials were transmitted in plaintext.',
    whyItMatters: 'Plaintext email sessions expose user credentials, email headers, and message bodies to any network observer. This represents a direct data confidentiality and integrity breach.',
    remediation: 'Enforce STARTTLS on IMAP port 143, or migrate all IMAP clients to use IMAPS (port 993) exclusively. Disable plaintext IMAP access. Reset credentials for affected users.',
    remediationPriority: 'critical',
    standardsMapping: [{ standard: 'RFC 8314', reference: 'Section 3', severity: 'MUST', recommendation: 'Implicit TLS is RECOMMENDED over STARTTLS' }],
    affectedAssets: ['imap-legacy.enterprise.local'], relatedSessionIds: ['IMAP-0088'], timestamp: '2026-09-28T09:18:44Z',
  },
  {
    id: 'CIPHER-001', title: 'Weak Cipher Suite Negotiated', description: 'Session SMTP-0194 negotiated TLS_RSA_WITH_3DES_EDE_CBC_SHA which uses the deprecated 3DES algorithm.',
    severity: 'medium', category: 'Cryptographic Weakness', detectionSource: 'rule_engine', confidence: 100, ruleId: 'RULE-CIPHER-WEAK-001', status: 'open',
    evidence: [{ sessionId: 'SMTP-0194', packets: '2101-2103', observed: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)', sourceIp: '10.0.2.15', destIp: '203.0.113.55', destHostname: 'relay.partner-org.com', timestamp: '2026-09-28T09:12:34Z' }],
    technicalDetails: '3DES has an effective security strength of 112 bits due to its 64-bit block size, making it vulnerable to the Sweet32 birthday attack after approximately 32GB of data.',
    whyItMatters: 'While the practical exploitability is moderate, 3DES is deprecated and should be replaced with AES-based cipher suites for compliance and forward-looking security.',
    remediation: 'Work with the partner organization (relay.partner-org.com) to disable 3DES cipher suites and enable AES-GCM alternatives.',
    remediationPriority: 'medium',
    standardsMapping: [{ standard: 'NIST SP 800-131A Rev 2', reference: 'Section 2', severity: 'Disallowed after 2023', recommendation: '3DES is disallowed for encryption' }],
    affectedAssets: ['relay.partner-org.com'], relatedSessionIds: ['SMTP-0194'], timestamp: '2026-09-28T09:12:34Z',
  },
];

// ── Anomalies ──

export const mockAnomalies: Anomaly[] = [
  { id: 'ANO-001', sessionId: 'SMTP-0192', anomalyScore: 67, confidence: 78, ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1', protocol: 'SMTP', reasoningSignals: ['Unusual cipher suite preference order', 'TLS extension combination not seen in baseline', 'Session timing deviation from organizational pattern'], featureContributions: [{ feature: 'cipher_order_entropy', value: 0.89, importance: 0.34, direction: 'increase' }, { feature: 'extension_set_rarity', value: 0.72, importance: 0.28, direction: 'increase' }, { feature: 'timing_deviation', value: 0.61, importance: 0.21, direction: 'increase' }], timestamp: '2026-09-28T09:01:04Z' },
  { id: 'ANO-002', sessionId: 'SMTP-0194', anomalyScore: 52, confidence: 65, ja4: 't12d1516h2_e5f6a7b8c9d0_a1b2c3d4e5f6', protocol: 'SMTP', reasoningSignals: ['Rare JA4 fingerprint in organizational context', 'Unusual SMTP command sequence'], featureContributions: [{ feature: 'ja4_frequency', value: 0.91, importance: 0.45, direction: 'increase' }, { feature: 'smtp_command_entropy', value: 0.58, importance: 0.22, direction: 'increase' }], timestamp: '2026-09-28T09:12:35Z' },
  { id: 'ANO-003', sessionId: 'IMAP-0088', anomalyScore: 78, confidence: 82, ja4: null, protocol: 'IMAP', reasoningSignals: ['Plaintext IMAP session on modern infrastructure', 'Authentication without encryption', 'Unusual access time pattern'], featureContributions: [{ feature: 'encryption_absence', value: 1.0, importance: 0.55, direction: 'increase' }, { feature: 'auth_cleartext', value: 1.0, importance: 0.30, direction: 'increase' }], timestamp: '2026-09-28T09:18:46Z' },
];

// ── Certificates ──

export const mockCertificates: CertificateRecord[] = [
  { id: 'CERT-EX-001', subject: 'mail.example.com', subjectAltNames: ['mail.example.com', 'smtp.example.com'], issuer: 'DigiCert SHA2 Extended Validation Server CA', serialNumber: '0A:1B:2C:3D:4E:5F:6A:7B', algorithm: 'SHA256withRSA', keySize: 2048, keyType: 'RSA', validFrom: '2025-10-17T00:00:00Z', validUntil: '2026-10-16T23:59:59Z', daysRemaining: 18, chainLength: 3, chainValid: true, status: 'expiring', relatedSessionIds: ['SMTP-0192', 'SMTP-0195'] },
  { id: 'CERT-EN-001', subject: 'smtp01.enterprise.local', subjectAltNames: ['smtp01.enterprise.local'], issuer: 'Enterprise Internal CA', serialNumber: '01:02:03:04:05:06:07:08', algorithm: 'SHA256withRSA', keySize: 4096, keyType: 'RSA', validFrom: '2025-01-01T00:00:00Z', validUntil: '2027-01-01T23:59:59Z', daysRemaining: 459, chainLength: 2, chainValid: true, status: 'valid', relatedSessionIds: ['SMTP-0193'] },
  { id: 'CERT-PR-001', subject: 'relay.partner-org.com', subjectAltNames: ['relay.partner-org.com', '*.partner-org.com'], issuer: 'Let\'s Encrypt Authority X3', serialNumber: 'AA:BB:CC:DD:EE:FF:00:11', algorithm: 'SHA256withECDSA', keySize: 256, keyType: 'ECDSA P-256', validFrom: '2026-08-15T00:00:00Z', validUntil: '2026-11-13T23:59:59Z', daysRemaining: 45, chainLength: 3, chainValid: true, status: 'valid', relatedSessionIds: ['SMTP-0194'] },
  { id: 'CERT-LG-001', subject: 'pop3.legacy-mail.internal', subjectAltNames: ['pop3.legacy-mail.internal'], issuer: 'Enterprise Internal CA', serialNumber: '11:22:33:44:55:66:77:88', algorithm: 'SHA1withRSA', keySize: 1024, keyType: 'RSA', validFrom: '2020-03-01T00:00:00Z', validUntil: '2025-03-01T23:59:59Z', daysRemaining: -577, chainLength: 2, chainValid: false, status: 'expired', relatedSessionIds: ['POP3-0034'] },
];

// ── Analyses ──

export const mockAnalyses: AnalysisJob[] = [
  { id: 'AN-1029', filename: 'enterprise_mail_q3.pcap', fileSize: 134217728, status: 'completed', progress: 100, sessionsCount: 248, findingsCount: 17, criticalCount: 3, highCount: 7, overallRisk: 78, startedAt: '2026-09-28T08:55:00Z', completedAt: '2026-09-28T09:01:00Z', error: null },
  { id: 'AN-1028', filename: 'branch_office_smtp.pcapng', fileSize: 52428800, status: 'completed', progress: 100, sessionsCount: 92, findingsCount: 4, criticalCount: 0, highCount: 2, overallRisk: 42, startedAt: '2026-09-27T14:20:00Z', completedAt: '2026-09-27T14:25:00Z', error: null },
  { id: 'AN-1030', filename: 'vendor_gateway_capture.pcap', fileSize: 67108864, status: 'completed', progress: 100, sessionsCount: 156, findingsCount: 8, criticalCount: 1, highCount: 3, overallRisk: 61, startedAt: '2026-09-28T10:00:00Z', completedAt: '2026-09-28T10:04:00Z', error: null },
];

// ── Reports ──

export const mockReports: Report[] = [
  { id: 'RPT-EX-001', type: 'executive', title: 'Executive Security Assessment — Q3 Email Infrastructure', analysisId: 'AN-1029', generatedAt: '2026-09-28T09:10:00Z', format: 'PDF', size: 2457600, status: 'ready' },
  { id: 'RPT-TH-001', type: 'technical', title: 'Technical Forensic Report — enterprise_mail_q3.pcap', analysisId: 'AN-1029', generatedAt: '2026-09-28T09:12:00Z', format: 'PDF', size: 8912400, status: 'ready' },
  { id: 'RPT-JS-001', type: 'json', title: 'Machine-Readable Analysis — AN-1029', analysisId: 'AN-1029', generatedAt: '2026-09-28T09:11:00Z', format: 'JSON', size: 1245184, status: 'ready' },
];

// ── System Status ──

export const mockSystemStatus: SystemStatus = {
  backend: 'connected',
  analysisEngine: 'connected',
  aiEngine: 'connected',
  database: 'connected',
  reportEngine: 'connected',
};

// ── Dashboard ──

export const mockDashboard: DashboardData = {
  risk: mockRisk,
  findingsSummary: { critical: 3, high: 7, medium: 4, low: 2, informational: 1, total: 17 },
  sessionsAnalyzed: 248,
  affectedAssets: 12,
  posture: mockPosture,
  recentFindings: mockFindings.slice(0, 5),
  recentAnalyses: mockAnalyses,
};

// ── CBOM ──

export const mockCbom: CbomAsset[] = [
  { id: 'CBOM-001', asset: 'smtp01.enterprise.local', protocol: 'SMTP', tlsVersion: 'TLS 1.0', cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA', keyAlgorithm: 'RSA', keySize: 2048, certificate: 'CERT-EN-001', ja4: 't10d1516h2_8daaf6152771_b2a1c3d4e5f6', risk: 'critical' },
  { id: 'CBOM-002', asset: 'mail.example.com', protocol: 'SMTP', tlsVersion: 'TLS 1.2', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', keyAlgorithm: 'RSA', keySize: 2048, certificate: 'CERT-EX-001', ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1', risk: 'medium' },
  { id: 'CBOM-003', asset: 'imap.example.com', protocol: 'IMAP', tlsVersion: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', keyAlgorithm: 'ECDSA P-256', keySize: 256, certificate: 'CERT-EX-001', ja4: 't13d1517h2_a023bc45d678_f1a2b3c4d5e6', risk: 'low' },
  { id: 'CBOM-004', asset: 'pop3.legacy-mail.internal', protocol: 'POP3', tlsVersion: 'TLS 1.1', cipher: 'TLS_RSA_WITH_AES_256_CBC_SHA', keyAlgorithm: 'RSA', keySize: 1024, certificate: 'CERT-LG-001', ja4: 't11d1516h2_c4d5e6f7a8b9_d1e2f3a4b5c6', risk: 'high' },
  { id: 'CBOM-005', asset: 'imap-legacy.enterprise.local', protocol: 'IMAP', tlsVersion: 'None', cipher: 'None', keyAlgorithm: 'N/A', keySize: 0, certificate: null, ja4: null, risk: 'critical' },
  { id: 'CBOM-006', asset: 'relay.partner-org.com', protocol: 'SMTP', tlsVersion: 'TLS 1.2', cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', keyAlgorithm: 'RSA', keySize: 2048, certificate: 'CERT-PR-001', ja4: 't12d1516h2_e5f6a7b8c9d0_a1b2c3d4e5f6', risk: 'medium' },
];
