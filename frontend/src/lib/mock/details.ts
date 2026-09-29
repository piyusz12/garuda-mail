/* ─── Garuda Mail — Extended Mock Data (Detail Views) ──────────── */

import type {
  SessionDetail, SessionTimelineEvent, PacketRecord,
  TlsAnalysis, Investigation, Ja4Fingerprint,
} from '@/types';
import { mockSessions, mockFindings, mockAnomalies, mockCertificates } from './data';

// ── Session Detail for SMTP-0192 ──

export const mockSessionTimeline: SessionTimelineEvent[] = [
  { timestamp: '2026-09-28T09:01:02.001Z', event: 'TCP Established', detail: 'SYN → SYN-ACK → ACK with 192.168.1.20:45123 → 203.0.113.50:587', type: 'tcp' },
  { timestamp: '2026-09-28T09:01:02.150Z', event: 'SMTP Greeting', detail: '220 mail.example.com ESMTP Postfix', type: 'smtp' },
  { timestamp: '2026-09-28T09:01:02.320Z', event: 'EHLO Command', detail: 'EHLO client.enterprise.local', type: 'smtp' },
  { timestamp: '2026-09-28T09:01:02.480Z', event: 'EHLO Response', detail: '250-mail.example.com, 250-STARTTLS, 250-AUTH PLAIN LOGIN', type: 'smtp' },
  { timestamp: '2026-09-28T09:01:02.650Z', event: 'STARTTLS Requested', detail: 'Client initiated STARTTLS upgrade', type: 'tls' },
  { timestamp: '2026-09-28T09:01:02.820Z', event: 'STARTTLS Accepted', detail: '220 2.0.0 Ready to start TLS', type: 'tls' },
  { timestamp: '2026-09-28T09:01:03.010Z', event: 'TLS ClientHello', detail: 'TLS 1.2, 15 cipher suites offered, SNI: mail.example.com', type: 'tls' },
  { timestamp: '2026-09-28T09:01:03.180Z', event: 'TLS ServerHello', detail: 'TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384', type: 'tls' },
  { timestamp: '2026-09-28T09:01:03.350Z', event: 'Certificate Received', detail: 'CN=mail.example.com, Issuer: DigiCert SHA2 EV CA, Expires: 2026-10-16', type: 'certificate' },
  { timestamp: '2026-09-28T09:01:03.520Z', event: 'Key Exchange', detail: 'ECDHE P-256 key exchange, forward secrecy established', type: 'tls' },
  { timestamp: '2026-09-28T09:01:03.700Z', event: 'TLS Established', detail: 'Encrypted session active — TLS 1.2 with AES-256-GCM', type: 'tls' },
  { timestamp: '2026-09-28T09:01:04.100Z', event: 'Anomaly Detected', detail: 'Unusual cipher preference order, anomaly score 67', type: 'anomaly' },
  { timestamp: '2026-09-28T09:01:04.500Z', event: 'Encrypted Data', detail: '12 application data records, 128 KB total', type: 'data' },
  { timestamp: '2026-09-28T09:01:06.830Z', event: 'TCP FIN', detail: 'Connection closed gracefully', type: 'tcp' },
];

export const mockSessionTls: TlsAnalysis = {
  version: 'TLS 1.2',
  versionNumeric: 0x0303,
  cipherSuite: 'ECDHE-RSA-AES256-GCM-SHA384',
  keyExchange: 'ECDHE (P-256)',
  authentication: 'RSA',
  encryption: 'AES-256-GCM',
  hash: 'SHA-384',
  forwardSecrecy: true,
  sni: 'mail.example.com',
  alpn: [],
  extensions: ['server_name', 'ec_point_formats', 'supported_groups', 'signature_algorithms', 'encrypt_then_mac', 'extended_master_secret'],
  policyStatus: 'acceptable',
};

export const mockPackets: PacketRecord[] = [
  { number: 1, timestamp: '2026-09-28T09:01:02.001Z', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, protocol: 'TCP', length: 74, flags: 'SYN', summary: 'TCP SYN → mail.example.com:587' },
  { number: 2, timestamp: '2026-09-28T09:01:02.045Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'TCP', length: 74, flags: 'SYN,ACK', summary: 'TCP SYN-ACK from mail.example.com' },
  { number: 3, timestamp: '2026-09-28T09:01:02.046Z', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, protocol: 'TCP', length: 66, flags: 'ACK', summary: 'TCP ACK — connection established' },
  { number: 4, timestamp: '2026-09-28T09:01:02.150Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'SMTP', length: 120, flags: 'PSH,ACK', summary: '220 mail.example.com ESMTP Postfix' },
  { number: 5, timestamp: '2026-09-28T09:01:02.320Z', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, protocol: 'SMTP', length: 98, flags: 'PSH,ACK', summary: 'EHLO client.enterprise.local' },
  { number: 6, timestamp: '2026-09-28T09:01:02.480Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'SMTP', length: 210, flags: 'PSH,ACK', summary: '250-mail.example.com EHLO response (STARTTLS, AUTH)' },
  { number: 7, timestamp: '2026-09-28T09:01:02.650Z', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, protocol: 'SMTP', length: 78, flags: 'PSH,ACK', summary: 'STARTTLS' },
  { number: 8, timestamp: '2026-09-28T09:01:02.820Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'SMTP', length: 92, flags: 'PSH,ACK', summary: '220 2.0.0 Ready to start TLS' },
  { number: 1823, timestamp: '2026-09-28T09:01:03.010Z', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, protocol: 'TLS', length: 517, flags: 'PSH,ACK', summary: 'TLS ClientHello (TLS 1.2, 15 cipher suites)' },
  { number: 1824, timestamp: '2026-09-28T09:01:03.180Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'TLS', length: 1420, flags: 'PSH,ACK', summary: 'TLS ServerHello, Certificate, ServerKeyExchange' },
  { number: 1825, timestamp: '2026-09-28T09:01:03.350Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'TLS', length: 2840, flags: 'PSH,ACK', summary: 'X.509 Certificate chain (3 certificates)' },
  { number: 1826, timestamp: '2026-09-28T09:01:03.520Z', sourceIp: '192.168.1.20', sourcePort: 45123, destIp: '203.0.113.50', destPort: 587, protocol: 'TLS', length: 126, flags: 'PSH,ACK', summary: 'ClientKeyExchange, ChangeCipherSpec, Finished' },
  { number: 1827, timestamp: '2026-09-28T09:01:03.700Z', sourceIp: '203.0.113.50', sourcePort: 587, destIp: '192.168.1.20', destPort: 45123, protocol: 'TLS', length: 81, flags: 'PSH,ACK', summary: 'ChangeCipherSpec, Finished' },
];

// ── Investigations ──

export const mockInvestigations: Investigation[] = [
  {
    id: 'INV-001',
    title: 'TLS 1.0 Deprecation on SMTP Gateway',
    description: 'Investigation into the use of deprecated TLS 1.0 on smtp01.enterprise.local. Session SMTP-0193 negotiated a weak cipher suite without forward secrecy.',
    status: 'active',
    createdAt: '2026-09-28T09:30:00Z',
    updatedAt: '2026-09-28T10:15:00Z',
    sessionIds: ['SMTP-0193'],
    findingIds: ['TLS-001', 'TLS-002'],
    notes: [
      { id: 'NOTE-001', content: 'Confirmed TLS 1.0 is negotiated due to server configuration. The MTA software version is Postfix 3.1 which supports TLS 1.2 but has not been configured to disable older protocols.', author: 'Security Analyst', createdAt: '2026-09-28T09:45:00Z' },
      { id: 'NOTE-002', content: 'Contacted infrastructure team for scheduled maintenance window to update TLS configuration.', author: 'Security Analyst', createdAt: '2026-09-28T10:15:00Z' },
    ],
  },
  {
    id: 'INV-002',
    title: 'Unencrypted IMAP Access — Legacy Server',
    description: 'Investigation into plaintext IMAP session on imap-legacy.enterprise.local. Credentials and email content transmitted without encryption.',
    status: 'active',
    createdAt: '2026-09-28T09:50:00Z',
    updatedAt: '2026-09-28T11:00:00Z',
    sessionIds: ['IMAP-0088'],
    findingIds: ['STARTTLS-001'],
    notes: [
      { id: 'NOTE-003', content: 'This legacy IMAP server is used by 3 internal users. Server runs Dovecot 2.2 without TLS configured. Certificate (CERT-LG-001) has expired.', author: 'Security Analyst', createdAt: '2026-09-28T10:00:00Z' },
    ],
  },
];

// ── JA4 Fingerprints ──

export const mockJa4Fingerprints: Ja4Fingerprint[] = [
  { fingerprint: 't13d1516h2_8daaf6152771_e5627efa2ab1', frequency: 4, firstSeen: '2026-09-28T09:01:02Z', lastSeen: '2026-09-28T09:22:11Z', associatedSessions: ['SMTP-0192', 'SMTP-0196'], rarity: 'common' },
  { fingerprint: 't10d1516h2_8daaf6152771_b2a1c3d4e5f6', frequency: 1, firstSeen: '2026-09-28T09:03:17Z', lastSeen: '2026-09-28T09:03:17Z', associatedSessions: ['SMTP-0193'], rarity: 'rare' },
  { fingerprint: 't13d1517h2_a023bc45d678_f1a2b3c4d5e6', frequency: 8, firstSeen: '2026-09-27T14:20:00Z', lastSeen: '2026-09-28T09:15:02Z', associatedSessions: ['IMAP-0087', 'SMTP-0195'], rarity: 'common' },
  { fingerprint: 't11d1516h2_c4d5e6f7a8b9_d1e2f3a4b5c6', frequency: 1, firstSeen: '2026-09-28T09:08:55Z', lastSeen: '2026-09-28T09:08:55Z', associatedSessions: ['POP3-0034'], rarity: 'rare' },
  { fingerprint: 't12d1516h2_e5f6a7b8c9d0_a1b2c3d4e5f6', frequency: 2, firstSeen: '2026-09-28T09:12:33Z', lastSeen: '2026-09-28T09:12:33Z', associatedSessions: ['SMTP-0194'], rarity: 'uncommon' },
  { fingerprint: 't12d1516h2_b3c4d5e6f7a8_c1d2e3f4a5b6', frequency: 3, firstSeen: '2026-09-27T14:22:00Z', lastSeen: '2026-09-28T09:22:11Z', associatedSessions: ['SMTP-0196'], rarity: 'common' },
];

// ── Session Detail Builder ──

export function buildSessionDetail(sessionId: string): SessionDetail | null {
  const session = mockSessions.find((s: any) => s.id === sessionId);
  if (!session) return null;

  const findings = mockFindings.filter((f: any) => f.relatedSessionIds.includes(sessionId));
  const anomalies = mockAnomalies.filter((a: any) => a.sessionId === sessionId);
  const cert = mockCertificates.find((c: any) => c.relatedSessionIds.includes(sessionId)) || null;

  return {
    ...session,
    tls: sessionId === 'SMTP-0192' ? mockSessionTls : session.tlsVersion ? {
      version: session.tlsVersion,
      versionNumeric: session.tlsVersion === 'TLS 1.3' ? 0x0304 : session.tlsVersion === 'TLS 1.2' ? 0x0303 : session.tlsVersion === 'TLS 1.1' ? 0x0302 : 0x0301,
      cipherSuite: session.tlsVersion === 'TLS 1.0' ? 'TLS_RSA_WITH_AES_128_CBC_SHA' : 'ECDHE-RSA-AES256-GCM-SHA384',
      keyExchange: session.tlsVersion === 'TLS 1.0' ? 'RSA' : 'ECDHE (P-256)',
      authentication: 'RSA',
      encryption: session.tlsVersion === 'TLS 1.0' ? 'AES-128-CBC' : 'AES-256-GCM',
      hash: session.tlsVersion === 'TLS 1.0' ? 'SHA-1' : 'SHA-384',
      forwardSecrecy: session.tlsVersion !== 'TLS 1.0' && session.tlsVersion !== 'TLS 1.1',
      sni: session.destHostname,
      alpn: [],
      extensions: ['server_name', 'supported_groups', 'signature_algorithms'],
      policyStatus: session.tlsVersion === 'TLS 1.0' ? 'insecure' as const : session.tlsVersion === 'TLS 1.1' ? 'deprecated' as const : session.tlsVersion === 'TLS 1.3' ? 'compliant' as const : 'acceptable' as const,
    } : null,
    certificate: cert,
    findings,
    anomalies,
    timeline: sessionId === 'SMTP-0192' ? mockSessionTimeline : generateBasicTimeline(session),
    packetRecords: sessionId === 'SMTP-0192' ? mockPackets : [],
  };
}

function generateBasicTimeline(session: any): SessionTimelineEvent[] {
  const ts = session.timestamp;
  const events: SessionTimelineEvent[] = [
    { timestamp: ts, event: 'TCP Established', detail: `${session.sourceIp}:${session.sourcePort} → ${session.destIp}:${session.destPort}`, type: 'tcp' },
  ];
  if (session.protocol !== 'UNKNOWN') {
    events.push({ timestamp: ts, event: `${session.protocol} Greeting`, detail: `Server greeting from ${session.destHostname || session.destIp}`, type: session.protocol.toLowerCase() as any });
  }
  if (session.starttls) {
    events.push({ timestamp: ts, event: 'STARTTLS', detail: 'Client initiated STARTTLS upgrade', type: 'tls' });
  }
  if (session.tlsVersion) {
    events.push({ timestamp: ts, event: 'TLS Handshake', detail: `${session.tlsVersion} negotiated`, type: 'tls' });
    events.push({ timestamp: ts, event: 'Encrypted Session', detail: 'Application data exchange', type: 'data' });
  } else {
    events.push({ timestamp: ts, event: 'Plaintext Session', detail: 'No encryption — data transmitted in cleartext', type: 'data' });
  }
  events.push({ timestamp: ts, event: 'TCP FIN', detail: 'Connection closed', type: 'tcp' });
  return events;
}
