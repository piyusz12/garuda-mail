/* ─── Garuda Mail — Mock Email Data ──────────────────────────────── */
/* Links forensic session data to an analyst-friendly email view.    */
/* Each email is connected to a forensic session via security.sessionId */

import type { EmailMessage } from '@/types/email';

export const mockEmails: EmailMessage[] = [
  {
    id: 'EMAIL-001',
    folder: 'inbox',
    from: { name: 'Security Operations', email: 'security@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Enterprise Security Assessment — Q3 TLS Configuration Review',
    preview: 'Attached findings from the quarterly email infrastructure audit. SMTP gateway smtp01.enterprise.local shows deprecated TLS 1.0 negotiation...',
    body: `Hi Team,

Please find the Q3 email infrastructure security assessment results attached. Key findings:

1. SMTP gateway smtp01.enterprise.local is negotiating TLS 1.0 with several external partners. This is a critical finding as TLS 1.0 has known cryptographic vulnerabilities.

2. The cipher suite TLS_RSA_WITH_AES_128_CBC_SHA lacks forward secrecy. If the server's private key is ever compromised, all past sessions can be decrypted.

3. We detected unusual cipher preference ordering on session SMTP-0192 which triggered our anomaly detection system.

Immediate action items:
- Disable TLS 1.0/1.1 on smtp01.enterprise.local
- Enforce ECDHE-based cipher suites
- Renew expiring certificates (mail.example.com — 18 days remaining)

Please review the attached PCAP analysis and remediation recommendations.

Best regards,
Security Operations Center`,
    timestamp: '2026-09-28T09:01:02Z',
    read: false,
    starred: true,
    attachments: [
      { name: 'enterprise_mail_q3.pcap', size: 134217728, type: 'application/octet-stream' },
      { name: 'q3_assessment_report.pdf', size: 2457600, type: 'application/pdf' },
    ],
    security: {
      level: 'warning',
      tlsVersion: 'TLS 1.2',
      cipher: 'ECDHE-RSA-AES256-GCM-SHA384',
      forwardSecrecy: true,
      starttls: true,
      certificateStatus: 'expiring',
      riskScore: 78,
      anomalyScore: 67,
      findingsCount: 3,
      sessionId: 'SMTP-0192',
    },
    threadId: 'THREAD-001',
    labels: ['security', 'assessment'],
  },
  {
    id: 'EMAIL-002',
    folder: 'inbox',
    from: { name: 'Infrastructure Team', email: 'infra@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'URGENT: SMTP Gateway TLS Downgrade Detected',
    preview: 'Our monitoring detected that smtp01.enterprise.local negotiated TLS 1.0 with 198.51.100.25. The server accepted a deprecated protocol version...',
    body: `URGENT SECURITY ALERT

Our passive monitoring system has detected a TLS downgrade on the SMTP gateway.

Session Details:
- Session ID: SMTP-0193
- Source: 192.168.1.20:45124
- Destination: smtp01.enterprise.local (198.51.100.25:25)
- Negotiated: TLS 1.0 (0x0301)
- Cipher: TLS_RSA_WITH_AES_128_CBC_SHA
- Forward Secrecy: NOT OBSERVED

The client offered TLS 1.2 in ClientHello, but the server selected TLS 1.0. This could indicate:
1. Server misconfiguration
2. An active TLS downgrade attack (MITM)

The resulting session uses CBC mode, which is susceptible to padding oracle attacks.

Action Required:
- Investigate smtp01.enterprise.local configuration immediately
- Check for potential MITM indicators
- Review all sessions from this server in the last 72 hours

This finding has been escalated to Priority: CRITICAL.

— Infrastructure Security`,
    timestamp: '2026-09-28T09:03:17Z',
    read: false,
    starred: false,
    attachments: [],
    security: {
      level: 'critical',
      tlsVersion: 'TLS 1.0',
      cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA',
      forwardSecrecy: false,
      starttls: true,
      certificateStatus: 'valid',
      riskScore: 94,
      anomalyScore: 12,
      findingsCount: 5,
      sessionId: 'SMTP-0193',
    },
    threadId: 'THREAD-002',
    labels: ['critical', 'tls-downgrade'],
  },
  {
    id: 'EMAIL-003',
    folder: 'inbox',
    from: { name: 'Certificate Manager', email: 'certs@example.com', domain: 'example.com' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Certificate Renewal Reminder — mail.example.com (18 days)',
    preview: 'Your TLS certificate for mail.example.com expires on October 16, 2026. Please initiate renewal to avoid service disruption...',
    body: `Certificate Expiry Notice

Domain: mail.example.com
Serial: 0A:1B:2C:3D:4E:5F:6A:7B
Issuer: DigiCert SHA2 Extended Validation Server CA
Expiry: October 16, 2026 (18 days remaining)

Subject Alternative Names:
- mail.example.com
- smtp.example.com

Key: RSA 2048-bit
Signature: SHA256withRSA

This certificate is used by ${2} active sessions in the current analysis.

Please renew this certificate before expiry to prevent TLS connection failures and email delivery disruption.

Certificate renewal instructions:
1. Generate a new CSR with the same SANs
2. Submit to DigiCert for reissuance
3. Deploy the renewed certificate
4. Verify with a post-change PCAP capture

— Certificate Management System`,
    timestamp: '2026-09-28T09:05:00Z',
    read: true,
    starred: false,
    attachments: [
      { name: 'cert_renewal_request.csr', size: 1024, type: 'application/pkcs10' },
    ],
    security: {
      level: 'secure',
      tlsVersion: 'TLS 1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      forwardSecrecy: true,
      starttls: false,
      certificateStatus: 'valid',
      riskScore: 18,
      anomalyScore: 8,
      findingsCount: 0,
      sessionId: 'IMAP-0087',
    },
    threadId: 'THREAD-003',
    labels: ['certificates'],
  },
  {
    id: 'EMAIL-004',
    folder: 'inbox',
    from: { name: 'Legacy Systems', email: 'admin@legacy-mail.internal', domain: 'legacy-mail.internal' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'POP3 Service Status Report — Monthly',
    preview: 'Monthly status report for POP3 service on pop3.legacy-mail.internal. Service uptime 99.2%. TLS configuration requires attention...',
    body: `POP3 Service Monthly Report

Server: pop3.legacy-mail.internal
Protocol: POP3 (port 995)
Report Period: September 2026

Uptime: 99.2%
Total Sessions: 1,247
Average Session Duration: 1.91s

TLS Configuration:
- Version: TLS 1.1 (DEPRECATED)
- Cipher: TLS_RSA_WITH_AES_256_CBC_SHA
- Key: RSA 1024-bit (WEAK)
- Certificate: EXPIRED (March 1, 2025)

⚠ WARNING: This server is using deprecated TLS 1.1 with a 1024-bit RSA key and an expired certificate. This configuration does not meet current security standards.

Recommendations:
1. Upgrade TLS to 1.2 minimum (1.3 preferred)
2. Replace 1024-bit RSA key with 2048-bit or ECDSA
3. Renew expired certificate immediately
4. Consider migrating users to IMAP over port 993

— Legacy Systems Administration`,
    timestamp: '2026-09-28T09:08:55Z',
    read: true,
    starred: false,
    attachments: [
      { name: 'pop3_monthly_report.pdf', size: 524288, type: 'application/pdf' },
    ],
    security: {
      level: 'critical',
      tlsVersion: 'TLS 1.1',
      cipher: 'TLS_RSA_WITH_AES_256_CBC_SHA',
      forwardSecrecy: false,
      starttls: false,
      certificateStatus: 'expired',
      riskScore: 72,
      anomalyScore: null,
      findingsCount: 2,
      sessionId: 'POP3-0034',
    },
    threadId: 'THREAD-004',
    labels: ['legacy', 'pop3'],
  },
  {
    id: 'EMAIL-005',
    folder: 'inbox',
    from: { name: 'Partner Security', email: 'security@partner-org.com', domain: 'partner-org.com' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Re: Cipher Suite Compatibility — 3DES Deprecation',
    preview: 'We acknowledge the 3DES cipher suite issue on relay.partner-org.com. Our engineering team has scheduled the migration to AES-GCM...',
    body: `Hi,

Thank you for bringing the 3DES cipher suite concern to our attention.

We've reviewed the analysis from session SMTP-0194 and confirm that our relay server (relay.partner-org.com) is indeed negotiating TLS_RSA_WITH_3DES_EDE_CBC_SHA.

Our engineering team has:
1. Scheduled a maintenance window for the cipher suite update
2. Planned migration to TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
3. Added TLS 1.3 support to the update scope

Timeline:
- Testing: October 5-7, 2026
- Production deployment: October 8, 2026
- Verification: October 9, 2026

We'll coordinate with your team for post-change verification via PCAP analysis.

Best regards,
Partner Organization Security Team`,
    timestamp: '2026-09-28T09:12:33Z',
    read: true,
    starred: true,
    attachments: [],
    security: {
      level: 'warning',
      tlsVersion: 'TLS 1.2',
      cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
      forwardSecrecy: false,
      starttls: true,
      certificateStatus: 'valid',
      riskScore: 45,
      anomalyScore: 52,
      findingsCount: 1,
      sessionId: 'SMTP-0194',
    },
    threadId: 'THREAD-005',
    labels: ['partner', 'cipher-deprecation'],
  },
  {
    id: 'EMAIL-006',
    folder: 'inbox',
    from: { name: 'Compliance Team', email: 'compliance@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Secure Channel Verification — TLS 1.3 Confirmed',
    preview: 'Verification complete. Session SMTP-0195 to mail.example.com confirmed using TLS 1.3 with AES-256-GCM and ECDHE forward secrecy...',
    body: `Verification Report

Session: SMTP-0195
Protocol: SMTP (port 587)
Source: 192.168.1.20:45200
Destination: mail.example.com (203.0.113.50:587)

TLS Analysis:
✓ TLS 1.3 — Modern and Secure
✓ AES-256-GCM — Strong AEAD encryption
✓ ECDHE — Forward secrecy established
✓ STARTTLS — Successfully negotiated
✓ Certificate — Valid (mail.example.com)

Risk Score: 12/100 (Low)
Anomaly Score: 5/100 (Normal)
Findings: 0

This session meets all current cryptographic security requirements and is compliant with NIST SP 800-52 Rev 2.

— Compliance Verification System`,
    timestamp: '2026-09-28T09:15:02Z',
    read: true,
    starred: false,
    attachments: [],
    security: {
      level: 'secure',
      tlsVersion: 'TLS 1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      forwardSecrecy: true,
      starttls: true,
      certificateStatus: 'valid',
      riskScore: 12,
      anomalyScore: 5,
      findingsCount: 0,
      sessionId: 'SMTP-0195',
    },
    threadId: 'THREAD-006',
    labels: ['compliance', 'verified'],
  },
  {
    id: 'EMAIL-007',
    folder: 'inbox',
    from: { name: 'IMAP Monitor', email: 'monitor@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: '🔴 CRITICAL: Plaintext IMAP Session Detected — Credentials Exposed',
    preview: 'A plaintext IMAP session was detected on imap-legacy.enterprise.local (port 143). User credentials were transmitted without encryption...',
    body: `╔══════════════════════════════════════════════╗
║  CRITICAL SECURITY ALERT — CREDENTIAL EXPOSURE  ║
╚══════════════════════════════════════════════╝

Session: IMAP-0088
Protocol: IMAP (port 143)
Source: 192.168.1.78:53210
Destination: imap-legacy.enterprise.local (198.51.100.25:143)

ALERT DETAILS:
This IMAP session completed authentication and mailbox operations WITHOUT any encryption. The LOGIN command transmitted user credentials in plaintext.

RISK ASSESSMENT:
- Risk Score: 98/100 (CRITICAL)
- Anomaly Score: 78/100 (High)
- No TLS negotiation observed
- No STARTTLS attempt
- Credentials visible to any network observer

AI ANALYSIS:
The anomaly detection system flagged this session for:
• Plaintext IMAP session on modern infrastructure
• Authentication without encryption
• Unusual access time pattern

IMMEDIATE ACTIONS REQUIRED:
1. Reset credentials for the affected user
2. Enforce STARTTLS on IMAP port 143
3. Or migrate to IMAPS (port 993) exclusively
4. Block plaintext IMAP access at the firewall
5. Audit all sessions from this server in the last 30 days

— Security Monitoring System`,
    timestamp: '2026-09-28T09:18:44Z',
    read: false,
    starred: true,
    attachments: [],
    security: {
      level: 'critical',
      tlsVersion: null,
      cipher: null,
      forwardSecrecy: null,
      starttls: false,
      certificateStatus: null,
      riskScore: 98,
      anomalyScore: 78,
      findingsCount: 4,
      sessionId: 'IMAP-0088',
    },
    threadId: 'THREAD-007',
    labels: ['critical', 'plaintext', 'credential-exposure'],
  },
  {
    id: 'EMAIL-008',
    folder: 'inbox',
    from: { name: 'Vendor Gateway', email: 'notifications@vendor-mail.net', domain: 'vendor-mail.net' },
    to: [{ name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Mail Relay Configuration Update — mx.vendor-mail.net',
    preview: 'Configuration changes applied to mx.vendor-mail.net relay. TLS 1.2 with STARTTLS enabled. Review session SMTP-0196 for verification...',
    body: `Relay Configuration Update Notice

Server: mx.vendor-mail.net
Time: September 28, 2026 09:22 UTC

Changes Applied:
- STARTTLS: Enabled and enforced
- TLS Version: TLS 1.2 (minimum)
- Cipher Suite: ECDHE-RSA-AES256-GCM-SHA384 (preferred)

Session Verification:
The most recent session (SMTP-0196) was captured and analyzed:
- Duration: 6.78s
- Packets: 489
- Data: 201 KB
- Risk Score: 38/100 (Medium)
- Anomaly Score: 29/100 (Normal)

Note: One finding was generated related to cipher suite ordering. This is informational and does not indicate a security issue.

Please review the session details and confirm the configuration meets your security policy requirements.

— Vendor Mail Operations`,
    timestamp: '2026-09-28T09:22:11Z',
    read: true,
    starred: false,
    attachments: [
      { name: 'relay_config_diff.txt', size: 4096, type: 'text/plain' },
    ],
    security: {
      level: 'warning',
      tlsVersion: 'TLS 1.2',
      cipher: 'ECDHE-RSA-AES256-GCM-SHA384',
      forwardSecrecy: true,
      starttls: true,
      certificateStatus: 'valid',
      riskScore: 38,
      anomalyScore: 29,
      findingsCount: 1,
      sessionId: 'SMTP-0196',
    },
    threadId: 'THREAD-008',
    labels: ['vendor', 'configuration'],
  },
  // ── Sent emails ──
  {
    id: 'EMAIL-009',
    folder: 'sent',
    from: { name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'Infrastructure Team', email: 'infra@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Re: SMTP Gateway TLS Downgrade — Remediation Plan',
    preview: 'I have reviewed the TLS downgrade on smtp01.enterprise.local. Here is the recommended remediation plan with priority assignments...',
    body: `Hi Infrastructure Team,

I've completed the forensic analysis of the TLS downgrade on smtp01.enterprise.local.

Remediation Plan:
1. [CRITICAL] Disable TLS 1.0 and TLS 1.1 on smtp01.enterprise.local
2. [CRITICAL] Configure minimum TLS version to 1.2
3. [HIGH] Enable ECDHE-based cipher suites as preferred
4. [HIGH] Disable RSA key exchange cipher suites
5. [MEDIUM] Add TLS 1.3 support

Recommended cipher suite order:
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

Please schedule a maintenance window for these changes. I'll run a post-change PCAP analysis to verify.

Best regards,
Security Analyst`,
    timestamp: '2026-09-28T09:35:00Z',
    read: true,
    starred: false,
    attachments: [],
    security: {
      level: 'secure',
      tlsVersion: 'TLS 1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      forwardSecrecy: true,
      starttls: true,
      certificateStatus: 'valid',
      riskScore: 8,
      anomalyScore: null,
      findingsCount: 0,
      sessionId: null,
    },
    threadId: 'THREAD-002',
    labels: ['remediation'],
  },
  {
    id: 'EMAIL-010',
    folder: 'sent',
    from: { name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'Partner Security', email: 'security@partner-org.com', domain: 'partner-org.com' }],
    subject: 'Cipher Suite Compatibility — 3DES Deprecation Notice',
    preview: 'Our analysis has detected that your relay server is negotiating TLS_RSA_WITH_3DES_EDE_CBC_SHA. 3DES is deprecated per NIST SP 800-131A...',
    body: `Dear Partner Security Team,

During our routine email infrastructure analysis, we detected that your relay server (relay.partner-org.com) is negotiating the cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA.

This cipher suite has two concerns:
1. 3DES has been deprecated by NIST SP 800-131A Rev 2
2. RSA key exchange does not provide forward secrecy

We recommend updating to AES-GCM based cipher suites with ECDHE key exchange.

Please let us know your timeline for addressing this.

Best regards,
Garuda Security Analysis Team`,
    timestamp: '2026-09-28T09:10:00Z',
    read: true,
    starred: false,
    attachments: [],
    security: {
      level: 'warning',
      tlsVersion: 'TLS 1.2',
      cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
      forwardSecrecy: false,
      starttls: true,
      certificateStatus: 'valid',
      riskScore: 45,
      anomalyScore: null,
      findingsCount: 0,
      sessionId: 'SMTP-0194',
    },
    threadId: 'THREAD-005',
    labels: ['partner', 'outbound'],
  },
  // ── Draft ──
  {
    id: 'EMAIL-011',
    folder: 'drafts',
    from: { name: 'Garuda Analyst', email: 'analyst@enterprise.local', domain: 'enterprise.local' },
    to: [{ name: 'CISO', email: 'ciso@enterprise.local', domain: 'enterprise.local' }],
    subject: 'Q3 Cryptographic Security Posture — Executive Summary',
    preview: 'Draft executive summary of the Q3 email infrastructure cryptographic security assessment. Overall risk score: 78/100...',
    body: `[DRAFT]

Executive Summary — Q3 Email Infrastructure Cryptographic Security Assessment

Overall Risk Score: 78/100 (HIGH)

Key Metrics:
- Sessions Analyzed: 248
- Total Findings: 17 (3 critical, 7 high)
- Affected Assets: 12
- AI Anomalies: 9

Critical Items:
1. TLS 1.0 in active use on SMTP gateway
2. Plaintext IMAP sessions exposing credentials
3. Expired certificate on legacy POP3 server

[Continue writing...]`,
    timestamp: '2026-09-28T10:00:00Z',
    read: true,
    starred: false,
    attachments: [],
    security: {
      level: 'unknown',
      tlsVersion: null,
      cipher: null,
      forwardSecrecy: null,
      starttls: null,
      certificateStatus: null,
      riskScore: null,
      anomalyScore: null,
      findingsCount: 0,
      sessionId: null,
    },
    threadId: 'THREAD-009',
    labels: ['draft', 'executive'],
  },
];

/** Get emails by folder */
export function getEmailsByFolder(folder: EmailFolder): EmailMessage[] {
  if (folder === 'starred') {
    return mockEmails.filter(e => e.starred && e.folder !== 'trash');
  }
  return mockEmails.filter(e => e.folder === folder);
}

/** Get unread count by folder */
export function getUnreadCounts(): Record<EmailFolder, number> {
  const counts = { inbox: 0, sent: 0, drafts: 0, starred: 0, archive: 0, trash: 0 };
  mockEmails.forEach(e => {
    if (!e.read && e.folder !== 'trash') {
      counts[e.folder]++;
      if (e.starred) counts.starred++;
    }
  });
  return counts;
}

/** Get email by ID */
export function getEmailById(id: string): EmailMessage | undefined {
  return mockEmails.find(e => e.id === id);
}
