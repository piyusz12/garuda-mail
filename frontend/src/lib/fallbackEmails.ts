export interface FallbackEmail {
  id: string;
  subject: string;
  body: string;
  preview: string;
  fromId: string;
  from: {
    id: string;
    name: string;
    email: string;
    avatarColor?: string;
  };
  tlsVersion: string | null;
  cipher: string | null;
  forwardSecrecy: boolean;
  starttls: boolean;
  riskScore: number;
  folder: string;
  starred: boolean;
  draft?: boolean;
  createdAt: string;
  sentAt?: string;
  recipients: Array<{
    id: string;
    address: string;
    name: string;
    userId: string | null;
    folder: string;
    read: boolean;
    starred: boolean;
  }>;
  attachments?: any[];
  labels?: any[];
}

export const FALLBACK_EMAILS: FallbackEmail[] = [
  {
    id: 'email-tls-review-001',
    subject: 'Enterprise Security Assessment — Q3 TLS Configuration Review',
    body: `Hi Team,\n\nPlease find the Q3 email infrastructure security assessment results attached. Key findings:\n\n1. SMTP gateway smtp01.enterprise.local is negotiating TLS 1.0 with several external partners. This is a critical finding as TLS 1.0 has known cryptographic vulnerabilities.\n\n2. The cipher suite TLS_RSA_WITH_AES_128_CBC_SHA lacks forward secrecy. If the server's private key is ever compromised, all past sessions can be decrypted.\n\n3. We detected unusual cipher preference ordering on session SMTP-0192 which triggered our anomaly detection system.\n\nImmediate action items:\n- Deprecate TLS 1.0/1.1 across all MTAs immediately\n- Prioritize ECDHE suites to enforce Forward Secrecy\n- Rotate expired certificates on imap.legacy.corp\n\nFull PCAP captures and CBOM inventory have been indexed in Garuda Mail for forensic review.\n\nRegards,\nSecurity Operations Team`,
    preview: 'Attached findings from the quarterly email infrastructure audit. SMTP gateway smtp01.enterprise.local shows deprecated TLS 1.0 negotiation...',
    fromId: 'user-security-004',
    from: {
      id: 'user-security-004',
      name: 'Security Operations',
      email: 'security@enterprise.local',
      avatarColor: '#F43F5E',
    },
    tlsVersion: 'TLS 1.0',
    cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    forwardSecrecy: false,
    starttls: true,
    riskScore: 85,
    folder: 'inbox',
    starred: true,
    createdAt: '2026-10-04T10:15:00Z',
    sentAt: '2026-10-04T10:15:00Z',
    recipients: [
      {
        id: 'rec-001',
        address: 'analyst@enterprise.local',
        name: 'Garuda Analyst',
        userId: 'user-analyst-003',
        folder: 'inbox',
        read: false,
        starred: true,
      },
    ],
  },
  {
    id: 'email-plaintext-imap-002',
    subject: 'Plaintext IMAP Transmission Alert — Immediate Remediation Required',
    body: `CRITICAL ALERT — INCIDENT #SEC-2026-0891\n\nAutomated sensor probe has detected unencrypted IMAP traffic on TCP port 143 from internal subnet 10.0.12.0/24.\n\nProtocol analysis confirms:\n- Client requested STARTTLS, server returned -ERR Unrecognized Command\n- Client subsequently transmitted credentials in PLAINTEXT\n- Affected user session: FLOW-00004\n\nMitigation steps executed:\n- Port 143 traffic redirected to quarantine VLAN\n- Credential revocation ticket opened with IAM\n- Forensics team assigned to packet stream extraction\n\nPlease review the attached session flow in the Forensic Sessions tab.\n\nSOC Alert Dispatcher`,
    preview: 'CRITICAL ALERT — Automated sensor probe has detected unencrypted IMAP traffic on TCP port 143 without TLS encryption...',
    fromId: 'user-security-004',
    from: {
      id: 'user-security-004',
      name: 'Security Operations',
      email: 'security@enterprise.local',
      avatarColor: '#F43F5E',
    },
    tlsVersion: null,
    cipher: null,
    forwardSecrecy: false,
    starttls: false,
    riskScore: 95,
    folder: 'inbox',
    starred: true,
    createdAt: '2026-10-04T14:30:00Z',
    sentAt: '2026-10-04T14:30:00Z',
    recipients: [
      {
        id: 'rec-002',
        address: 'analyst@enterprise.local',
        name: 'Garuda Analyst',
        userId: 'user-analyst-003',
        folder: 'inbox',
        read: false,
        starred: true,
      },
    ],
  },
  {
    id: 'email-pqc-readiness-003',
    subject: 'Post-Quantum Cryptography (PQC) Readiness — CBOM Milestone 2 Update',
    body: `Hello Garuda Forensic Analysts,\n\nWe have completed our Post-Quantum Cryptography (PQC) audit of the email gateway cryptographic bill of materials (CBOM):\n\n- 82% of current MTAs are operating with classical RSA-2048 keys\n- Hybrid post-quantum key exchange (X25519Kyber768Draft00) is now supported on Edge Gateway smtp-pqc.enterprise.local\n- Zero quantum-vulnerable long-lived session keys observed on core infrastructure\n\nCheck out the CBOM workspace in the sidebar to visualize the asset inventory and post-quantum readiness scores.\n\nBest,\nAlice Vance\nCryptography Team`,
    preview: 'Completed audit of email gateway cryptographic bill of materials. Hybrid post-quantum key exchange enabled on Edge Gateway...',
    fromId: 'user-alice-006',
    from: {
      id: 'user-alice-006',
      name: 'Alice Vance',
      email: 'alice@enterprise.local',
      avatarColor: '#8B5CF6',
    },
    tlsVersion: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    forwardSecrecy: true,
    starttls: true,
    riskScore: 10,
    folder: 'inbox',
    starred: false,
    createdAt: '2026-10-03T09:00:00Z',
    sentAt: '2026-10-03T09:00:00Z',
    recipients: [
      {
        id: 'rec-003',
        address: 'analyst@enterprise.local',
        name: 'Garuda Analyst',
        userId: 'user-analyst-003',
        folder: 'inbox',
        read: true,
        starred: false,
      },
    ],
  },
  {
    id: 'email-downgrade-investigation-004',
    subject: 'Investigation Closed: Suspected Downgrade Attack on relay-02',
    body: `Analyst Team,\n\nInvestigation INV-2026-042 regarding the suspected STARTTLS stripping attack on relay-02 has concluded.\n\nRoot Cause: Middlebox firewall configuration pushed an MTU clamp that fragmented the EHLO STARTTLS response packet, causing client fallback.\nResolution: Rule updated to preserve full STARTTLS capability advertisement.\n\nStatus: CLOSED — False Positive (Network Misconfiguration).\n\nThanks,\nBob Henderson`,
    preview: 'Investigation INV-2026-042 regarding the suspected STARTTLS stripping attack on relay-02 has concluded. Root cause: middlebox MTU clamp...',
    fromId: 'user-bob-005',
    from: {
      id: 'user-bob-005',
      name: 'Bob Henderson',
      email: 'bob@enterprise.local',
      avatarColor: '#10B981',
    },
    tlsVersion: 'TLS 1.3',
    cipher: 'TLS_AES_128_GCM_SHA256',
    forwardSecrecy: true,
    starttls: true,
    riskScore: 15,
    folder: 'inbox',
    starred: false,
    createdAt: '2026-10-02T16:45:00Z',
    sentAt: '2026-10-02T16:45:00Z',
    recipients: [
      {
        id: 'rec-004',
        address: 'analyst@enterprise.local',
        name: 'Garuda Analyst',
        userId: 'user-analyst-003',
        folder: 'inbox',
        read: true,
        starred: false,
      },
    ],
  },
  {
    id: 'email-partner-audit-005',
    subject: 'Outbound Security Audit: Partners Gateway Compliance Report',
    body: `To: partner-ops@external-partner.org\n\nThis is an automated delivery confirmation for the monthly security compliance report.\n\nConnection negotiated: TLS 1.3 with Forward Secrecy.\nCertificate validated against CA root store.\n\nGaruda Automated Security Gateway`,
    preview: 'Automated delivery confirmation for monthly security compliance report. Connection negotiated TLS 1.3 with Forward Secrecy...',
    fromId: 'user-thalendra-001',
    from: {
      id: 'user-thalendra-001',
      name: 'Thalendra Bhaskar',
      email: 'bhaskarthalendra@gmail.com',
      avatarColor: '#38BDF8',
    },
    tlsVersion: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    forwardSecrecy: true,
    starttls: true,
    riskScore: 5,
    folder: 'sent',
    starred: false,
    createdAt: '2026-10-01T11:20:00Z',
    sentAt: '2026-10-01T11:20:00Z',
    recipients: [
      {
        id: 'rec-005',
        address: 'partner-ops@external-partner.org',
        name: 'Partner Operations',
        userId: null,
        folder: 'sent',
        read: true,
        starred: false,
      },
    ],
  },
];

export function getFallbackEmailsResponse(folder: string = 'inbox', search: string = '') {
  let list = FALLBACK_EMAILS;

  if (folder === 'starred') {
    list = list.filter(e => e.starred);
  } else if (folder === 'sent') {
    list = list.filter(e => e.folder === 'sent');
  } else if (folder === 'drafts' || folder === 'draft') {
    list = list.filter(e => e.draft);
  } else if (folder === 'trash') {
    list = [];
  } else if (folder === 'archive') {
    list = [];
  } else {
    // inbox
    list = list.filter(e => e.folder === 'inbox');
  }

  if (search) {
    const s = search.toLowerCase();
    list = list.filter(e => e.subject.toLowerCase().includes(s) || e.body.toLowerCase().includes(s));
  }

  return {
    emails: list,
    unreadCounts: {
      inbox: 2,
      starred: 2,
      sent: 0,
      drafts: 0,
      trash: 0,
      archive: 0,
    },
    page: 1,
    total: list.length,
  };
}
