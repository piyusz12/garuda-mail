import { create } from 'zustand';

export interface PacketRecord {
  id: number;
  timestamp: number;
  timeOffsetMs: number;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP' | 'TLS' | 'SMTP' | 'IMAP' | 'POP3';
  length: number;
  info: string;
  tlsRecordType?: number;
  tlsContentType?: string;
  handshakeType?: number;
  handshakeName?: string;
  rawHex?: string;
}

export interface TlsStepNode {
  id: string;
  index: number;
  name: string;
  direction: 'client-to-server' | 'server-to-client';
  type: 'ClientHello' | 'ServerHello' | 'Certificate' | 'ServerKeyExchange' | 'ClientKeyExchange' | 'ChangeCipherSpec' | 'Finished' | 'EncryptedData';
  version: string;
  cipher?: string;
  extensions?: string[];
  keyExchange?: string;
  alpn?: string[];
  sni?: string;
  hexDump: string;
  parsedSummary: Record<string, string | number | boolean | string[]>;
  timestampMs: number;
  status: 'valid' | 'warning' | 'critical';
}

export interface CertNode {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  keyType: string;
  keySize: number;
  signatureAlgorithm: string;
  status: 'trusted' | 'expiring' | 'expired' | 'self-signed' | 'weak';
  parentId?: string;
  sanList: string[];
  fingerprintSha256: string;
}

export interface Ja4Fingerprint {
  hash: string;
  protocol: string;
  tlsVersion: string;
  cipherCount: number;
  extensionCount: number;
  alpnFirst: string;
  userAgentGuess: string;
  riskRating: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  threatName?: string;
  count: number;
}

export interface ThreatItem {
  id: string;
  title: string;
  category: 'PROTOCOL_DOWNGRADE' | 'CERTIFICATE_FAILURE' | 'WEAK_CIPHER' | 'PLAINTEXT_LEAK' | 'MALICIOUS_JA4';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cve?: string;
  description: string;
  affectedSession: string;
  recommendation: string;
}

export interface ForensicState {
  // Ingestion & File State
  fileName: string | null;
  fileSizeBytes: number;
  packetCount: number;
  isProcessing: boolean;
  processingProgress: number;
  processingStage: string;
  airGappedMode: boolean;

  // Parsed Stream Data
  packets: PacketRecord[];
  tlsSteps: TlsStepNode[];
  activeStepIndex: number;
  isPlaying: boolean;
  playbackSpeed: number;

  // X.509 Certificate Hierarchy
  certificates: CertNode[];
  selectedCertId: string | null;

  // AI Security Posture & JA4
  securityScore: number;
  ja4Fingerprints: Ja4Fingerprint[];
  activeJa4Filter: string | null;
  threats: ThreatItem[];

  // Actions
  loadFile: (file: File) => Promise<void>;
  loadSampleSession: () => void;
  setActiveStepIndex: (index: number) => void;
  nextStep: () => void;
  prevStep: () => void;
  setIsPlaying: (playing: boolean) => void;
  setPlaybackSpeed: (speed: number) => void;
  setSelectedCertId: (id: string | null) => void;
  setActiveJa4Filter: (filter: string | null) => void;
  reset: () => void;
}

const SAMPLE_TLS_STEPS: TlsStepNode[] = [
  {
    id: 'step-1',
    index: 0,
    name: 'ClientHello',
    direction: 'client-to-server',
    type: 'ClientHello',
    version: 'TLS 1.3',
    sni: 'mail.enterprise.local',
    alpn: ['smtp', 'esmtp'],
    keyExchange: 'x25519, secp256r1, Kyber-768',
    cipher: 'Offering 18 Cipher Suites (Preferred: TLS_AES_256_GCM_SHA384)',
    extensions: ['server_name', 'supported_versions', 'key_share', 'signature_algorithms', 'alpn'],
    timestampMs: 0.12,
    status: 'valid',
    hexDump: '16 03 01 01 fc 01 00 01 f8 03 03 a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90 20 e1 e2 e3 e4 e5 e6 e7 e8 00 24 13 02 13 01 13 03 c0 2b c0 2f cca9 cca8 00 9c 00 9d',
    parsedSummary: {
      'Handshake Version': 'TLS 1.3 (Draft RFC 8446)',
      'Random Nonce': 'a1b2c3d4e5f60718293a4b5c6d7e8f90...',
      'Session ID Length': '32 bytes (Echo fallback)',
      'Cipher Suites Offered': 18,
      'PQC Hybrid Key Shares': 'x25519Kyber768Draft00 (0x6399)',
      'Server Name Indication': 'mail.enterprise.local',
      'Supported Groups': 'x25519, secp256r1, secp384r1, mlkem768',
      'Signature Schemes': 'ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256',
    },
  },
  {
    id: 'step-2',
    index: 1,
    name: 'ServerHello',
    direction: 'server-to-client',
    type: 'ServerHello',
    version: 'TLS 1.3',
    cipher: 'TLS_AES_256_GCM_SHA384 (0x1302)',
    keyExchange: 'x25519 + Kyber-768 Hybrid Secret Agreement',
    timestampMs: 14.85,
    status: 'valid',
    hexDump: '16 03 03 00 7a 02 00 00 76 03 03 f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b 3c 2d 1e 0f 20 e1 e2 e3 e4 e5 e6 e7 e8 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20',
    parsedSummary: {
      'Handshake Version': 'TLS 1.3 Negotiated',
      'Selected Cipher Suite': 'TLS_AES_256_GCM_SHA384',
      'Key Share Agreement': 'PQC Kyber-768 Secret Finalized',
      'Server Random': 'f0e1d2c3b4a5968778695a4b3c2d1e0f...',
      'Early Data Accepted': false,
      'Forward Secrecy': 'Active (Ephemeral Diffie-Hellman + Post-Quantum Lattice)',
    },
  },
  {
    id: 'step-3',
    index: 2,
    name: 'Certificate & Chain',
    direction: 'server-to-client',
    type: 'Certificate',
    version: 'X.509v3',
    cipher: '2048-bit RSA with SHA-256 (Expiring in 18 days)',
    timestampMs: 18.22,
    status: 'warning',
    hexDump: '16 03 03 0b 4a 0b 00 0b 46 00 0b 43 00 05 a1 30 82 05 9d 30 82 04 85 a0 03 02 01 02 02 10 4d 7e 8a 1b 2c 3d 4e 5f 60 71 82 93 a4 b5 c6 d7 30 0d 06 09 2a 86 48 86 f7',
    parsedSummary: {
      'Certificate Subject': 'CN=mail.enterprise.local, O=Garuda Enterprise, C=IN',
      'Issuer': 'CN=Garuda Enterprise Intermediate CA 2026',
      'Key Type': 'RSA 2048 bits (Warning: Recommend ECDSA P-384 or Kyber)',
      'Signature Algorithm': 'sha256WithRSAEncryption (1.2.840.113549.1.1.11)',
      'Validity Window': '2025-10-22 to 2026-10-22',
      'Status': 'Expiring soon in 18 days',
      'SAN Extension': 'mail.enterprise.local, smtp.enterprise.local, autodiscover.enterprise.local',
    },
  },
  {
    id: 'step-4',
    index: 3,
    name: 'ServerKeyExchange / Extensions',
    direction: 'server-to-client',
    type: 'ServerKeyExchange',
    version: 'TLS 1.3',
    timestampMs: 22.05,
    status: 'valid',
    hexDump: '16 03 03 00 c8 08 00 00 c4 00 c2 00 08 00 06 05 68 32 04 73 6d 74 70 00 0a 00 08 00 06 00 1d 00 17 00 18 00 23 00 00 00 2b 00 02 03 04 00 0d 00 16 00 14 04 03 05 03',
    parsedSummary: {
      'Encrypted Extensions': 'ALPN (smtp), Supported Groups Confirmed',
      'Certificate Request': 'None (Server-only authentication)',
      'Certificate Verify': 'ECDSA signature over handshake transcript',
    },
  },
  {
    id: 'step-5',
    index: 4,
    name: 'ChangeCipherSpec / Finished',
    direction: 'server-to-client',
    type: 'ChangeCipherSpec',
    version: 'TLS 1.3',
    timestampMs: 24.12,
    status: 'valid',
    hexDump: '14 03 03 00 01 01 16 03 03 00 34 8c e4 99 22 71 a3 bb 99 44 11 00 f2 e8 99 aa cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff',
    parsedSummary: {
      'Record Type': 'ChangeCipherSpec (Compatibility dummy for TLS 1.3)',
      'Finished MAC': 'HMAC-SHA384 transcript verification verified',
      'State': 'Handshake Keys transitioned to Application Traffic Keys',
    },
  },
  {
    id: 'step-6',
    index: 5,
    name: 'Encrypted Application Data',
    direction: 'client-to-server',
    type: 'EncryptedData',
    version: 'TLS 1.3',
    timestampMs: 28.94,
    status: 'valid',
    hexDump: '17 03 03 01 a0 4e 89 b2 3f 9a 11 8c df a2 00 19 8c 77 12 99 aa 33 fe dc ba 98 76 54 32 10 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 a0 b1 c2 d3 e4 f5',
    parsedSummary: {
      'Content Type': 'Application Data (0x17)',
      'Ciphertext Length': '416 bytes',
      'Authentication Tag': '16-byte Poly1305 / GCM Tag verified',
      'Payload Type': 'ESMTP Commands: EHLO, STARTTLS, MAIL FROM, RCPT TO, DATA (Protected)',
    },
  },
];

const SAMPLE_CERTS: CertNode[] = [
  {
    id: 'cert-root',
    subject: 'GlobalSign Root CA - R3',
    issuer: 'GlobalSign Root CA - R3',
    serialNumber: '04:00:00:00:00:01:15:4B:5A:C3:94',
    validFrom: '2019-03-18',
    validTo: '2039-03-18',
    daysRemaining: 4548,
    keyType: 'RSA',
    keySize: 4096,
    signatureAlgorithm: 'SHA384withRSA',
    status: 'trusted',
    sanList: [],
    fingerprintSha256: 'D6:9B:56:11:48:0D:1C:62:CD:C8:51:72:A6:97:1B:61:52:CE:43:99:02:C2:C5:44:E6:E0:0F:17:5C:E3:22:9B',
  },
  {
    id: 'cert-intermediate',
    subject: 'Garuda Enterprise Intermediate CA 2026',
    issuer: 'GlobalSign Root CA - R3',
    serialNumber: '7A:91:02:44:81:CC:09:12:FE:33',
    validFrom: '2023-01-01',
    validTo: '2028-01-01',
    daysRemaining: 454,
    keyType: 'ECDSA',
    keySize: 384,
    signatureAlgorithm: 'SHA384withECDSA',
    status: 'trusted',
    parentId: 'cert-root',
    sanList: ['ca.enterprise.local'],
    fingerprintSha256: '88:41:2B:EE:99:A1:04:77:23:CD:45:90:12:AB:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56',
  },
  {
    id: 'cert-leaf',
    subject: 'mail.enterprise.local',
    issuer: 'Garuda Enterprise Intermediate CA 2026',
    serialNumber: '4D:7E:8A:1B:2C:3D:4E:5F:60:71:82:93',
    validFrom: '2025-10-22',
    validTo: '2026-10-22',
    daysRemaining: 18,
    keyType: 'RSA',
    keySize: 2048,
    signatureAlgorithm: 'SHA256withRSA',
    status: 'expiring',
    parentId: 'cert-intermediate',
    sanList: ['mail.enterprise.local', 'smtp.enterprise.local', 'autodiscover.enterprise.local'],
    fingerprintSha256: '3E:A1:7B:90:44:55:12:89:C0:EE:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66',
  },
  {
    id: 'cert-legacy',
    subject: 'pop3.legacy-mail.internal (Self-Signed)',
    issuer: 'pop3.legacy-mail.internal',
    serialNumber: '00:99:AA:BB:CC:DD',
    validFrom: '2020-01-01',
    validTo: '2025-01-01',
    daysRemaining: -642,
    keyType: 'RSA',
    keySize: 1024,
    signatureAlgorithm: 'SHA1withRSA (Insecure)',
    status: 'expired',
    sanList: ['pop3.legacy-mail.internal'],
    fingerprintSha256: 'FA:FA:FA:FA:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:AA:BB:CC',
  }
];

const SAMPLE_JA4: Ja4Fingerprint[] = [
  {
    hash: 't13d1516h2_8daaf6152771_e5627efa2ab1',
    protocol: 'TCP / TLS 1.3',
    tlsVersion: '1.3',
    cipherCount: 15,
    extensionCount: 16,
    alpnFirst: 'h2',
    userAgentGuess: 'Google Chrome / modern ESMTP client',
    riskRating: 'BENIGN',
    count: 142,
  },
  {
    hash: 't12d1808h1_22a10599cb10_39dcae449910',
    protocol: 'TCP / TLS 1.2',
    tlsVersion: '1.2',
    cipherCount: 18,
    extensionCount: 8,
    alpnFirst: 'http/1.1',
    userAgentGuess: 'Legacy Python Requests / Custom Automation',
    riskRating: 'SUSPICIOUS',
    threatName: 'Non-Standard TLS Fingerprint on SMTP Relay',
    count: 14,
  },
  {
    hash: 't10i050200_a99f1100ee22_000000000000',
    protocol: 'TCP / TLS 1.0',
    tlsVersion: '1.0 (Deprecated)',
    cipherCount: 5,
    extensionCount: 2,
    alpnFirst: 'none',
    userAgentGuess: 'Automated Vulnerability Scanner / Downgrade Exploit',
    riskRating: 'MALICIOUS',
    threatName: 'BEAST / Downgrade Attack Vector (CVE-2011-3389)',
    count: 3,
  },
];

const SAMPLE_THREATS: ThreatItem[] = [
  {
    id: 'thr-1',
    title: 'Deprecated TLS 1.0 Negotiation Detected',
    category: 'PROTOCOL_DOWNGRADE',
    severity: 'CRITICAL',
    cve: 'CVE-2011-3389 (BEAST)',
    description: 'A remote client initiated a TLS 1.0 handshake on port 587 offering CBC-mode ciphers without modern extension safeguards.',
    affectedSession: 'SMTP-Session #0192',
    recommendation: 'Enforce MinVersion TLSv1.2 in server cipher suite settings and disallow downgrade negotiation.',
  },
  {
    id: 'thr-2',
    title: 'X.509 Leaf Certificate Expiring within 18 Days',
    category: 'CERTIFICATE_FAILURE',
    severity: 'HIGH',
    description: 'The certificate for mail.enterprise.local expires on 2026-10-22. Client SMTP dispatch will fail once expired.',
    affectedSession: 'mail.enterprise.local:587',
    recommendation: 'Rotate the TLS certificate using automated ACME / Let\'s Encrypt or corporate PKI renewal.',
  },
  {
    id: 'thr-3',
    title: 'Legacy Self-Signed Certificate with SHA-1 & 1024-bit RSA',
    category: 'WEAK_CIPHER',
    severity: 'CRITICAL',
    cve: 'CVE-2005-4900 (SHAttered)',
    description: 'Gateway pop3.legacy-mail.internal is serving an expired certificate with 1024-bit RSA and weak SHA-1 signatures.',
    affectedSession: 'POP3-Session #0044',
    recommendation: 'Decommission legacy POP3 node or re-issue with minimum 2048-bit RSA or ECDSA P-256.',
  },
  {
    id: 'thr-4',
    title: 'Suspicious JA4 Fingerprint Beaconing',
    category: 'MALICIOUS_JA4',
    severity: 'HIGH',
    description: 'Fingerprint t10i050200_a99f1100ee22 matches automated reconnaissance toolkits scanning mail services.',
    affectedSession: '192.168.1.185 -> 192.168.1.3:587',
    recommendation: 'Blacklist source IP on edge firewall and inspect mail transmission logs for brute-force attempts.',
  },
];

export const usePcapStore = create<ForensicState>((set, get) => ({
  fileName: 'enterprise_pcap_capture_2026.pcap',
  fileSizeBytes: 14285714,
  packetCount: 384,
  isProcessing: false,
  processingProgress: 100,
  processingStage: 'Ready',
  airGappedMode: true,

  packets: [],
  tlsSteps: SAMPLE_TLS_STEPS,
  activeStepIndex: 0,
  isPlaying: false,
  playbackSpeed: 1000,

  certificates: SAMPLE_CERTS,
  selectedCertId: 'cert-leaf',

  securityScore: 78,
  ja4Fingerprints: SAMPLE_JA4,
  activeJa4Filter: null,
  threats: SAMPLE_THREATS,

  loadFile: async (file: File) => {
    set({
      fileName: file.name,
      fileSizeBytes: file.size,
      isProcessing: true,
      processingProgress: 10,
      processingStage: 'Reading raw PCAP bytes in local browser memory...',
    });

    // Zero-network local processing simulation (air-gapped via browser FileReader)
    await new Promise(r => setTimeout(r, 400));
    set({ processingProgress: 35, processingStage: 'Reconstructing TCP streams & TLS record layers...' });

    await new Promise(r => setTimeout(r, 600));
    set({ processingProgress: 70, processingStage: 'Extracting X.509 chains & computing JA4+ fingerprints...' });

    await new Promise(r => setTimeout(r, 400));
    set({ processingProgress: 90, processingStage: 'Running deterministic security rules & AI threat inference...' });

    await new Promise(r => setTimeout(r, 300));
    set({
      isProcessing: false,
      processingProgress: 100,
      processingStage: 'Analysis complete',
      packetCount: Math.round(file.size / 350) + 120,
      activeStepIndex: 0,
    });
  },

  loadSampleSession: () => {
    set({
      fileName: 'enterprise_mail_demo.pcap',
      fileSizeBytes: 8492040,
      packetCount: 256,
      tlsSteps: SAMPLE_TLS_STEPS,
      activeStepIndex: 0,
      certificates: SAMPLE_CERTS,
      ja4Fingerprints: SAMPLE_JA4,
      threats: SAMPLE_THREATS,
      securityScore: 82,
      isProcessing: false,
    });
  },

  setActiveStepIndex: (index: number) => {
    const { tlsSteps } = get();
    if (index >= 0 && index < tlsSteps.length) {
      set({ activeStepIndex: index });
    }
  },

  nextStep: () => {
    const { activeStepIndex, tlsSteps } = get();
    if (activeStepIndex < tlsSteps.length - 1) {
      set({ activeStepIndex: activeStepIndex + 1 });
    } else {
      set({ isPlaying: false });
    }
  },

  prevStep: () => {
    const { activeStepIndex } = get();
    if (activeStepIndex > 0) {
      set({ activeStepIndex: activeStepIndex - 1 });
    }
  },

  setIsPlaying: (playing: boolean) => set({ isPlaying: playing }),
  setPlaybackSpeed: (speed: number) => set({ playbackSpeed: speed }),
  setSelectedCertId: (id: string | null) => set({ selectedCertId: id }),
  setActiveJa4Filter: (filter: string | null) => set({ activeJa4Filter: filter }),
  reset: () => set({ activeStepIndex: 0, isPlaying: false, activeJa4Filter: null }),
}));
