/**
 * Constants — App-wide enumerations and configuration
 */

// Standard email protocol ports
export const PORTS = {
  SMTP: 25,
  SMTP_SUBMISSION: 587,
  SMTPS: 465,
  IMAP: 143,
  IMAPS: 993,
  POP3: 110,
  POP3S: 995
};

export const IMPLICIT_TLS_PORTS = new Set([465, 993, 995]);
export const EMAIL_PORTS = new Set([25, 110, 143, 465, 587, 993, 995]);

// Protocol identifiers
export const PROTOCOL = {
  SMTP: 'SMTP',
  IMAP: 'IMAP',
  POP3: 'POP3',
  UNKNOWN: 'UNKNOWN'
};

// TLS versions
export const TLS_VERSION = {
  0x0200: 'SSL 2.0',
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3'
};

export const TLS_VERSION_SECURITY = {
  0x0200: { level: 'critical', label: 'Catastrophically Broken', compliant: false },
  0x0300: { level: 'critical', label: 'Broken (POODLE)', compliant: false },
  0x0301: { level: 'critical', label: 'Deprecated (RFC 8996)', compliant: false },
  0x0302: { level: 'critical', label: 'Deprecated (RFC 8996)', compliant: false },
  0x0303: { level: 'medium', label: 'Acceptable (configure AEAD)', compliant: true },
  0x0304: { level: 'low', label: 'Modern & Secure', compliant: true }
};

// TLS record types
export const TLS_RECORD_TYPE = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23
};

// TLS handshake message types
export const TLS_HANDSHAKE_TYPE = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  CERTIFICATE: 11,
  SERVER_KEY_EXCHANGE: 12,
  CERTIFICATE_REQUEST: 13,
  SERVER_HELLO_DONE: 14,
  CERTIFICATE_VERIFY: 15,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20,
  ENCRYPTED_EXTENSIONS: 8
};

// TLS Extensions
export const TLS_EXTENSION = {
  SERVER_NAME: 0,
  ELLIPTIC_CURVES: 10,
  EC_POINT_FORMATS: 11,
  SIGNATURE_ALGORITHMS: 13,
  ALPN: 16,
  EXTENDED_MASTER_SECRET: 23,
  SESSION_TICKET: 35,
  SUPPORTED_VERSIONS: 43,
  PSK_KEY_EXCHANGE_MODES: 45,
  KEY_SHARE: 51,
  RENEGOTIATION_INFO: 65281
};

export const TLS_EXTENSION_NAMES = {
  0: 'server_name',
  1: 'max_fragment_length',
  5: 'status_request',
  10: 'supported_groups',
  11: 'ec_point_formats',
  13: 'signature_algorithms',
  14: 'use_srtp',
  15: 'heartbeat',
  16: 'application_layer_protocol_negotiation',
  18: 'signed_certificate_timestamp',
  21: 'padding',
  23: 'extended_master_secret',
  35: 'session_ticket',
  41: 'pre_shared_key',
  42: 'early_data',
  43: 'supported_versions',
  44: 'cookie',
  45: 'psk_key_exchange_modes',
  47: 'certificate_authorities',
  48: 'oid_filters',
  49: 'post_handshake_auth',
  50: 'signature_algorithms_cert',
  51: 'key_share',
  65281: 'renegotiation_info'
};

// GREASE values to filter out
export const GREASE_VALUES = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
  0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa
]);

// Risk levels
export const RISK_LEVEL = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

// TCP flags
export const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
};

// IP Protocol numbers
export const IP_PROTO = {
  TCP: 6,
  UDP: 17
};

// PCAP magic numbers
export const PCAP_MAGIC_LE = 0xa1b2c3d4;
export const PCAP_MAGIC_BE = 0xd4c3b2a1;
export const PCAP_MAGIC_NS_LE = 0xa1b23c4d;
export const PCAP_MAGIC_NS_BE = 0x4d3cb2a1;

// Ethernet types
export const ETHERTYPE = {
  IPv4: 0x0800,
  IPv6: 0x86DD,
  VLAN: 0x8100
};

// Signature algorithms
export const SIG_ALGO_NAMES = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512'
};

export const NAMED_CURVES = {
  23: { name: 'secp256r1 (P-256)', bits: 256, nistApproved: true },
  24: { name: 'secp384r1 (P-384)', bits: 384, nistApproved: true },
  25: { name: 'secp521r1 (P-521)', bits: 521, nistApproved: true },
  29: { name: 'x25519', bits: 256, nistApproved: false },
  30: { name: 'x448', bits: 448, nistApproved: false },
  256: { name: 'ffdhe2048', bits: 2048, nistApproved: true },
  257: { name: 'ffdhe3072', bits: 3072, nistApproved: true },
  258: { name: 'ffdhe4096', bits: 4096, nistApproved: true }
};
