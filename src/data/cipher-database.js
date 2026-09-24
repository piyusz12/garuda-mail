/**
 * Cipher Suite Database — Comprehensive security ratings for TLS cipher suites
 * Covers IANA-registered suites with NIST SP 800-52 Rev 2 and RFC 9325 compliance
 */

const S = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

// Format: [hexCode]: { name, kx, auth, enc, mac, bits, fs, aead, risk, compliant, deprecated, notes }
export const CIPHER_SUITES = {
  // ═══ TLS 1.3 Suites (All enforce forward secrecy) ═══
  0x1301: { name: 'TLS_AES_128_GCM_SHA256', kx: 'Any', auth: 'Any', enc: 'AES-128-GCM', mac: 'SHA-256', bits: 128, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0x1302: { name: 'TLS_AES_256_GCM_SHA384', kx: 'Any', auth: 'Any', enc: 'AES-256-GCM', mac: 'SHA-384', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0x1303: { name: 'TLS_CHACHA20_POLY1305_SHA256', kx: 'Any', auth: 'Any', enc: 'ChaCha20-Poly1305', mac: 'SHA-256', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },

  // ═══ TLS 1.2 ECDHE + AEAD (Best Practice) ═══
  0xc02b: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', kx: 'ECDHE', auth: 'ECDSA', enc: 'AES-128-GCM', mac: 'SHA-256', bits: 128, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0xc02c: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', kx: 'ECDHE', auth: 'ECDSA', enc: 'AES-256-GCM', mac: 'SHA-384', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0xc02f: { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', kx: 'ECDHE', auth: 'RSA', enc: 'AES-128-GCM', mac: 'SHA-256', bits: 128, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0xc030: { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', kx: 'ECDHE', auth: 'RSA', enc: 'AES-256-GCM', mac: 'SHA-384', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0xcca8: { name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', kx: 'ECDHE', auth: 'RSA', enc: 'ChaCha20-Poly1305', mac: 'SHA-256', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0xcca9: { name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', kx: 'ECDHE', auth: 'ECDSA', enc: 'ChaCha20-Poly1305', mac: 'SHA-256', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },

  // ═══ TLS 1.2 DHE + AEAD ═══
  0x009e: { name: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', kx: 'DHE', auth: 'RSA', enc: 'AES-128-GCM', mac: 'SHA-256', bits: 128, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0x009f: { name: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', kx: 'DHE', auth: 'RSA', enc: 'AES-256-GCM', mac: 'SHA-384', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },
  0xccaa: { name: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', kx: 'DHE', auth: 'RSA', enc: 'ChaCha20-Poly1305', mac: 'SHA-256', bits: 256, fs: true, aead: true, risk: S.LOW, compliant: true, deprecated: false },

  // ═══ TLS 1.2 ECDHE + CBC (Medium risk — padding oracle) ═══
  0xc023: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', kx: 'ECDHE', auth: 'ECDSA', enc: 'AES-128-CBC', mac: 'SHA-256', bits: 128, fs: true, aead: false, risk: S.MEDIUM, compliant: true, deprecated: false, notes: 'CBC mode vulnerable to padding oracle attacks. Migrate to GCM.' },
  0xc024: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', kx: 'ECDHE', auth: 'ECDSA', enc: 'AES-256-CBC', mac: 'SHA-384', bits: 256, fs: true, aead: false, risk: S.MEDIUM, compliant: true, deprecated: false, notes: 'CBC mode vulnerable to padding oracle attacks.' },
  0xc027: { name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', kx: 'ECDHE', auth: 'RSA', enc: 'AES-128-CBC', mac: 'SHA-256', bits: 128, fs: true, aead: false, risk: S.MEDIUM, compliant: true, deprecated: false, notes: 'CBC mode — Lucky Thirteen susceptible.' },
  0xc028: { name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', kx: 'ECDHE', auth: 'RSA', enc: 'AES-256-CBC', mac: 'SHA-384', bits: 256, fs: true, aead: false, risk: S.MEDIUM, compliant: true, deprecated: false, notes: 'CBC mode — Lucky Thirteen susceptible.' },
  0xc013: { name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', kx: 'ECDHE', auth: 'RSA', enc: 'AES-128-CBC', mac: 'SHA-1', bits: 128, fs: true, aead: false, risk: S.MEDIUM, compliant: false, deprecated: false, notes: 'SHA-1 MAC + CBC mode.' },
  0xc014: { name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', kx: 'ECDHE', auth: 'RSA', enc: 'AES-256-CBC', mac: 'SHA-1', bits: 256, fs: true, aead: false, risk: S.MEDIUM, compliant: false, deprecated: false, notes: 'SHA-1 MAC + CBC mode.' },

  // ═══ TLS 1.2 Static RSA (No forward secrecy — HIGH risk) ═══
  0x009c: { name: 'TLS_RSA_WITH_AES_128_GCM_SHA256', kx: 'RSA', auth: 'RSA', enc: 'AES-128-GCM', mac: 'SHA-256', bits: 128, fs: false, aead: true, risk: S.HIGH, compliant: false, deprecated: false, notes: 'Static RSA key exchange — no forward secrecy.' },
  0x009d: { name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', kx: 'RSA', auth: 'RSA', enc: 'AES-256-GCM', mac: 'SHA-384', bits: 256, fs: false, aead: true, risk: S.HIGH, compliant: false, deprecated: false, notes: 'Static RSA — retroactive decryption possible.' },
  0x002f: { name: 'TLS_RSA_WITH_AES_128_CBC_SHA', kx: 'RSA', auth: 'RSA', enc: 'AES-128-CBC', mac: 'SHA-1', bits: 128, fs: false, aead: false, risk: S.HIGH, compliant: false, deprecated: false, notes: 'Static RSA + CBC + SHA-1.' },
  0x0035: { name: 'TLS_RSA_WITH_AES_256_CBC_SHA', kx: 'RSA', auth: 'RSA', enc: 'AES-256-CBC', mac: 'SHA-1', bits: 256, fs: false, aead: false, risk: S.HIGH, compliant: false, deprecated: false, notes: 'Static RSA + CBC + SHA-1.' },
  0x003c: { name: 'TLS_RSA_WITH_AES_128_CBC_SHA256', kx: 'RSA', auth: 'RSA', enc: 'AES-128-CBC', mac: 'SHA-256', bits: 128, fs: false, aead: false, risk: S.HIGH, compliant: false, deprecated: false, notes: 'Static RSA + CBC — no forward secrecy.' },
  0x003d: { name: 'TLS_RSA_WITH_AES_256_CBC_SHA256', kx: 'RSA', auth: 'RSA', enc: 'AES-256-CBC', mac: 'SHA-256', bits: 256, fs: false, aead: false, risk: S.HIGH, compliant: false, deprecated: false, notes: 'Static RSA + CBC — no forward secrecy.' },

  // ═══ 3DES (CRITICAL — SWEET32 vulnerable) ═══
  0xc012: { name: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', kx: 'ECDHE', auth: 'RSA', enc: '3DES-EDE-CBC', mac: 'SHA-1', bits: 112, fs: true, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'SWEET32 collision attack; 64-bit block cipher.' },
  0x000a: { name: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', kx: 'RSA', auth: 'RSA', enc: '3DES-EDE-CBC', mac: 'SHA-1', bits: 112, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'SWEET32 + static RSA — must disable.' },

  // ═══ RC4 (CRITICAL — bias attacks) ═══
  0xc011: { name: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', kx: 'ECDHE', auth: 'RSA', enc: 'RC4-128', mac: 'SHA-1', bits: 128, fs: true, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'RC4 bias attacks allow plaintext recovery.' },
  0x0005: { name: 'TLS_RSA_WITH_RC4_128_SHA', kx: 'RSA', auth: 'RSA', enc: 'RC4-128', mac: 'SHA-1', bits: 128, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'RC4 + static RSA — completely broken.' },
  0x0004: { name: 'TLS_RSA_WITH_RC4_128_MD5', kx: 'RSA', auth: 'RSA', enc: 'RC4-128', mac: 'MD5', bits: 128, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'RC4 + MD5 — catastrophically insecure.' },

  // ═══ NULL / EXPORT Ciphers (CRITICAL) ═══
  0x0000: { name: 'TLS_NULL_WITH_NULL_NULL', kx: 'NULL', auth: 'NULL', enc: 'NULL', mac: 'NULL', bits: 0, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'No encryption whatsoever.' },
  0x0001: { name: 'TLS_RSA_WITH_NULL_MD5', kx: 'RSA', auth: 'RSA', enc: 'NULL', mac: 'MD5', bits: 0, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'NULL encryption — plaintext.' },
  0x0002: { name: 'TLS_RSA_WITH_NULL_SHA', kx: 'RSA', auth: 'RSA', enc: 'NULL', mac: 'SHA-1', bits: 0, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'NULL encryption — plaintext.' },
  0x003b: { name: 'TLS_RSA_WITH_NULL_SHA256', kx: 'RSA', auth: 'RSA', enc: 'NULL', mac: 'SHA-256', bits: 0, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'NULL encryption — plaintext.' },
  0x0003: { name: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', kx: 'RSA_EXPORT', auth: 'RSA', enc: 'RC4-40', mac: 'MD5', bits: 40, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'EXPORT 40-bit — trivially breakable.' },
  0x0006: { name: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', kx: 'RSA_EXPORT', auth: 'RSA', enc: 'RC2-40', mac: 'MD5', bits: 40, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'EXPORT cipher — FREAK/Logjam.' },
  0x0008: { name: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', kx: 'RSA_EXPORT', auth: 'RSA', enc: 'DES-40', mac: 'SHA-1', bits: 40, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'EXPORT DES — 40-bit trivially breakable.' },
  0x0009: { name: 'TLS_RSA_WITH_DES_CBC_SHA', kx: 'RSA', auth: 'RSA', enc: 'DES-CBC', mac: 'SHA-1', bits: 56, fs: false, aead: false, risk: S.CRITICAL, compliant: false, deprecated: true, notes: 'Single DES — 56-bit, effectively broken.' },
};

/**
 * Look up a cipher suite by its hex code
 */
export function lookupCipherSuite(code) {
  return CIPHER_SUITES[code] || {
    name: `Unknown (0x${code.toString(16).padStart(4, '0')})`,
    kx: 'Unknown', auth: 'Unknown', enc: 'Unknown', mac: 'Unknown',
    bits: 0, fs: false, aead: false, risk: S.MEDIUM, compliant: false, deprecated: false,
    notes: 'Unknown cipher suite — not in database.'
  };
}

/**
 * Get security assessment for a cipher suite code
 */
export function assessCipherSuite(code) {
  const suite = lookupCipherSuite(code);
  const issues = [];

  if (suite.enc === 'NULL' || suite.enc.includes('EXPORT')) issues.push('NULL/EXPORT encryption provides zero security.');
  if (suite.enc.includes('RC4')) issues.push('RC4 has severe cryptographic biases allowing plaintext recovery.');
  if (suite.enc.includes('3DES')) issues.push('3DES vulnerable to SWEET32 birthday collision attack.');
  if (suite.enc.includes('DES') && !suite.enc.includes('3DES')) issues.push('Single DES (56-bit) is trivially breakable.');
  if (suite.enc.includes('CBC')) issues.push('CBC mode susceptible to padding oracle attacks (Lucky Thirteen, POODLE).');
  if (!suite.fs) issues.push('No forward secrecy — compromised private key enables retroactive decryption.');
  if (suite.mac === 'MD5') issues.push('MD5 is cryptographically broken for authentication.');
  if (suite.mac === 'SHA-1') issues.push('SHA-1 is deprecated; collision attacks are practical.');
  if (suite.bits > 0 && suite.bits < 128) issues.push(`Encryption key length (${suite.bits}-bit) is below minimum 128-bit threshold.`);

  return { ...suite, issues };
}
