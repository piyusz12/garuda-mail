/**
 * Demo Data Generator
 * Creates realistic synthetic email sessions with a mix of security postures
 */

import { PROTOCOL } from '../utils/constants.js';

const rand = (min, max) => Math.random() * (max - min) + min;
const randInt = (min, max) => Math.floor(rand(min, max));
const pick = (arr) => arr[randInt(0, arr.length)];
const uuid = () => crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${randInt(1000,9999)}`;

const INTERNAL_IPS = ['10.0.1.50', '10.0.1.51', '10.0.2.10', '10.0.2.11', '192.168.1.100', '192.168.1.101'];
const EXTERNAL_IPS = ['203.0.113.25', '198.51.100.42', '93.184.216.34', '104.18.32.7', '172.217.14.99', '151.101.1.67', '185.199.108.153'];
const MTA_DOMAINS = ['mail.enterprise.com', 'smtp.internal.corp', 'mx1.partner.org', 'relay.vendor.net', 'mail.customer.io', 'smtp.legacy.local'];
const SANS = ['mail.enterprise.com', '*.enterprise.com', 'smtp.enterprise.com', 'imap.enterprise.com', 'pop.enterprise.com'];

const GOOD_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9];
const MEDIUM_CIPHERS = [0xc023, 0xc027, 0xc028, 0x009c, 0x009d, 0x003c, 0x003d];
const BAD_CIPHERS = [0xc012, 0x000a, 0xc011, 0x0005, 0x0004, 0x002f, 0x0035];

const GOOD_JA4 = ['t13d1516h2', 't13d0810h1', 't13d0308h0', 't13d0410h0', 't12d0608h1'];
const SUSPICIOUS_JA4 = ['t12d0203h0', 't12d0102h0', 't10d0103h0', 't12d0305h0_msf', 't12d0204h0_hyd', 't12d0102h0_c2'];

const SIG_ALGOS = ['sha256WithRSAEncryption', 'sha384WithRSAEncryption', 'ecdsa-with-SHA256', 'sha1WithRSAEncryption', 'md5WithRSAEncryption'];

function generateCertificate(type = 'valid') {
  const now = Date.now();
  const day = 86400000;

  const templates = {
    valid: {
      subject: 'CN=mail.enterprise.com, O=Enterprise Corp, C=US',
      issuer: 'CN=DigiCert SHA2 Extended Validation Server CA, O=DigiCert Inc, C=US',
      san: ['mail.enterprise.com', '*.enterprise.com', 'smtp.enterprise.com'],
      notBefore: new Date(now - 180 * day),
      notAfter: new Date(now + 185 * day),
      serialNumber: 'A1:B2:C3:D4:E5:F6:07:08',
      keyAlgo: 'RSA',
      keySize: 2048,
      sigAlgo: 'sha256WithRSAEncryption',
      selfSigned: false,
      chain: [
        { cn: 'DigiCert SHA2 Extended Validation Server CA', issuer: 'DigiCert Global Root CA', keySize: 2048, sigAlgo: 'sha256WithRSAEncryption' },
        { cn: 'DigiCert Global Root CA', issuer: 'DigiCert Global Root CA', keySize: 4096, sigAlgo: 'sha256WithRSAEncryption' }
      ]
    },
    expired: {
      subject: 'CN=smtp.legacy.local, O=Legacy Systems, C=US',
      issuer: 'CN=Internal CA, O=Enterprise Corp, C=US',
      san: ['smtp.legacy.local'],
      notBefore: new Date(now - 400 * day),
      notAfter: new Date(now - 35 * day),
      serialNumber: 'FF:EE:DD:CC:BB:AA:99:88',
      keyAlgo: 'RSA',
      keySize: 1024,
      sigAlgo: 'sha1WithRSAEncryption',
      selfSigned: false,
      chain: [
        { cn: 'Internal CA', issuer: 'Internal CA', keySize: 2048, sigAlgo: 'sha1WithRSAEncryption' }
      ]
    },
    selfSigned: {
      subject: 'CN=relay.vendor.net, O=Vendor LLC, C=DE',
      issuer: 'CN=relay.vendor.net, O=Vendor LLC, C=DE',
      san: ['relay.vendor.net'],
      notBefore: new Date(now - 90 * day),
      notAfter: new Date(now + 275 * day),
      serialNumber: '11:22:33:44:55:66:77:88',
      keyAlgo: 'RSA',
      keySize: 2048,
      sigAlgo: 'sha256WithRSAEncryption',
      selfSigned: true,
      chain: []
    },
    ecdsa: {
      subject: 'CN=mx1.partner.org, O=Partner Organization, C=UK',
      issuer: "CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US",
      san: ['mx1.partner.org', '*.partner.org'],
      notBefore: new Date(now - 45 * day),
      notAfter: new Date(now + 45 * day),
      serialNumber: 'AA:BB:CC:DD:EE:FF:00:11',
      keyAlgo: 'ECDSA',
      keySize: 256,
      sigAlgo: 'ecdsa-with-SHA256',
      selfSigned: false,
      chain: [
        { cn: "Let's Encrypt Authority X3", issuer: 'DST Root CA X3', keySize: 2048, sigAlgo: 'sha256WithRSAEncryption' },
        { cn: 'DST Root CA X3', issuer: 'DST Root CA X3', keySize: 4096, sigAlgo: 'sha256WithRSAEncryption' }
      ]
    },
    weakKey: {
      subject: 'CN=mail.customer.io, O=Customer Inc, C=IN',
      issuer: 'CN=GeoTrust RSA CA 2018, O=DigiCert Inc, C=US',
      san: ['mail.customer.io'],
      notBefore: new Date(now - 200 * day),
      notAfter: new Date(now + 165 * day),
      serialNumber: 'CC:DD:EE:FF:00:11:22:33',
      keyAlgo: 'RSA',
      keySize: 1024,
      sigAlgo: 'sha256WithRSAEncryption',
      selfSigned: false,
      chain: [
        { cn: 'GeoTrust RSA CA 2018', issuer: 'DigiCert Global Root CA', keySize: 2048, sigAlgo: 'sha256WithRSAEncryption' }
      ]
    }
  };

  return templates[type] || templates.valid;
}

function generateSession(index, baseTime) {
  const profiles = [
    // 40% — Modern, compliant sessions
    () => {
      const proto = pick([PROTOCOL.SMTP, PROTOCOL.IMAP, PROTOCOL.POP3]);
      const isImplicit = Math.random() > 0.4;
      const port = proto === PROTOCOL.SMTP ? (isImplicit ? 465 : 587) : proto === PROTOCOL.IMAP ? (isImplicit ? 993 : 143) : (isImplicit ? 995 : 110);
      return {
        protocol: proto,
        srcIP: pick(INTERNAL_IPS),
        dstIP: pick(EXTERNAL_IPS),
        srcPort: randInt(49152, 65535),
        dstPort: port,
        tlsVersion: 0x0304,
        cipherSuite: pick(GOOD_CIPHERS.slice(0, 3)),
        ja4: pick(GOOD_JA4),
        certificate: generateCertificate('valid'),
        starttls: !isImplicit ? { attempted: true, success: true } : null,
        implicitTLS: isImplicit,
        plaintextAuth: false,
        anomalyScore: rand(0.05, 0.25),
        duration: rand(500, 5000),
        packets: randInt(10, 60),
        bytesTransferred: randInt(1024, 102400),
        sni: pick(MTA_DOMAINS),
      };
    },

    // 20% — TLS 1.2 with decent config
    () => {
      const proto = pick([PROTOCOL.SMTP, PROTOCOL.IMAP]);
      return {
        protocol: proto,
        srcIP: pick(INTERNAL_IPS),
        dstIP: pick(EXTERNAL_IPS),
        srcPort: randInt(49152, 65535),
        dstPort: proto === PROTOCOL.SMTP ? 587 : 143,
        tlsVersion: 0x0303,
        cipherSuite: pick(GOOD_CIPHERS.slice(3)),
        ja4: pick(GOOD_JA4),
        certificate: generateCertificate(Math.random() > 0.7 ? 'ecdsa' : 'valid'),
        starttls: { attempted: true, success: true },
        implicitTLS: false,
        plaintextAuth: false,
        anomalyScore: rand(0.1, 0.35),
        duration: rand(800, 8000),
        packets: randInt(15, 80),
        bytesTransferred: randInt(2048, 204800),
        sni: pick(MTA_DOMAINS),
      };
    },

    // 15% — TLS 1.2 with CBC or static RSA (medium risk)
    () => {
      const proto = pick([PROTOCOL.SMTP, PROTOCOL.IMAP, PROTOCOL.POP3]);
      return {
        protocol: proto,
        srcIP: pick(INTERNAL_IPS),
        dstIP: pick(EXTERNAL_IPS),
        srcPort: randInt(49152, 65535),
        dstPort: proto === PROTOCOL.SMTP ? 25 : proto === PROTOCOL.IMAP ? 143 : 110,
        tlsVersion: 0x0303,
        cipherSuite: pick(MEDIUM_CIPHERS),
        ja4: pick(GOOD_JA4),
        certificate: generateCertificate(Math.random() > 0.5 ? 'weakKey' : 'selfSigned'),
        starttls: { attempted: true, success: true },
        implicitTLS: false,
        plaintextAuth: false,
        anomalyScore: rand(0.25, 0.55),
        duration: rand(1000, 12000),
        packets: randInt(20, 100),
        bytesTransferred: randInt(4096, 512000),
        sni: pick(MTA_DOMAINS),
      };
    },

    // 10% — Deprecated TLS 1.0/1.1 (high risk)
    () => {
      const proto = pick([PROTOCOL.SMTP, PROTOCOL.IMAP]);
      return {
        protocol: proto,
        srcIP: pick(INTERNAL_IPS),
        dstIP: pick(EXTERNAL_IPS.concat(['10.0.3.200', '10.0.3.201'])),
        srcPort: randInt(49152, 65535),
        dstPort: proto === PROTOCOL.SMTP ? 25 : 143,
        tlsVersion: pick([0x0301, 0x0302]),
        cipherSuite: pick(MEDIUM_CIPHERS.concat(BAD_CIPHERS.slice(0, 2))),
        ja4: pick(GOOD_JA4.concat(SUSPICIOUS_JA4.slice(0, 2))),
        certificate: generateCertificate('expired'),
        starttls: { attempted: true, success: true },
        implicitTLS: false,
        plaintextAuth: false,
        anomalyScore: rand(0.5, 0.78),
        duration: rand(2000, 15000),
        packets: randInt(30, 120),
        bytesTransferred: randInt(8192, 1048576),
        sni: pick(['smtp.legacy.local', 'mail.old-system.internal']),
      };
    },

    // 8% — Failed STARTTLS / plaintext fallback (critical)
    () => {
      const proto = pick([PROTOCOL.SMTP, PROTOCOL.POP3]);
      return {
        protocol: proto,
        srcIP: pick(INTERNAL_IPS),
        dstIP: pick(EXTERNAL_IPS),
        srcPort: randInt(49152, 65535),
        dstPort: proto === PROTOCOL.SMTP ? 587 : 110,
        tlsVersion: null,
        cipherSuite: null,
        ja4: null,
        certificate: null,
        starttls: { attempted: true, success: false, error: 'Server rejected STARTTLS — possible MITM stripping' },
        implicitTLS: false,
        plaintextAuth: true,
        anomalyScore: rand(0.8, 0.98),
        duration: rand(300, 2000),
        packets: randInt(8, 30),
        bytesTransferred: randInt(512, 8192),
        sni: null,
      };
    },

    // 5% — Suspicious JA4 / possible exfiltration (critical)
    () => {
      const proto = pick([PROTOCOL.SMTP, PROTOCOL.IMAP]);
      return {
        protocol: proto,
        srcIP: pick(['10.0.5.99', '192.168.100.42']),
        dstIP: pick(['185.100.87.174', '91.219.237.229']),
        srcPort: randInt(49152, 65535),
        dstPort: proto === PROTOCOL.SMTP ? 465 : 993,
        tlsVersion: pick([0x0301, 0x0303]),
        cipherSuite: pick(BAD_CIPHERS.concat([0x002f, 0x0035])),
        ja4: pick(SUSPICIOUS_JA4),
        certificate: generateCertificate('selfSigned'),
        starttls: null,
        implicitTLS: true,
        plaintextAuth: false,
        anomalyScore: rand(0.85, 0.99),
        duration: rand(30000, 180000),
        packets: randInt(200, 2000),
        bytesTransferred: randInt(1048576, 52428800),
        sni: pick(['update-service.xyz', 'cdn-static.cc', 'api.analytics-hub.io']),
      };
    },

    // 2% — Beaconing pattern
    () => ({
      protocol: PROTOCOL.SMTP,
      srcIP: '10.0.2.11',
      dstIP: '45.33.32.156',
      srcPort: randInt(49152, 65535),
      dstPort: 465,
      tlsVersion: 0x0303,
      cipherSuite: 0x002f,
      ja4: 't12d0102h0_c2',
      certificate: generateCertificate('selfSigned'),
      starttls: null,
      implicitTLS: true,
      plaintextAuth: false,
      anomalyScore: rand(0.92, 0.99),
      duration: rand(100, 300),
      packets: randInt(4, 8),
      bytesTransferred: randInt(64, 512),
      sni: 'mail-relay.cloud-services.cc',
      isBeaconing: true,
    }),
  ];

  // Weighted selection
  const weights = [40, 20, 15, 10, 8, 5, 2];
  const totalWeight = weights.reduce((a, b) => a + b, 0);
  let r = Math.random() * totalWeight;
  let profileIndex = 0;
  for (let i = 0; i < weights.length; i++) {
    r -= weights[i];
    if (r <= 0) { profileIndex = i; break; }
  }

  const session = profiles[profileIndex]();
  const timestamp = baseTime + index * randInt(500, 30000);

  // Generate inter-packet timing
  const interPacketTimes = [];
  for (let i = 0; i < (session.packets || 10) - 1; i++) {
    if (session.isBeaconing) {
      interPacketTimes.push(rand(28, 32)); // Very uniform timing
    } else {
      interPacketTimes.push(rand(1, session.duration / (session.packets || 10) * 3));
    }
  }

  const mean = interPacketTimes.reduce((a, b) => a + b, 0) / interPacketTimes.length;
  const variance = interPacketTimes.reduce((a, b) => a + (b - mean) ** 2, 0) / interPacketTimes.length;

  return {
    id: uuid(),
    index,
    timestamp: new Date(timestamp),
    ...session,
    interPacketTiming: {
      mean: mean,
      stdDev: Math.sqrt(variance),
      variance: variance,
      min: Math.min(...interPacketTimes),
      max: Math.max(...interPacketTimes),
    },
    entropy: session.tlsVersion ? rand(7.2, 7.99) : rand(3.5, 6.2),
    handshakeLatency: session.tlsVersion ? rand(5, 150) : 0,
  };
}

/**
 * Generate a full demo dataset
 */
export function generateDemoData(sessionCount = 75) {
  const baseTime = Date.now() - 3600000; // 1 hour ago
  const sessions = [];

  for (let i = 0; i < sessionCount; i++) {
    sessions.push(generateSession(i, baseTime));
  }

  // Sort by timestamp
  sessions.sort((a, b) => a.timestamp - b.timestamp);

  return {
    metadata: {
      source: 'Demo Data Generator',
      generatedAt: new Date(),
      sessionCount: sessions.length,
      timeRange: {
        start: sessions[0].timestamp,
        end: sessions[sessions.length - 1].timestamp,
      },
    },
    sessions,
  };
}
