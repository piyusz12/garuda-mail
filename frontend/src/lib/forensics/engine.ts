import 'reflect-metadata';
import type { CertNode, Ja4Fingerprint, PacketRecord, ThreatItem, TlsStepNode } from '@/lib/store/usePcapStore';
import { X509Certificate } from '@peculiar/x509';

export interface ForensicAnalysis {
  packets: PacketRecord[];
  tlsSteps: TlsStepNode[];
  certificates: CertNode[];
  ja4Fingerprints: Ja4Fingerprint[];
  threats: ThreatItem[];
  securityScore: number;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';
  starttls: { offered: boolean; requested: boolean; accepted: boolean; rejected: boolean };
  tls: { detected: boolean; version: string; cipher: string; keyExchange: string; forwardSecrecy: boolean };
  streams: Array<{ key: string; clientToServerBytes: number; serverToClientBytes: number; packetCount: number }>;
}

type Direction = 'client-to-server' | 'server-to-client';
type Segment = { timestamp: number; seq: number; src: string; dst: string; srcPort: number; dstPort: number; payload: Uint8Array };

const text = (bytes: Uint8Array) => new TextDecoder('latin1').decode(bytes);
const hex = (bytes: Uint8Array) => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join(' ');
const u16 = (bytes: Uint8Array, offset: number) => (bytes[offset] << 8) | bytes[offset + 1];
const u32 = (bytes: Uint8Array, offset: number) => (((bytes[offset] << 24) >>> 0) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

function concat(parts: Uint8Array[]) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function ipv4(bytes: Uint8Array, offset: number) { return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`; }

function parseClassicPcap(bytes: Uint8Array): Segment[] {
  if (bytes.length < 24) return [];
  const magic = u32(bytes, 0);
  const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const read32 = (offset: number) => little ? (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0 : u32(bytes, offset);
  const linkType = read32(20);
  const segments: Segment[] = [];
  let offset = 24;
  while (offset + 16 <= bytes.length) {
    const seconds = read32(offset);
    const micros = read32(offset + 4);
    const captured = read32(offset + 8);
    if (!captured || offset + 16 + captured > bytes.length) break;
    const frame = bytes.slice(offset + 16, offset + 16 + captured);
    let ipOffset = linkType === 1 ? 14 : linkType === 101 ? 0 : linkType === 113 ? 16 : -1;
    if (ipOffset < 0 || ipOffset + 20 > frame.length || (frame[ipOffset] >> 4) !== 4) { offset += 16 + captured; continue; }
    const ihl = (frame[ipOffset] & 15) * 4;
    if (frame[ipOffset + 9] !== 6 || ipOffset + ihl + 20 > frame.length) { offset += 16 + captured; continue; }
    const source = ipv4(frame, ipOffset + 12); const destination = ipv4(frame, ipOffset + 16);
    const tcp = ipOffset + ihl; const sourcePort = u16(frame, tcp); const destinationPort = u16(frame, tcp + 2);
    const dataOffset = (frame[tcp + 12] >> 4) * 4; const payloadStart = tcp + dataOffset;
    if (payloadStart < frame.length) segments.push({ timestamp: seconds * 1000 + micros / 1000, seq: u32(frame, tcp + 4), src: source, dst: destination, srcPort: sourcePort, dstPort: destinationPort, payload: frame.slice(payloadStart) });
    offset += 16 + captured;
  }
  return segments;
}

function parsePcapNg(bytes: Uint8Array): Segment[] {
  const segments: Segment[] = []; const interfaces: number[] = []; let little = true; let offset = 0;
  const read32 = (at: number) => little ? (bytes[at] | bytes[at + 1] << 8 | bytes[at + 2] << 16 | bytes[at + 3] << 24) >>> 0 : u32(bytes, at);
  while (offset + 12 <= bytes.length) {
    const blockType = read32(offset); const blockLength = read32(offset + 4); if (blockLength < 12 || offset + blockLength > bytes.length) break;
    if (blockType === 0x0a0d0d0a && offset + 12 <= bytes.length) { little = u32(bytes, offset + 8) === 0x1a2b3c4d; offset += blockLength; continue; }
    if (blockType === 1 && offset + 12 <= bytes.length) { interfaces.push(bytes[offset + 8] | bytes[offset + 9] << 8); offset += blockLength; continue; }
    if (blockType === 6 && offset + 32 <= bytes.length) {
      const interfaceId = read32(offset + 8); const timestamp = read32(offset + 12) * 4294967296 + read32(offset + 16); const captured = read32(offset + 20); const frame = bytes.slice(offset + 28, offset + 28 + captured); const linkType = interfaces[interfaceId] ?? 1;
      const synthetic = new Uint8Array(40 + frame.length); const view = new DataView(synthetic.buffer); view.setUint32(20, linkType, true); view.setUint32(24, Math.floor(timestamp / 1000000), true); view.setUint32(32, frame.length, true); view.setUint32(36, frame.length, true); synthetic.set(frame, 40);
      const parsed = parseClassicPcap(synthetic);
      for (const segment of parsed) segments.push({ ...segment, timestamp: timestamp / 1000 });
    }
    offset += blockLength;
  }
  return segments;
}

function parsePcap(bytes: Uint8Array) {
  // Classic PCAP is intentionally parsed without a dependency so captures remain air-gapped.
  return u32(bytes, 0) === 0x0a0d0d0a ? parsePcapNg(bytes) : parseClassicPcap(bytes);
}

function streamFor(segments: Segment[], client: Segment, direction: Direction) {
  const selected = segments.filter(segment => direction === 'client-to-server'
    ? segment.src === client.src && segment.srcPort === client.srcPort
    : segment.dst === client.src && segment.dstPort === client.srcPort)
    .sort((left, right) => left.seq - right.seq || left.timestamp - right.timestamp);
  return concat(selected.map(segment => segment.payload));
}

function tlsVersion(value: number) {
  return ({ 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2' } as Record<number, string>)[value] || (value === 0x0304 ? 'TLS 1.3' : `0x${value.toString(16)}`);
}

function parseTls(stream: Uint8Array, direction: Direction, baseTime: number): { steps: TlsStepNode[]; version: string; cipher: string; keyExchange: string; forwardSecrecy: boolean; certificates: CertNode[] } {
  const steps: TlsStepNode[] = []; const certificates: CertNode[] = []; let offset = 0; let version = 'Unknown'; let cipher = 'Unknown';
  let keyExchange = 'Unknown'; let forwardSecrecy = false;
  while (offset + 5 <= stream.length) {
    const recordType = stream[offset]; const recordVersion = u16(stream, offset + 1); const length = u16(stream, offset + 3);
    if (offset + 5 + length > stream.length || recordType < 20 || recordType > 24) break;
    const body = stream.slice(offset + 5, offset + 5 + length);
    if (recordType === 22 && body.length >= 4) {
      const handshake = body[0]; const messageLength = (body[1] << 16) | (body[2] << 8) | body[3]; const data = body.slice(4, 4 + messageLength);
      const name = handshake === 1 ? 'ClientHello' : handshake === 2 ? 'ServerHello' : handshake === 11 ? 'Certificate' : handshake === 12 ? 'ServerKeyExchange' : handshake === 20 ? 'Finished' : `Handshake ${handshake}`;
      if (handshake === 1 || handshake === 2) version = tlsVersion(u16(data, 0));
      if (handshake === 2 && data.length > 38) { const sessionLength = data[34]; const cipherOffset = 35 + sessionLength; if (cipherOffset + 2 <= data.length) cipher = `0x${u16(data, cipherOffset).toString(16).padStart(4, '0')}`; }
      if (handshake === 11 && data.length >= 3) {
        let certificateOffset = 3;
        const certificateListLength = (data[0] << 16) | (data[1] << 8) | data[2];
        const certificateEnd = Math.min(data.length, certificateOffset + certificateListLength);
        while (certificateOffset + 3 <= certificateEnd) {
          const certificateLength = (data[certificateOffset] << 16) | (data[certificateOffset + 1] << 8) | data[certificateOffset + 2]; certificateOffset += 3;
          if (certificateOffset + certificateLength > certificateEnd) break;
          try {
            const certificate = new X509Certificate(data.slice(certificateOffset, certificateOffset + certificateLength));
            const publicKey = certificate.publicKey.algorithm as Record<string, string | number>;
            const daysRemaining = Math.floor((certificate.notAfter.getTime() - Date.now()) / 86400000);
            const keySize = Number(publicKey.modulusLength || (publicKey.namedCurve === 'P-384' ? 384 : publicKey.namedCurve === 'P-256' ? 256 : 0));
            certificates.push({ id: `cert-${certificates.length}`, subject: certificate.subject, issuer: certificate.issuer, serialNumber: certificate.serialNumber, validFrom: certificate.notBefore.toISOString(), validTo: certificate.notAfter.toISOString(), daysRemaining, keyType: String(publicKey.name || 'Unknown'), keySize, signatureAlgorithm: String((certificate.signatureAlgorithm as { name?: string }).name || 'Unknown'), status: daysRemaining < 0 ? 'expired' : daysRemaining < 30 ? 'expiring' : 'trusted', sanList: [], fingerprintSha256: 'available in certificate evidence' });
          } catch { /* Ignore malformed certificates but preserve the handshake evidence. */ }
          certificateOffset += certificateLength;
        }
      }
      if (handshake === 12) { keyExchange = 'Ephemeral key exchange observed'; forwardSecrecy = true; }
      steps.push({ id: `tls-${steps.length}`, index: steps.length, name, direction, type: name === 'ClientHello' || name === 'ServerHello' || name === 'Certificate' || name === 'ServerKeyExchange' || name === 'Finished' ? name : 'EncryptedData', version, cipher, keyExchange, extensions: [], hexDump: hex(stream.slice(offset, Math.min(offset + 5 + length, offset + 80))), parsedSummary: { 'Record Type': recordType, 'Record Version': tlsVersion(recordVersion), 'Handshake Bytes': data.length }, timestampMs: baseTime + offset / 1000, status: version === 'TLS 1.0' || version === 'TLS 1.1' ? 'critical' : 'valid' });
      }
    offset += 5 + length;
  }
  return { steps, version, cipher, keyExchange, forwardSecrecy, certificates };
}

function finding(id: string, title: string, severity: ThreatItem['severity'], description: string, recommendation: string): ThreatItem {
  return { id, title, category: id.includes('TLS') ? 'PROTOCOL_DOWNGRADE' : id.includes('STARTTLS') ? 'PLAINTEXT_LEAK' : 'WEAK_CIPHER', severity, description, affectedSession: 'uploaded capture', recommendation };
}

export function analyzePcap(buffer: ArrayBuffer): ForensicAnalysis {
  const segments = parsePcap(new Uint8Array(buffer));
  const packets: PacketRecord[] = segments.map((segment, index) => ({ id: index, timestamp: segment.timestamp, timeOffsetMs: index ? segment.timestamp - segments[0].timestamp : 0, srcIp: segment.src, srcPort: segment.srcPort, dstIp: segment.dst, dstPort: segment.dstPort, protocol: 'TCP', length: segment.payload.length, info: `TCP payload ${segment.payload.length} bytes`, rawHex: hex(segment.payload.slice(0, 32)) }));
  if (!segments.length) return emptyAnalysis(packets);
  const first = segments[0]; const c2s = streamFor(segments, first, 'client-to-server'); const s2c = streamFor(segments, first, 'server-to-client'); const combined = `${text(c2s)}\n${text(s2c)}`.toUpperCase();
  const protocol: ForensicAnalysis['protocol'] = /(?:^|\n)220 .*ESMTP|EHLO|MAIL FROM/.test(combined) ? 'SMTP' : /IMAP4|\* OK|CAPABILITY/.test(combined) ? 'IMAP' : /POP3|\+OK|USER |PASS /.test(combined) ? 'POP3' : 'UNKNOWN';
  const offered = /STARTTLS|STLS/.test(combined); const requested = /(?:^|\n)(?:STARTTLS|STLS)(?:\r?\n|$)/.test(combined); const accepted = /220 .*READY TO START TLS|OK .*TLS|\+OK .*TLS/.test(combined); const rejected = /454|530|TLS NOT AVAILABLE|REJECT/.test(combined);
  const tlsOffset = c2s.findIndex((value, index) => value === 22 && c2s[index + 1] === 3); const tls = tlsOffset >= 0 ? parseTls(c2s.slice(tlsOffset), 'client-to-server', first.timestamp) : { steps: [], version: 'None', cipher: 'None', keyExchange: 'Unknown', forwardSecrecy: false, certificates: [] };
  const threats: ThreatItem[] = []; if (!tls.steps.length && (requested || protocol !== 'UNKNOWN')) threats.push(finding('STARTTLS-001', rejected ? 'STARTTLS negotiation rejected' : 'Email session is not encrypted', 'CRITICAL', 'The capture contains mail protocol traffic without a completed TLS handshake.', 'Require STARTTLS or implicit TLS before authentication and message transfer.')); if (tls.version === 'TLS 1.0' || tls.version === 'TLS 1.1' || tls.version === 'SSL 3.0') threats.push(finding('TLS-001', `Deprecated ${tls.version} negotiated`, 'CRITICAL', 'A deprecated TLS version was observed in the handshake.', 'Require TLS 1.2 or TLS 1.3.')); if (offered && !requested) threats.push(finding('STARTTLS-002', 'STARTTLS advertised but unused', 'HIGH', 'The server offered an encryption upgrade that the client did not use.', 'Enforce TLS before authentication and reject plaintext fallback.'));
  const securityScore = Math.max(0, 100 - threats.reduce((total, threat) => total + (threat.severity === 'CRITICAL' ? 35 : threat.severity === 'HIGH' ? 20 : 10), 0));
  return { packets, tlsSteps: tls.steps, certificates: tls.certificates, ja4Fingerprints: [], threats, securityScore, protocol, starttls: { offered, requested, accepted, rejected }, tls: { detected: tls.steps.length > 0, version: tls.version, cipher: tls.cipher, keyExchange: tls.keyExchange, forwardSecrecy: tls.forwardSecrecy }, streams: [{ key: `${first.src}:${first.srcPort}-${first.dst}:${first.dstPort}`, clientToServerBytes: c2s.length, serverToClientBytes: s2c.length, packetCount: segments.length }] };
}

function emptyAnalysis(packets: PacketRecord[]): ForensicAnalysis { return { packets, tlsSteps: [], certificates: [], ja4Fingerprints: [], threats: [finding('PCAP-001', 'No TCP payloads could be reconstructed', 'HIGH', 'The capture format or link type was not supported, or it contains no complete TCP payload.', 'Provide a classic PCAP with Ethernet, raw IP, or Linux SLL frames.')], securityScore: 0, protocol: 'UNKNOWN', starttls: { offered: false, requested: false, accepted: false, rejected: false }, tls: { detected: false, version: 'None', cipher: 'None', keyExchange: 'Unknown', forwardSecrecy: false }, streams: [] }; }