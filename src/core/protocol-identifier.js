/**
 * Protocol Identifier — DPI-based email protocol detection
 * Uses payload signatures rather than port numbers
 */

import { PROTOCOL, EMAIL_PORTS, IMPLICIT_TLS_PORTS } from '../utils/constants.js';

const SMTP_BANNER = /^220[ -]/;
const SMTP_EHLO = /^(EHLO|HELO)\s/i;
const IMAP_GREETING = /^\* OK/;
const POP3_GREETING = /^\+OK/;
const TLS_RECORD_HEADER = 0x16; // Handshake content type
const TLS_VERSION_BYTES = [0x03, 0x00, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x03, 0x04];

export class ProtocolIdentifier {
  /**
   * Identify the application-layer protocol from a reassembled flow
   */
  identify(flow) {
    const result = {
      protocol: PROTOCOL.UNKNOWN,
      confidence: 0,
      method: 'none',
      implicitTLS: false,
      banner: null,
    };

    // Check for implicit TLS first (starts with TLS ClientHello)
    if (this._startsWithTLS(flow.clientData) || this._startsWithTLS(flow.serverData)) {
      result.implicitTLS = true;
      result.confidence = 0.6;

      // Use port for implicit TLS identification
      if (IMPLICIT_TLS_PORTS.has(flow.serverPort)) {
        if (flow.serverPort === 465) { result.protocol = PROTOCOL.SMTP; result.confidence = 0.85; }
        else if (flow.serverPort === 993) { result.protocol = PROTOCOL.IMAP; result.confidence = 0.85; }
        else if (flow.serverPort === 995) { result.protocol = PROTOCOL.POP3; result.confidence = 0.85; }
        result.method = 'implicit_tls_port';
      }
      return result;
    }

    // DPI: Check server banner (plaintext)
    const serverStr = this._decodeInitial(flow.serverData, 512);
    const clientStr = this._decodeInitial(flow.clientData, 512);

    if (serverStr) {
      // SMTP detection
      if (SMTP_BANNER.test(serverStr)) {
        result.protocol = PROTOCOL.SMTP;
        result.confidence = 0.95;
        result.method = 'dpi_banner';
        result.banner = serverStr.split('\r\n')[0] || serverStr.split('\n')[0];
        return result;
      }

      // IMAP detection
      if (IMAP_GREETING.test(serverStr)) {
        result.protocol = PROTOCOL.IMAP;
        result.confidence = 0.95;
        result.method = 'dpi_banner';
        result.banner = serverStr.split('\r\n')[0] || serverStr.split('\n')[0];
        return result;
      }

      // POP3 detection
      if (POP3_GREETING.test(serverStr)) {
        result.protocol = PROTOCOL.POP3;
        result.confidence = 0.95;
        result.method = 'dpi_banner';
        result.banner = serverStr.split('\r\n')[0] || serverStr.split('\n')[0];
        return result;
      }
    }

    // Check client-side commands
    if (clientStr) {
      if (SMTP_EHLO.test(clientStr)) {
        result.protocol = PROTOCOL.SMTP;
        result.confidence = 0.85;
        result.method = 'dpi_command';
        return result;
      }
    }

    // Fallback: port-based heuristic
    if (EMAIL_PORTS.has(flow.serverPort)) {
      if (flow.serverPort === 25 || flow.serverPort === 587) result.protocol = PROTOCOL.SMTP;
      else if (flow.serverPort === 143) result.protocol = PROTOCOL.IMAP;
      else if (flow.serverPort === 110) result.protocol = PROTOCOL.POP3;
      result.confidence = 0.5;
      result.method = 'port_heuristic';
    }

    return result;
  }

  /**
   * Detect STARTTLS/STLS commands in plaintext data
   */
  detectSTARTTLS(flow, protocol) {
    const clientStr = this._decodeInitial(flow.clientData, 4096);
    const serverStr = this._decodeInitial(flow.serverData, 4096);

    if (!clientStr || !serverStr) return null;

    const result = {
      attempted: false,
      success: false,
      command: null,
      response: null,
      byteOffset: -1,
    };

    if (protocol === PROTOCOL.SMTP || protocol === PROTOCOL.IMAP) {
      const starttlsMatch = clientStr.match(/STARTTLS/i);
      if (starttlsMatch) {
        result.attempted = true;
        result.command = 'STARTTLS';
        result.byteOffset = starttlsMatch.index;

        // Check for successful response
        if (protocol === PROTOCOL.SMTP && /220[\s-].*(?:TLS|ready)/i.test(serverStr)) {
          result.success = true;
          result.response = '220 Ready to start TLS';
        } else if (protocol === PROTOCOL.IMAP && /OK.*STARTTLS/i.test(serverStr)) {
          result.success = true;
          result.response = 'OK STARTTLS completed';
        }
      }
    } else if (protocol === PROTOCOL.POP3) {
      const stlsMatch = clientStr.match(/STLS/i);
      if (stlsMatch) {
        result.attempted = true;
        result.command = 'STLS';
        result.byteOffset = stlsMatch.index;

        if (/\+OK.*(?:TLS|Begin)/i.test(serverStr)) {
          result.success = true;
          result.response = '+OK Begin TLS negotiation';
        }
      }
    }

    return result;
  }

  _startsWithTLS(data) {
    if (!data || data.length < 5) return false;
    return data[0] === TLS_RECORD_HEADER && data[1] === 0x03 &&
           (data[2] >= 0x00 && data[2] <= 0x04);
  }

  _decodeInitial(data, maxLen) {
    if (!data || data.length === 0) return null;
    try {
      const slice = data.slice(0, Math.min(data.length, maxLen));
      return new TextDecoder('ascii', { fatal: false }).decode(slice);
    } catch {
      return null;
    }
  }
}
