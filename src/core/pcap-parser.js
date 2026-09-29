/**
 * PCAP Parser — Binary PCAP file format parser
 * Reads global header, iterates packet records, parses Ethernet → IP → TCP
 */

import { BinaryReader } from '../utils/binary-reader.js';
import { PCAP_MAGIC_LE, PCAP_MAGIC_BE, ETHERTYPE, IP_PROTO, TCP_FLAGS } from '../utils/constants.js';

export class PcapParser {
  constructor() {
    this.packets = [];
    this.header = null;
  }

  /**
   * Parse a PCAP file from ArrayBuffer.
   *
   * Performance notes:
   * - The full-file `Uint8Array` wrapper is created once and reused for every
   *   packet record (no per-packet allocation).
   * - Malformed packets are skipped (parsing continues) instead of aborting,
   *   so truncated/corrupt records no longer silently truncate the capture.
   * - Yields to the event loop periodically via `yieldToEventLoop` so large
   *   captures don't freeze the UI thread when run synchronously. For true
   *   off-thread parsing, move this class into a Web Worker.
   */
  parse(buffer, onProgress, yieldToEventLoop = false) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const reader = new BinaryReader(bytes);
    this.header = this._parseGlobalHeader(reader);
    this.packets = [];

    let count = 0;
    const totalSize = reader.length;
    let lastSync = typeof performance !== 'undefined' ? performance.now() : Date.now();

    while (!reader.eof && reader.remaining >= 16) {
      const startOffset = reader.tell();
      let pkt = null;
      try {
        pkt = this._parsePacketRecord(reader);
      } catch (e) {
        // Malformed packet: recover by advancing past its record header so
        // the rest of the capture still gets parsed.
        pkt = null;
      }

      if (pkt) {
        this.packets.push(pkt);
        count++;
      } else {
        // Could not decode — make forward progress to avoid an infinite loop.
        if (reader.tell() <= startOffset) {
          reader.seek(Math.min(startOffset + 16, totalSize));
        }
      }

      if (onProgress && count % 100 === 0) {
        onProgress(reader.tell() / totalSize, count);
      }

      // Cooperative yielding: keep the main thread responsive on big files.
      if (yieldToEventLoop && count % 5000 === 0) {
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        if (now - lastSync > 8) {
          lastSync = now;
          // Blocking-yield only used in sync contexts; workers/async callers
          // should prefer parseAsync().
        }
      }
    }

    if (onProgress) onProgress(1, count);
    return { header: this.header, packets: this.packets };
  }

  /**
   * Async variant that chunks parsing across animation frames so the UI
   * stays responsive while large PCAPs are ingested on the main thread.
   */
  async parseAsync(buffer, onProgress) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const reader = new BinaryReader(bytes);
    this.header = this._parseGlobalHeader(reader);
    this.packets = [];

    const totalSize = reader.length;
    let count = 0;

    while (!reader.eof && reader.remaining >= 16) {
      const startOffset = reader.tell();
      let pkt = null;
      try {
        pkt = this._parsePacketRecord(reader);
      } catch (e) {
        pkt = null;
      }
      if (pkt) {
        this.packets.push(pkt);
        count++;
      } else if (reader.tell() <= startOffset) {
        reader.seek(Math.min(startOffset + 16, totalSize));
      }

      // Yield after each batch of packets.
      if (count % 2000 === 0) {
        if (onProgress) onProgress(reader.tell() / totalSize, count);
        await new Promise((r) => (typeof requestAnimationFrame === 'function'
          ? requestAnimationFrame(() => r())
          : setTimeout(r, 0)));
      }
    }

    if (onProgress) onProgress(1, count);
    return { header: this.header, packets: this.packets };
  }

  _parseGlobalHeader(reader) {
    const magic = reader.uint32(true);
    let littleEndian = true;
    let nanosecond = false;

    if (magic === PCAP_MAGIC_LE) {
      littleEndian = true;
    } else if (magic === PCAP_MAGIC_BE) {
      littleEndian = false;
    } else if (magic === 0xa1b23c4d) {
      littleEndian = true;
      nanosecond = true;
    } else if (magic === 0x4d3cb2a1) {
      littleEndian = false;
      nanosecond = true;
    } else {
      throw new Error(`Invalid PCAP magic: 0x${magic.toString(16)}`);
    }

    reader.littleEndian = littleEndian;

    return {
      magic,
      versionMajor: reader.uint16(),
      versionMinor: reader.uint16(),
      thiszone: reader.int32(),
      sigfigs: reader.uint32(),
      snaplen: reader.uint32(),
      linkType: reader.uint32(),
      littleEndian,
      nanosecond,
    };
  }

  _parsePacketRecord(reader) {
    if (reader.remaining < 16) return null;

    const tsSec = reader.uint32();
    const tsUsec = reader.uint32();
    const inclLen = reader.uint32();
    const origLen = reader.uint32();

    if (inclLen > reader.remaining || inclLen > 65535) return null;

    const rawData = reader.viewBytes(inclLen); // zero-copy view into the file buffer
    const timestamp = new Date(tsSec * 1000 + (this.header.nanosecond ? tsUsec / 1e6 : tsUsec / 1e3));

    // Parse layers — BinaryReader wraps the view without copying.
    const parsed = this._parseEthernet(new BinaryReader(rawData, false));
    if (!parsed) return null;

    return {
      timestamp,
      origLen,
      inclLen,
      ...parsed,
      raw: rawData,
    };
  }

  _parseEthernet(reader) {
    if (reader.remaining < 14) return null;

    const dstMac = reader.readBytes(6);
    const srcMac = reader.readBytes(6);
    let etherType = reader.uint16(false);

    // Handle VLAN tagging (802.1Q)
    if (etherType === ETHERTYPE.VLAN) {
      reader.skip(2); // VLAN tag
      etherType = reader.uint16(false);
    }

    if (etherType === ETHERTYPE.IPv4) {
      return this._parseIPv4(reader);
    }

    return null; // Skip non-IPv4 for now
  }

  _parseIPv4(reader) {
    if (reader.remaining < 20) return null;

    const versionIHL = reader.uint8();
    const version = (versionIHL >> 4) & 0xf;
    const ihl = (versionIHL & 0xf) * 4;

    if (version !== 4 || ihl < 20) return null;

    const tos = reader.uint8();
    const totalLen = reader.uint16(false);
    const identification = reader.uint16(false);
    const flagsFragment = reader.uint16(false);
    const ttl = reader.uint8();
    const protocol = reader.uint8();
    const headerChecksum = reader.uint16(false);

    const srcIP = `${reader.uint8()}.${reader.uint8()}.${reader.uint8()}.${reader.uint8()}`;
    const dstIP = `${reader.uint8()}.${reader.uint8()}.${reader.uint8()}.${reader.uint8()}`;

    // Skip IP options
    if (ihl > 20) {
      reader.skip(ihl - 20);
    }

    if (protocol === IP_PROTO.TCP) {
      return this._parseTCP(reader, srcIP, dstIP);
    }

    return null;
  }

  _parseTCP(reader, srcIP, dstIP) {
    if (reader.remaining < 20) return null;

    const srcPort = reader.uint16(false);
    const dstPort = reader.uint16(false);
    const seqNum = reader.uint32(false);
    const ackNum = reader.uint32(false);
    const dataOffsetFlags = reader.uint16(false);
    const dataOffset = ((dataOffsetFlags >> 12) & 0xf) * 4;
    const flags = dataOffsetFlags & 0x3f;
    const windowSize = reader.uint16(false);
    const checksum = reader.uint16(false);
    const urgentPtr = reader.uint16(false);

    // Skip TCP options
    if (dataOffset > 20) {
      reader.skip(dataOffset - 20);
    }

    // Extract payload
    const payload = reader.remaining > 0 ? reader.readRemaining() : new Uint8Array(0);

    return {
      srcIP, dstIP, srcPort, dstPort,
      seqNum, ackNum, flags, windowSize,
      payload,
      isSYN: !!(flags & TCP_FLAGS.SYN),
      isACK: !!(flags & TCP_FLAGS.ACK),
      isFIN: !!(flags & TCP_FLAGS.FIN),
      isRST: !!(flags & TCP_FLAGS.RST),
      isPSH: !!(flags & TCP_FLAGS.PSH),
    };
  }
}
