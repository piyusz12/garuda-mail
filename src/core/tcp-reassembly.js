/**
 * TCP Stream Reassembly — In-memory state machine per flow
 * Buffers segments by SEQ, handles out-of-order, outputs contiguous byte streams
 */

export class TCPReassembler {
  constructor() {
    this.flows = new Map();
    this.completedFlows = [];
  }

  /**
   * Generate a unique flow key from the 5-tuple
   */
  flowKey(srcIP, dstIP, srcPort, dstPort) {
    // Normalize direction — use lower IP:port as the first part
    if (srcIP < dstIP || (srcIP === dstIP && srcPort < dstPort)) {
      return `${srcIP}:${srcPort}-${dstIP}:${dstPort}`;
    }
    return `${dstIP}:${dstPort}-${srcIP}:${srcPort}`;
  }

  /**
   * Process a parsed TCP packet
   */
  processPacket(packet) {
    const key = this.flowKey(packet.srcIP, packet.dstIP, packet.srcPort, packet.dstPort);

    if (!this.flows.has(key)) {
      this.flows.set(key, {
        key,
        srcIP: packet.srcIP,
        dstIP: packet.dstIP,
        srcPort: packet.srcPort,
        dstPort: packet.dstPort,
        clientToServer: [],
        serverToClient: [],
        state: 'INIT',
        startTime: packet.timestamp,
        endTime: packet.timestamp,
        packets: [],
        clientIP: null,
        serverIP: null,
        clientPort: null,
        serverPort: null,
      });
    }

    const flow = this.flows.get(key);
    flow.endTime = packet.timestamp;
    flow.packets.push(packet);

    // Track client/server direction by SYN
    if (packet.isSYN && !packet.isACK) {
      flow.clientIP = packet.srcIP;
      flow.clientPort = packet.srcPort;
      flow.serverIP = packet.dstIP;
      flow.serverPort = packet.dstPort;
      flow.state = 'SYN_SENT';
    } else if (packet.isSYN && packet.isACK) {
      flow.state = 'SYN_ACK';
      if (!flow.clientIP) {
        flow.serverIP = packet.srcIP;
        flow.serverPort = packet.srcPort;
        flow.clientIP = packet.dstIP;
        flow.clientPort = packet.dstPort;
      }
    }

    // Determine direction if not yet determined
    if (!flow.clientIP) {
      // Heuristic: lower port is likely the server
      if (packet.srcPort < packet.dstPort) {
        flow.serverIP = packet.srcIP;
        flow.serverPort = packet.srcPort;
        flow.clientIP = packet.dstIP;
        flow.clientPort = packet.dstPort;
      } else {
        flow.clientIP = packet.srcIP;
        flow.clientPort = packet.srcPort;
        flow.serverIP = packet.dstIP;
        flow.serverPort = packet.dstPort;
      }
    }

    // Add payload to appropriate direction
    if (packet.payload && packet.payload.length > 0) {
      const isFromClient = (packet.srcIP === flow.clientIP && packet.srcPort === flow.clientPort);
      if (isFromClient) {
        flow.clientToServer.push({
          seqNum: packet.seqNum,
          data: packet.payload,
          timestamp: packet.timestamp,
        });
      } else {
        flow.serverToClient.push({
          seqNum: packet.seqNum,
          data: packet.payload,
          timestamp: packet.timestamp,
        });
      }
      flow.state = 'ESTABLISHED';
    }

    // Detect termination
    if (packet.isFIN || packet.isRST) {
      flow.state = packet.isRST ? 'RESET' : 'CLOSING';
    }
  }

  /**
   * Process all packets and return completed flows
   */
  processAll(packets) {
    for (const pkt of packets) {
      this.processPacket(pkt);
    }
    return this.getFlows();
  }

  /**
   * Get all reconstructed flows with merged payloads
   */
  getFlows() {
    const result = [];

    for (const flow of this.flows.values()) {
      // Sort segments by sequence number and merge
      const clientData = this._mergeSegments(flow.clientToServer);
      const serverData = this._mergeSegments(flow.serverToClient);

      result.push({
        key: flow.key,
        clientIP: flow.clientIP,
        clientPort: flow.clientPort,
        serverIP: flow.serverIP,
        serverPort: flow.serverPort,
        startTime: flow.startTime,
        endTime: flow.endTime,
        state: flow.state,
        clientData,
        serverData,
        packetCount: flow.packets.length,
        duration: flow.endTime - flow.startTime,
        timestamps: flow.packets.map(p => p.timestamp),
      });
    }

    return result;
  }

  /**
   * Merge ordered TCP segments into a contiguous byte array
   */
  _mergeSegments(segments) {
    if (segments.length === 0) return new Uint8Array(0);

    // Sort by sequence number
    segments.sort((a, b) => a.seqNum - b.seqNum);

    // Simple concatenation (handles basic reassembly)
    const totalLen = segments.reduce((sum, s) => sum + s.data.length, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;

    for (const seg of segments) {
      merged.set(seg.data, offset);
      offset += seg.data.length;
    }

    return merged;
  }
}
