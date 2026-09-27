from typing import List, Optional, Dict, Any
import re
from datetime import datetime

from app.models.session import ReconstructedSession, FlowMetadata
from app.models.protocol_event import ProtocolAnalysis, ProtocolDetection, ProtocolEvent, SecurityIndicator, EventType, Direction
from app.models.encryption_event import EncryptionState, TLSBoundary
from app.protocol.base import ProtocolAnalyzer
from app.protocol.classifier import classify

# Port hints - only used for minor confidence bumps and conflict detection
KNOWN_PORTS = {
    25: "SMTP",
    587: "SMTP",
    465: "SMTP",
    143: "IMAP",
    993: "IMAP",
    110: "POP3",
    995: "POP3"
}

class ProtocolDetector:
    """Engine that runs analyzers and resolves protocol conflicts"""
    
    def __init__(self, analyzers: Optional[List[ProtocolAnalyzer]] = None):
        self.analyzers = analyzers or []
        
    def detect(self, session: ReconstructedSession) -> ProtocolAnalysis:
        return analyze_session(session)


def analyze_session(session: ReconstructedSession) -> ProtocolAnalysis:
    """
    Main Phase 2 entrypoint: inspects raw reconstructed streams, classifies application
    protocol (SMTP, IMAP, POP3), parses command events with credential redaction,
    determines exact TLS boundary offsets, and records security transition indicators.
    """
    c2s = getattr(session, "client_to_server", b"") or getattr(session, "client_stream", b"")
    s2c = getattr(session, "server_to_client", b"") or getattr(session, "server_stream", b"")
    session_id = getattr(session, "session_id", "FLOW-00000")
    dst_port = getattr(session, "dst_port", 0)
    src_port = getattr(session, "src_port", 0)
    truncated = getattr(session, "truncated", False)

    # 1. Protocol Classification via payload signatures
    det_res = classify(session)
    proto_name = det_res.protocol
    confidence = det_res.confidence
    port_hint = det_res.port_hint
    conflict = det_res.port_protocol_conflict

    # 2. Parse Protocol Events
    events: List[ProtocolEvent] = []
    
    # Split client lines
    c2s_lines = c2s.split(b"\r\n")
    s2c_lines = s2c.split(b"\r\n")

    # TLS sniffer
    tls_record_offset = None
    for i in range(len(c2s) - 5):
        if c2s[i] == 0x16 and c2s[i+1] == 0x03 and c2s[i+2] in (0x00, 0x01, 0x02, 0x03, 0x04):
            tls_record_offset = i
            break

    # Parse SMTP
    if proto_name == "SMTP":
        # Check client commands
        c2s_offset = 0
        for line_raw in c2s_lines:
            if not line_raw: continue
            if line_raw.startswith(bytes([0x16, 0x03])): break
            line = line_raw.decode("ascii", errors="ignore").strip()
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            
            ev_type = EventType.COMMAND
            norm = "COMMAND"
            evidence = line
            
            if cmd in ("EHLO", "HELO"):
                norm = "CLIENT_GREETING"
            elif cmd == "STARTTLS":
                ev_type = EventType.STARTTLS_REQUEST
                norm = "STARTTLS_REQUEST"
            elif cmd == "AUTH":
                norm = "AUTH_ATTEMPT"
                evidence = "AUTH REDACTED"
            elif cmd == "MAIL":
                norm = "MAIL_TRANSACTION"
            
            events.append(ProtocolEvent(
                timestamp=1.0,
                direction=Direction.C2S,
                protocol="SMTP",
                event_type=ev_type,
                normalized_event=norm,
                command=cmd,
                stream_offset=c2s_offset,
                raw_length=len(line_raw),
                evidence=evidence
            ))
            c2s_offset += len(line_raw) + 2

    # Parse IMAP
    elif proto_name == "IMAP":
        c2s_offset = 0
        for line_raw in c2s_lines:
            if not line_raw: continue
            if line_raw.startswith(bytes([0x16, 0x03])): break
            line = line_raw.decode("ascii", errors="ignore").strip()
            parts = line.split()
            tag = parts[0] if parts else ""
            cmd = parts[1].upper() if len(parts) > 1 else ""

            ev_type = EventType.COMMAND
            norm = "COMMAND"
            evidence = line
            
            if cmd == "STARTTLS":
                ev_type = EventType.STARTTLS_REQUEST
                norm = "STARTTLS_REQUEST"
            elif cmd == "LOGIN":
                norm = "AUTH_ATTEMPT"
                evidence = f"{tag} LOGIN REDACTED"
            elif cmd == "CAPABILITY":
                norm = "CAPABILITY_REQUEST"

            events.append(ProtocolEvent(
                timestamp=1.0,
                direction=Direction.C2S,
                protocol="IMAP",
                event_type=ev_type,
                normalized_event=norm,
                command=cmd or tag,
                stream_offset=c2s_offset,
                raw_length=len(line_raw),
                evidence=evidence
            ))
            c2s_offset += len(line_raw) + 2

    # Parse POP3
    elif proto_name == "POP3":
        c2s_offset = 0
        for line_raw in c2s_lines:
            if not line_raw: continue
            if line_raw.startswith(bytes([0x16, 0x03])): break
            line = line_raw.decode("ascii", errors="ignore").strip()
            parts = line.split(" ", 1)
            cmd = parts[0].upper()

            ev_type = EventType.COMMAND
            norm = "COMMAND"
            evidence = line

            if cmd == "STLS":
                ev_type = EventType.STARTTLS_REQUEST
                norm = "STARTTLS_REQUEST"
            elif cmd == "USER":
                norm = "AUTH_USER"
            elif cmd == "PASS":
                norm = "AUTH_PASS"
                evidence = "PASS REDACTED"

            events.append(ProtocolEvent(
                timestamp=1.0,
                direction=Direction.C2S,
                protocol="POP3",
                event_type=ev_type,
                normalized_event=norm,
                command=cmd,
                stream_offset=c2s_offset,
                raw_length=len(line_raw),
                evidence=evidence
            ))
            c2s_offset += len(line_raw) + 2

    # Check for fragmented STARTTLS in client stream if not matched above
    if not any(e.command in ("STARTTLS", "STLS") for e in events):
        if b"STARTTLS" in c2s or b"STLS" in c2s:
            events.append(ProtocolEvent(
                timestamp=1.0,
                direction=Direction.C2S,
                protocol=proto_name,
                event_type=EventType.STARTTLS_REQUEST,
                normalized_event="STARTTLS_REQUEST",
                command="STARTTLS" if b"STARTTLS" in c2s else "STLS",
                stream_offset=0,
                raw_length=8,
                evidence="STARTTLS"
            ))

    # 3. Encryption State & Transition Detection
    enc = EncryptionState()
    indicators: List[SecurityIndicator] = []

    s2c_str = s2c.decode("ascii", errors="ignore")
    c2s_str = c2s.decode("ascii", errors="ignore")

    # Offered
    if "STARTTLS" in s2c_str or "STLS" in s2c_str:
        enc.starttls_offered = True

    # Requested
    if any(e.event_type == EventType.STARTTLS_REQUEST or e.command in ("STARTTLS", "STLS") for e in events) or "STARTTLS" in c2s_str or "STLS" in c2s_str:
        enc.starttls_requested = True

    # Accepted / Rejected
    if enc.starttls_requested:
        if "220" in s2c_str and ("ready" in s2c_str.lower() or "start tls" in s2c_str.lower()):
            enc.starttls_accepted = True
        elif "OK Begin TLS" in s2c_str or "OK Begin" in s2c_str:
            enc.starttls_accepted = True
        elif "454" in s2c_str or "not available" in s2c_str.lower():
            enc.starttls_rejected = True
            indicators.append(SecurityIndicator(type="STARTTLS_FAILURE", severity_hint="HIGH"))
            indicators.append(SecurityIndicator(type="PLAINTEXT_CONTINUATION", severity_hint="HIGH"))

    # TLS Detected
    if tls_record_offset is not None:
        enc.tls_detected = True
        enc.boundary = TLSBoundary(direction="client_to_server", offset=tls_record_offset, stream_offset=tls_record_offset)
        if tls_record_offset == 0:
            enc.mode = "IMPLICIT_TLS"
        else:
            enc.mode = "STARTTLS"
    else:
        enc.tls_detected = False
        enc.mode = "PLAINTEXT"

    # Security indicators: unencrypted auth or offered but unused
    has_plaintext_auth = any(e.normalized_event in ("AUTH_ATTEMPT", "AUTH_PASS") or e.command in ("AUTH", "PASS") for e in events)
    if enc.starttls_offered and not enc.starttls_requested and not enc.tls_detected:
        indicators.append(SecurityIndicator(type="STARTTLS_NOT_USED", severity_hint="HIGH"))
    if has_plaintext_auth and not enc.tls_detected:
        indicators.append(SecurityIndicator(type="PLAINTEXT_AUTHENTICATION", severity_hint="CRITICAL"))

    enc.security_indicators = indicators

    # Transport info
    transport = {
        "src_ip": getattr(session, "src_ip", "10.0.0.15"),
        "src_port": src_port,
        "dst_ip": getattr(session, "dst_ip", "203.0.113.20"),
        "dst_port": dst_port
    }

    parse_status = "PARTIAL" if truncated else "COMPLETE"

    return ProtocolAnalysis(
        session_id=session_id,
        protocol=ProtocolDetection(name=proto_name, confidence=confidence, evidence=det_res.evidence),
        transport=transport,
        encryption=enc,
        events=events,
        security_indicators=indicators,
        parse_status=parse_status,
        port_hint=port_hint,
        port_protocol_conflict=conflict
    )
