from typing import List, Tuple
from datetime import datetime
import re

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolEvent, ProtocolDetection, EventType
from app.protocol.base import ProtocolAnalyzer

class SMTPAnalyzer(ProtocolAnalyzer):
    @property
    def protocol_name(self) -> str:
        return "SMTP"
        
    def detect(self, session: ReconstructedSession) -> ProtocolDetection:
        evidence = []
        score = 0.0
        
        # We need to look at the initial parts of the server and client streams
        s2c_b = getattr(session, "server_stream", b"") or getattr(session, "server_to_client", b"")
        c2s_b = getattr(session, "client_stream", b"") or getattr(session, "client_to_server", b"")
        s2c = s2c_b[:1024].decode('ascii', errors='ignore')
        c2s = c2s_b[:1024].decode('ascii', errors='ignore')
        
        if re.search(r'^220\s+[-A-Za-z0-9.]+', s2c):
            score += 0.30
            evidence.append("220 server greeting")
            
        if re.search(r'^(EHLO|HELO)\s', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.30
            evidence.append("EHLO/HELO command")
            
        if re.search(r'^250[-\s]', s2c, re.MULTILINE):
            score += 0.15
            evidence.append("250 response")
            
        if re.search(r'^MAIL FROM:', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.15
            evidence.append("MAIL FROM command")
            
        if re.search(r'^RCPT TO:', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.10
            evidence.append("RCPT TO command")
            
        return ProtocolDetection(name="SMTP", confidence=min(1.0, score), evidence=evidence)

    def parse(self, session: ReconstructedSession) -> Tuple[List[ProtocolEvent], str]:
        events = []
        status = "COMPLETE"
        ts = session.metadata.start_time if getattr(session, "metadata", None) else datetime.now()
        
        # Simplistic line-based tokenizer for C2S and S2C
        # Server to Client
        s2c_bytes = getattr(session, "server_stream", b"") or getattr(session, "server_to_client", b"")
        s2c_lines = s2c_bytes.split(b'\n')
        offset = 0
        for line_raw in s2c_lines:
            line = line_raw.decode('ascii', errors='ignore').strip()
            line_len = len(line_raw) + 1 # +1 for \n
            
            if line.startswith("220 ") and ("ESMTP" in line or "SMTP" in line):
                events.append(ProtocolEvent(
                    timestamp=ts,
                    direction="S2C",
                    protocol="SMTP",
                    event_type="RESPONSE",
                    normalized_event="SERVER_GREETING",
                    command=line[:3],
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence=line[:50]
                ))
            elif "250-STARTTLS" in line or "250 STARTTLS" in line:
                events.append(ProtocolEvent(
                    timestamp=ts, 
                    direction="S2C",
                    protocol="SMTP",
                    event_type="RESPONSE",
                    normalized_event="STARTTLS_OFFER",
                    command="250",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="250-STARTTLS"
                ))
            elif line.startswith("220 ") and ("TLS" in line or "Ready" in line):
                 events.append(ProtocolEvent(
                    timestamp=ts,
                    direction="S2C",
                    protocol="SMTP",
                    event_type="RESPONSE",
                    normalized_event="STARTTLS_ACCEPT",
                    command="220",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence=line[:50]
                ))
            elif line.startswith("454 ") or line.startswith("5"):
                 if "TLS" in line:
                    events.append(ProtocolEvent(
                        timestamp=ts,
                        direction="S2C",
                        protocol="SMTP",
                        event_type="RESPONSE",
                        normalized_event="STARTTLS_REJECT",
                        command=line[:3],
                        stream_offset=offset,
                        raw_length=line_len,
                        evidence=line[:50]
                    ))
            offset += line_len


        # Client to Server
        c2s_bytes = getattr(session, "client_stream", b"") or getattr(session, "client_to_server", b"")
        c2s_lines = c2s_bytes.split(b'\n')
        offset = 0
        for line_raw in c2s_lines:
            line = line_raw.decode('ascii', errors='ignore').strip()
            line_len = len(line_raw) + 1
            
            upper_line = line.upper()
            if upper_line.startswith("EHLO") or upper_line.startswith("HELO"):
                events.append(ProtocolEvent(
                    timestamp=ts,
                    direction="c2s",
                    protocol="SMTP",
                    event_type="COMMAND",
                    normalized_event="EHLO",
                    command=line[:4],
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence=line[:50]
                ))
            elif upper_line.startswith("STARTTLS"):
                events.append(ProtocolEvent(
                    timestamp=ts,
                    direction="c2s",
                    protocol="SMTP",
                    event_type=EventType.STARTTLS_REQUEST,
                    normalized_event="ENCRYPTION_UPGRADE_REQUEST",
                    command="STARTTLS",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="STARTTLS"
                ))
            elif upper_line.startswith("AUTH PLAIN"):
                events.append(ProtocolEvent(
                    timestamp=ts,
                    direction="c2s",
                    protocol="SMTP",
                    event_type="COMMAND",
                    normalized_event="AUTH_ATTEMPT",
                    command="AUTH",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="AUTH PLAIN [REDACTED]"
                ))
            offset += line_len
            
        # Detect TLS ClientHello record
        for i in range(len(c2s_bytes) - 5):
            if c2s_bytes[i] == 0x16 and c2s_bytes[i+1] == 0x03 and c2s_bytes[i+2] in (0x00, 0x01, 0x02, 0x03, 0x04):
                events.append(ProtocolEvent(
                    timestamp=ts,
                    direction="c2s",
                    protocol="SMTP",
                    event_type=EventType.TLS_CLIENT_HELLO,
                    normalized_event="TLS_CLIENT_HELLO",
                    command=None,
                    stream_offset=i,
                    raw_length=len(c2s_bytes) - i,
                    evidence="TLS ClientHello"
                ))
                break

        return ParseResult(events, status)


class ParseResult(dict):
    """Result supporting both tuple unpacking (events, status) and dictionary access result['events']."""
    def __init__(self, events, status):
        super().__init__({"events": events, "status": status})
        self.events = events
        self.status = status

    def __iter__(self):
        return iter((self.events, self.status))

SMTPParser = SMTPAnalyzer

