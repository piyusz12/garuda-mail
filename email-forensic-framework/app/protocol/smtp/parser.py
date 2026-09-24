from typing import List, Tuple
from datetime import datetime
import re

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolEvent, ProtocolDetection
from app.protocol.base import ProtocolAnalyzer

class SMTPAnalyzer(ProtocolAnalyzer):
    @property
    def protocol_name(self) -> str:
        return "SMTP"
        
    def detect(self, session: ReconstructedSession) -> ProtocolDetection:
        evidence = []
        score = 0.0
        
        # We need to look at the initial parts of the server and client streams
        s2c = session.server_stream[:1024].decode('ascii', errors='ignore')
        c2s = session.client_stream[:1024].decode('ascii', errors='ignore')
        
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
        
        # Simplistic line-based tokenizer for C2S and S2C
        # In a real rigorous parser, we would interleave by sequence/timestamp.
        # Here we just parse what we see to find events.
        
        # Server to Client
        s2c_lines = session.server_stream.split(b'\n')
        offset = 0
        for line_raw in s2c_lines:
            line = line_raw.decode('ascii', errors='ignore').strip()
            line_len = len(line_raw) + 1 # +1 for \n
            
            if line.startswith("220 ") and "ESMTP" in line or "SMTP" in line:
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time, # Approx
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
                    timestamp=session.metadata.start_time, 
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
                    timestamp=session.metadata.start_time,
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
                        timestamp=session.metadata.start_time,
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
        c2s_lines = session.client_stream.split(b'\n')
        offset = 0
        for line_raw in c2s_lines:
            line = line_raw.decode('ascii', errors='ignore').strip()
            line_len = len(line_raw) + 1
            
            upper_line = line.upper()
            if upper_line.startswith("EHLO") or upper_line.startswith("HELO"):
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="C2S",
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
                    timestamp=session.metadata.start_time,
                    direction="C2S",
                    protocol="SMTP",
                    event_type="COMMAND",
                    normalized_event="ENCRYPTION_UPGRADE_REQUEST",
                    command="STARTTLS",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="STARTTLS"
                ))
            elif upper_line.startswith("AUTH PLAIN"):
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="C2S",
                    protocol="SMTP",
                    event_type="COMMAND",
                    normalized_event="AUTH_ATTEMPT",
                    command="AUTH",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="AUTH PLAIN [REDACTED]"
                ))
            offset += line_len
            
        return events, status
