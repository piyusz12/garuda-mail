from typing import List, Tuple
from datetime import datetime
import re

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolEvent, ProtocolDetection
from app.protocol.base import ProtocolAnalyzer

class IMAPAnalyzer(ProtocolAnalyzer):
    @property
    def protocol_name(self) -> str:
        return "IMAP"
        
    def detect(self, session: ReconstructedSession) -> ProtocolDetection:
        evidence = []
        score = 0.0
        
        s2c = session.server_stream[:1024].decode('ascii', errors='ignore')
        c2s = session.client_stream[:1024].decode('ascii', errors='ignore')
        
        if re.search(r'^\* OK ', s2c):
            score += 0.40
            evidence.append("* OK server greeting")
            
        if re.search(r'^[A-Za-z0-9]+\s+CAPABILITY', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.30
            evidence.append("CAPABILITY command")
            
        if re.search(r'^\* CAPABILITY ', s2c, re.MULTILINE):
            score += 0.20
            evidence.append("* CAPABILITY response")
            
        if re.search(r'^[A-Za-z0-9]+\s+LOGIN', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.15
            evidence.append("LOGIN command")
            
        return ProtocolDetection(name="IMAP", confidence=min(1.0, score), evidence=evidence)

    def parse(self, session: ReconstructedSession) -> Tuple[List[ProtocolEvent], str]:
        events = []
        status = "COMPLETE"
        
        # Server to Client
        s2c_lines = session.server_stream.split(b'\n')
        offset = 0
        for line_raw in s2c_lines:
            line = line_raw.decode('ascii', errors='ignore').strip()
            line_len = len(line_raw) + 1
            
            if line.startswith("* OK "):
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="S2C",
                    protocol="IMAP",
                    event_type="RESPONSE",
                    normalized_event="SERVER_GREETING",
                    command="* OK",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence=line[:50]
                ))
            elif "* CAPABILITY" in line and "STARTTLS" in line:
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="S2C",
                    protocol="IMAP",
                    event_type="RESPONSE",
                    normalized_event="STARTTLS_OFFER",
                    command="*",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="STARTTLS advertised"
                ))
            elif " OK " in line and ("TLS" in line or "Begin" in line):
                 events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="S2C",
                    protocol="IMAP",
                    event_type="RESPONSE",
                    normalized_event="STARTTLS_ACCEPT",
                    command="OK",
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
            
            # IMAP commands start with a tag, e.g., A001 STARTTLS
            match = re.match(r'^([A-Za-z0-9]+)\s+(.+)$', line, re.IGNORECASE)
            if match:
                tag = match.group(1)
                cmd_rest = match.group(2).upper()
                
                if cmd_rest.startswith("STARTTLS"):
                    events.append(ProtocolEvent(
                        timestamp=session.metadata.start_time,
                        direction="C2S",
                        protocol="IMAP",
                        event_type="COMMAND",
                        normalized_event="ENCRYPTION_UPGRADE_REQUEST",
                        command="STARTTLS",
                        stream_offset=offset,
                        raw_length=line_len,
                        evidence=f"{tag} STARTTLS"
                    ))
                elif cmd_rest.startswith("LOGIN "):
                    events.append(ProtocolEvent(
                        timestamp=session.metadata.start_time,
                        direction="C2S",
                        protocol="IMAP",
                        event_type="COMMAND",
                        normalized_event="AUTH_ATTEMPT",
                        command="LOGIN",
                        stream_offset=offset,
                        raw_length=line_len,
                        evidence=f"{tag} LOGIN [REDACTED]"
                    ))
            offset += line_len
            
        return events, status
