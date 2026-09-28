from typing import List, Tuple
from datetime import datetime
import re

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolEvent, ProtocolDetection
from app.protocol.base import ProtocolAnalyzer

class POP3Analyzer(ProtocolAnalyzer):
    @property
    def protocol_name(self) -> str:
        return "POP3"
        
    def detect(self, session: ReconstructedSession) -> ProtocolDetection:
        evidence = []
        score = 0.0
        
        s2c = session.server_stream[:1024].decode('ascii', errors='ignore')
        c2s = session.client_stream[:1024].decode('ascii', errors='ignore')
        
        if re.search(r'^\+OK\s', s2c):
            score += 0.40
            evidence.append("+OK server greeting")
            
        if re.search(r'^USER\s', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.30
            evidence.append("USER command")
            
        if re.search(r'^PASS\s', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.20
            evidence.append("PASS command")
            
        if re.search(r'^CAPA', c2s, re.IGNORECASE | re.MULTILINE):
            score += 0.15
            evidence.append("CAPA command")
            
        return ProtocolDetection(name="POP3", confidence=min(1.0, score), evidence=evidence)

    def parse(self, session: ReconstructedSession) -> Tuple[List[ProtocolEvent], str]:
        events = []
        status = "COMPLETE"
        
        # Server to Client
        s2c_lines = session.server_stream.split(b'\n')
        offset = 0
        for line_raw in s2c_lines:
            line = line_raw.decode('ascii', errors='ignore').strip()
            line_len = len(line_raw) + 1
            
            if offset == 0 and line.startswith("+OK"):
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="S2C",
                    protocol="POP3",
                    event_type="RESPONSE",
                    normalized_event="SERVER_GREETING",
                    command="+OK",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence=line[:50]
                ))
            elif line.upper() == "STLS":
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="S2C",
                    protocol="POP3",
                    event_type="RESPONSE",
                    normalized_event="STARTTLS_OFFER",
                    command="STLS",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="STLS advertised"
                ))
            elif line.startswith("+OK") and ("TLS" in line or "Begin" in line):
                 events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="S2C",
                    protocol="POP3",
                    event_type="RESPONSE",
                    normalized_event="STARTTLS_ACCEPT",
                    command="+OK",
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
            
            if upper_line.startswith("STLS"):
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="C2S",
                    protocol="POP3",
                    event_type="COMMAND",
                    normalized_event="ENCRYPTION_UPGRADE_REQUEST",
                    command="STLS",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="STLS"
                ))
            elif upper_line.startswith("PASS "):
                events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="C2S",
                    protocol="POP3",
                    event_type="COMMAND",
                    normalized_event="AUTH_ATTEMPT",
                    command="PASS",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="PASS [REDACTED]"
                ))
            elif upper_line.startswith("USER "):
                 events.append(ProtocolEvent(
                    timestamp=session.metadata.start_time,
                    direction="C2S",
                    protocol="POP3",
                    event_type="COMMAND",
                    normalized_event="AUTH_ATTEMPT",
                    command="USER",
                    stream_offset=offset,
                    raw_length=line_len,
                    evidence="USER [REDACTED]"
                ))
            offset += line_len
            
        return events, status
