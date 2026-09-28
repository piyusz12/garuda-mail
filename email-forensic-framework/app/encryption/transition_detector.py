from typing import List, Optional

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolAnalysis, ProtocolEvent, SecurityIndicator
from app.models.encryption_event import EncryptionState, TLSBoundary

class EncryptionTransitionDetector:
    def detect(self, session: ReconstructedSession, analysis: ProtocolAnalysis):
        state = EncryptionState()
        indicators: List[SecurityIndicator] = []
        
        # 1. Detect Implicit TLS (TLS immediately after TCP connection)
        # Check first 5 bytes of C2S stream for TLS Record (16 03 01/02/03)
        if self._is_tls_handshake(session.client_stream, 0):
            state.mode = "IMPLICIT_TLS"
            state.tls_detected = True
            state.boundary = TLSBoundary(direction="C2S", offset=0)
            analysis.encryption = state
            return
            
        # 2. Extract STARTTLS state from protocol events
        has_auth = False
        
        for event in analysis.events:
            if event.normalized_event == "STARTTLS_OFFER":
                state.starttls_offered = True
            elif event.normalized_event == "ENCRYPTION_UPGRADE_REQUEST":
                state.starttls_requested = True
            elif event.normalized_event == "STARTTLS_ACCEPT":
                state.starttls_accepted = True
            elif event.normalized_event == "STARTTLS_REJECT":
                indicators.append(SecurityIndicator(
                    type="STARTTLS_FAILURE",
                    severity_hint="HIGH"
                ))
            elif event.normalized_event == "AUTH_ATTEMPT":
                has_auth = True
                
        # 3. Detect TLS Boundary (Explicit STARTTLS)
        # We need to find where the TLS ClientHello begins in the C2S stream
        # This usually happens right after the STARTTLS_ACCEPT event from S2C.
        tls_offset = self._find_tls_boundary(session.client_stream)
        
        if tls_offset is not None:
            state.tls_detected = True
            state.mode = "STARTTLS"
            state.boundary = TLSBoundary(direction="C2S", offset=tls_offset)
        else:
            state.mode = "PLAINTEXT"
            
        # 4. Generate Security Indicators
        if state.starttls_offered and not state.starttls_requested and not state.tls_detected:
            indicators.append(SecurityIndicator(
                type="STARTTLS_NOT_USED",
                severity_hint="HIGH"
            ))
            
        if has_auth and not state.tls_detected:
            indicators.append(SecurityIndicator(
                type="PLAINTEXT_AUTHENTICATION",
                severity_hint="CRITICAL",
                details={"before_tls": True}
            ))
            
        if state.starttls_requested and not state.starttls_accepted and not state.tls_detected:
            indicators.append(SecurityIndicator(
                type="PLAINTEXT_CONTINUATION",
                severity_hint="HIGH"
            ))
            
        analysis.encryption = state
        analysis.security_indicators.extend(indicators)

    def _is_tls_handshake(self, stream: bytes, offset: int) -> bool:
        if not stream or len(stream) < offset + 5:
            return False
        # Content Type 22 (0x16) = Handshake
        # Version (0x03 0x00, 0x03 0x01, 0x03 0x02, 0x03 0x03, 0x03 0x04)
        return stream[offset] == 0x16 and stream[offset+1] == 0x03 and stream[offset+2] in (0x00, 0x01, 0x02, 0x03, 0x04)

    def _find_tls_boundary(self, c2s_stream: bytes) -> Optional[int]:
        """
        Scans the client stream to find the first TLS ClientHello record.
        This usually follows a \r\n from the STARTTLS command.
        """
        # Very simplistic scanner: look for \x16\x03 sequence
        for i in range(len(c2s_stream) - 5):
            if self._is_tls_handshake(c2s_stream, i):
                return i
        return None
