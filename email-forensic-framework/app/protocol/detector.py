from typing import List

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolAnalysis, ProtocolDetection
from app.protocol.base import ProtocolAnalyzer

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
    
    def __init__(self, analyzers: List[ProtocolAnalyzer]):
        self.analyzers = analyzers
        
    def detect(self, session: ReconstructedSession) -> ProtocolAnalysis:
        # Determine port hint
        server_port = session.metadata.server_port
        port_hint = KNOWN_PORTS.get(server_port)
        
        # Run payload detection across all analyzers
        detections: List[ProtocolDetection] = []
        for analyzer in self.analyzers:
            detection = analyzer.detect(session)
            if detection.confidence > 0:
                # Add minor confidence bump if port matches (max +0.05)
                if port_hint == analyzer.protocol_name:
                    detection.confidence = min(1.0, detection.confidence + 0.05)
                    detection.evidence.append(f"Port {server_port} matches known {port_hint} port")
                detections.append(detection)
                
        # Sort by confidence descending
        detections.sort(key=lambda d: d.confidence, reverse=True)
        
        if not detections:
            best_detection = ProtocolDetection(name="UNKNOWN", confidence=0.0)
        else:
            best_detection = detections[0]
            
        # Check for conflict
        conflict = False
        if port_hint and best_detection.name != "UNKNOWN" and port_hint != best_detection.name:
            conflict = True
            
        # Initialize the analysis contract
        transport = {
            "src_ip": session.metadata.client_ip,
            "src_port": session.metadata.client_port,
            "dst_ip": session.metadata.server_ip,
            "dst_port": session.metadata.server_port
        }
        
        analysis = ProtocolAnalysis(
            session_id=session.metadata.flow_id,
            protocol=best_detection,
            transport=transport,
            port_hint=port_hint,
            port_protocol_conflict=conflict
        )
        
        # If we have a decent match, parse events
        if best_detection.confidence > 0.5:
            # Find the winning analyzer
            winner = next((a for a in self.analyzers if a.protocol_name == best_detection.name), None)
            if winner:
                events, status = winner.parse(session)
                analysis.events = events
                analysis.parse_status = status
                
        return analysis
