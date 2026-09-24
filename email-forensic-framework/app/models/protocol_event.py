from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.models.encryption_event import EncryptionState
from app.models.tls_metadata import TLSMetadata

class ProtocolEvent(BaseModel):
    timestamp: datetime
    direction: str # "C2S" or "S2C"
    protocol: str
    event_type: str # e.g., "COMMAND", "RESPONSE"
    normalized_event: str # e.g., "SERVER_GREETING", "STARTTLS_REQUEST"
    command: Optional[str] = None
    stream_offset: int
    raw_length: int
    evidence: Optional[str] = None # A small snippet of the stream

class ProtocolDetection(BaseModel):
    name: str = "UNKNOWN"
    confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)

class SecurityIndicator(BaseModel):
    type: str
    severity_hint: str = "INFO"
    details: Optional[Dict[str, Any]] = None

class ProtocolAnalysis(BaseModel):
    """The final contract output of Phase 2 and 3"""
    session_id: str
    
    protocol: ProtocolDetection
    
    transport: Dict[str, Any] # src_ip, src_port, dst_ip, dst_port
    
    encryption: EncryptionState = Field(default_factory=EncryptionState)
    tls_metadata: Optional[TLSMetadata] = None

    
    events: List[ProtocolEvent] = Field(default_factory=list)
    security_indicators: List[SecurityIndicator] = Field(default_factory=list)
    
    parse_status: str = "COMPLETE" # COMPLETE, PARTIAL, ERROR
    
    # Internal state tracking
    port_hint: Optional[str] = None
    port_protocol_conflict: bool = False
