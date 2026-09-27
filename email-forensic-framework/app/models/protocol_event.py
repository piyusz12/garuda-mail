from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum

from app.models.encryption_event import EncryptionState, TLSBoundary
from app.models.tls_metadata import TLSMetadata

class Direction(str, Enum):
    C2S = "c2s"
    S2C = "s2c"

class EventType(str, Enum):
    COMMAND = "COMMAND"
    RESPONSE = "RESPONSE"
    STARTTLS_REQUEST = "STARTTLS_REQUEST"
    STARTTLS_RESPONSE = "STARTTLS_RESPONSE"
    TLS_CLIENT_HELLO = "TLS_CLIENT_HELLO"

class ProtocolEvent(BaseModel):
    timestamp: Union[datetime, float]
    direction: Union[Direction, str] # "C2S" or "S2C"
    protocol: str = "UNKNOWN"
    event_type: Union[EventType, str] # e.g., "COMMAND", "RESPONSE"
    normalized_event: str = "" # e.g., "SERVER_GREETING", "STARTTLS_REQUEST"
    command: Optional[str] = None
    stream_offset: int = 0
    raw_length: int = 0
    evidence: Optional[str] = None # A small snippet of the stream

class ProtocolDetection(BaseModel):
    name: str = "UNKNOWN"
    confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.name.upper() == other.upper()
        if isinstance(other, ProtocolDetection):
            return self.name == other.name and self.confidence == other.confidence
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.name)

class SecurityIndicator(BaseModel):
    type: str
    severity_hint: str = "INFO"
    details: Optional[Dict[str, Any]] = None

    def __getitem__(self, item: str):
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

class ProtocolAnalysis(BaseModel):
    """The final contract output of Phase 2 and 3"""
    session_id: str
    protocol: ProtocolDetection
    transport: Dict[str, Any] = Field(default_factory=dict) # src_ip, src_port, dst_ip, dst_port
    encryption: EncryptionState = Field(default_factory=EncryptionState)
    tls_metadata: Optional[TLSMetadata] = None
    events: List[ProtocolEvent] = Field(default_factory=list)
    security_indicators: List[SecurityIndicator] = Field(default_factory=list)
    parse_status: str = "COMPLETE" # COMPLETE, PARTIAL, ERROR
    port_hint: Optional[str] = None
    port_protocol_conflict: bool = False

    @property
    def confidence(self) -> float:
        return self.protocol.confidence

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump() if hasattr(self, "model_dump") else self.dict()
        # Ensure protocol dictionary has confidence_bucket
        if "protocol" in d and isinstance(d["protocol"], dict):
            conf = d["protocol"].get("confidence", 0.0)
            bucket = "HIGH" if conf >= 0.90 else ("MEDIUM" if conf >= 0.70 else "LOW")
            d["protocol"]["confidence_bucket"] = bucket

        # Ensure encryption dictionary has expected keys
        if "encryption" in d and isinstance(d["encryption"], dict):
            enc = d["encryption"]
            enc["offered"] = enc.get("starttls_offered", False)
            enc["requested"] = enc.get("starttls_requested", False)
            enc["accepted"] = enc.get("starttls_accepted", False)
            enc["rejected"] = enc.get("starttls_rejected", False)
            if enc.get("boundary") and isinstance(enc["boundary"], dict):
                b = enc["boundary"]
                if "offset" not in b and "stream_offset" in b:
                    b["offset"] = b["stream_offset"]
                if "direction" in b:
                    b["direction"] = "client_to_server" if b["direction"].lower() in ("c2s", "client_to_server") else "server_to_client"
        return d

