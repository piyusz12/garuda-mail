from pydantic import BaseModel, Field
from typing import Optional, List, Any

class TLSBoundary(BaseModel):
    direction: str = "c2s"  # "C2S" or "S2C"
    offset: int = 0
    stream_offset: int = 0
    timestamp: float = 0.0

    def __getitem__(self, item: str):
        if item == "direction":
            return "client_to_server" if self.direction.lower() in ("c2s", "client_to_server") else "server_to_client"
        if item in ("offset", "stream_offset"):
            return self.offset or self.stream_offset
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

class EncryptionState(BaseModel):
    mode: str = "UNKNOWN"  # PLAINTEXT, STARTTLS, IMPLICIT_TLS
    starttls_offered: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    starttls_rejected: bool = False
    tls_detected: bool = False
    boundary: Optional[TLSBoundary] = None
    security_indicators: List[Any] = Field(default_factory=list)

    def __getitem__(self, item: str):
        if item == "offered":
            return self.starttls_offered
        if item == "requested":
            return self.starttls_requested
        if item == "accepted":
            return self.starttls_accepted
        if item == "rejected":
            return self.starttls_rejected
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

