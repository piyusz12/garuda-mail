from pydantic import BaseModel
from typing import Optional

class TLSBoundary(BaseModel):
    direction: str  # "C2S" or "S2C"
    offset: int

class EncryptionState(BaseModel):
    mode: str = "UNKNOWN"  # PLAINTEXT, STARTTLS, IMPLICIT_TLS
    
    starttls_offered: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    
    tls_detected: bool = False
    boundary: Optional[TLSBoundary] = None
