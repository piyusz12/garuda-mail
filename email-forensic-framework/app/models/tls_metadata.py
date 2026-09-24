from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class JA4Fingerprint(BaseModel):
    ja4: Optional[str] = None # Client Fingerprint
    ja4s: Optional[str] = None # Server Fingerprint

class X509Certificate(BaseModel):
    subject: str
    issuer: str
    subject_alt_names: List[str]
    not_before: datetime
    not_after: datetime
    is_expired: bool
    public_key_algorithm: str
    public_key_size: int
    signature_algorithm: str
    serial_number: str

class TLSMetadata(BaseModel):
    client_version: Optional[str] = None
    server_version: Optional[str] = None
    
    cipher_suites_offered: List[str] = []
    cipher_suite_selected: Optional[str] = None
    
    sni: Optional[str] = None
    alpn_offered: List[str] = []
    alpn_selected: Optional[str] = None
    
    extensions_offered: List[int] = []
    
    certificates: List[X509Certificate] = []
    
    ja4: JA4Fingerprint = JA4Fingerprint()
