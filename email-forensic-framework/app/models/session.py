from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class Evidence(BaseModel):
    id: str
    filename: str
    sha256: str
    size_bytes: int
    ingested_at: datetime
    status: str = "immutable"
    
class GapRecord(BaseModel):
    start_seq: int
    end_seq: int
    length: int

class ReassemblyMetadata(BaseModel):
    retransmissions: int = 0
    overlaps: int = 0
    gaps: int = 0
    complete_client_stream: bool = False
    complete_server_stream: bool = False
    overlap_policy_used: str

class FlowTermination(BaseModel):
    reason: str

class FlowMetadata(BaseModel):
    flow_id: str
    evidence_id: str
    protocol: str = "TCP"
    
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    
    start_time: datetime
    end_time: datetime
    duration_ms: int
    
    packet_count: int
    client_bytes: int
    server_bytes: int
    
    tcp_state: str
    termination: FlowTermination
    reassembly: ReassemblyMetadata

class ReconstructedSession(BaseModel):
    """The fully reconstructed TCP session, passed to Phase 2"""
    metadata: FlowMetadata
    client_stream: bytes
    server_stream: bytes
