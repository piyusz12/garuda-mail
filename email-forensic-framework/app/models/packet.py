from dataclasses import dataclass
from typing import Optional
import datetime

@dataclass
class PacketRecord:
    """Normalized internal representation of a packet"""
    timestamp: datetime.datetime
    
    # Network Layer
    src_ip: str
    dst_ip: str
    src_mac: str
    dst_mac: str
    ip_version: int
    ttl: int
    
    # Transport Layer
    protocol: str
    src_port: int
    dst_port: int
    
    # TCP Specific
    seq: int = 0
    ack: int = 0
    window_size: int = 0
    flags: int = 0
    
    # TCP Flags boolean helpers
    is_syn: bool = False
    is_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_psh: bool = False
    is_urg: bool = False
    
    # Payload
    payload_length: int = 0
    payload: bytes = b""
