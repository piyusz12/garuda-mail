from dataclasses import dataclass, field
from typing import Dict, List, Optional
import datetime

from app.models.packet import PacketRecord
from app.flow.tcp_state import TCPStateMachine, TCPState

@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "TCP"
    
    def canonical(self) -> str:
        """Returns direction-agnostic canonical string representation"""
        if self.src_ip < self.dst_ip or (self.src_ip == self.dst_ip and self.src_port < self.dst_port):
            return f"{self.protocol}-{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"
        return f"{self.protocol}-{self.dst_ip}:{self.dst_port}-{self.src_ip}:{self.src_port}"
        
@dataclass
class Flow:
    flow_id: str
    key: FlowKey
    
    # We lock in client/server roles once we see SYN
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    
    packet_count: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    
    state_machine: TCPStateMachine = field(default_factory=TCPStateMachine)
    packets: List[PacketRecord] = field(default_factory=list)
    
    def add_packet(self, pkt: PacketRecord):
        if not self.start_time:
            self.start_time = pkt.timestamp
        self.end_time = pkt.timestamp
        self.packet_count += 1
        self.packets.append(pkt)
        
        # Determine direction
        if self.client_ip is None:
            if pkt.is_syn and not pkt.is_ack:
                self.client_ip = pkt.src_ip
                self.client_port = pkt.src_port
                self.server_ip = pkt.dst_ip
                self.server_port = pkt.dst_port
            elif pkt.is_syn and pkt.is_ack:
                self.server_ip = pkt.src_ip
                self.server_port = pkt.src_port
                self.client_ip = pkt.dst_ip
                self.client_port = pkt.dst_port
            else:
                # Heuristic fallback
                if pkt.src_port > pkt.dst_port:
                    self.client_ip = pkt.src_ip
                    self.client_port = pkt.src_port
                    self.server_ip = pkt.dst_ip
                    self.server_port = pkt.dst_port
                else:
                    self.server_ip = pkt.src_ip
                    self.server_port = pkt.src_port
                    self.client_ip = pkt.dst_ip
                    self.client_port = pkt.dst_port
                    
        is_client = (pkt.src_ip == self.client_ip and pkt.src_port == self.client_port)
        
        if is_client:
            self.client_bytes += pkt.payload_length
        else:
            self.server_bytes += pkt.payload_length
            
        self.state_machine.process_flags(is_client, pkt.is_syn, pkt.is_ack, pkt.is_fin, pkt.is_rst)

class FlowManager:
    """Manages flows by 5-tuple"""
    def __init__(self):
        self.flows: Dict[str, Flow] = {}
        self._flow_counter = 0
        
    def process_packet(self, pkt: PacketRecord) -> Flow:
        key = FlowKey(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        canonical = key.canonical()
        
        if canonical not in self.flows:
            self._flow_counter += 1
            flow_id = f"FLOW-{self._flow_counter:05X}"
            self.flows[canonical] = Flow(flow_id=flow_id, key=key)
            
        flow = self.flows[canonical]
        flow.add_packet(pkt)
        return flow
