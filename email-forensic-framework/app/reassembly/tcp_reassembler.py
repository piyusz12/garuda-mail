import json
from pathlib import Path
from typing import List, Optional

from app.config import config
from app.logger import logger
from app.flow.flow_manager import Flow
from app.models.session import (
    ReconstructedSession,
    FlowMetadata,
    FlowTermination,
    ReassemblyMetadata
)
from app.reassembly.sequence_buffer import SequenceBuffer

class TCPReassembler:
    """Takes Flow objects and finalizes them into ReconstructedSessions"""
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or config.OUTPUT_DIR
        self.sessions_dir = self.output_dir / "sessions"
        self.streams_dir = self.output_dir / "streams"
        
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.streams_dir.mkdir(parents=True, exist_ok=True)

    def finalize(self, flow: Flow, evidence_id: str) -> ReconstructedSession:
        logger.info("REASSEMBLING_FLOW", flow_id=flow.flow_id)
        
        client_buffer = SequenceBuffer(policy=config.OVERLAP_POLICY)
        server_buffer = SequenceBuffer(policy=config.OVERLAP_POLICY)
        
        for pkt in flow.packets:
            if pkt.payload_length == 0:
                continue
                
            is_client = (pkt.src_ip == flow.client_ip and pkt.src_port == flow.client_port)
            if is_client:
                client_buffer.add_segment(pkt.seq, pkt.payload)
            else:
                server_buffer.add_segment(pkt.seq, pkt.payload)
                
        client_stream, c_complete = client_buffer.reassemble()
        server_stream, s_complete = server_buffer.reassemble()
        
        total_retransmissions = client_buffer.retransmissions + server_buffer.retransmissions
        total_overlaps = client_buffer.overlaps + server_buffer.overlaps
        total_gaps = len(client_buffer.gaps) + len(server_buffer.gaps)
        
        reassembly_meta = ReassemblyMetadata(
            retransmissions=total_retransmissions,
            overlaps=total_overlaps,
            gaps=total_gaps,
            complete_client_stream=c_complete,
            complete_server_stream=s_complete,
            overlap_policy_used=config.OVERLAP_POLICY.value
        )
        
        duration = 0
        if flow.start_time and flow.end_time:
            duration = int((flow.end_time - flow.start_time).total_seconds() * 1000)
            
        metadata = FlowMetadata(
            flow_id=flow.flow_id,
            evidence_id=evidence_id,
            protocol="TCP",
            client_ip=flow.client_ip or "0.0.0.0",
            client_port=flow.client_port or 0,
            server_ip=flow.server_ip or "0.0.0.0",
            server_port=flow.server_port or 0,
            start_time=flow.start_time,
            end_time=flow.end_time,
            duration_ms=duration,
            packet_count=flow.packet_count,
            client_bytes=flow.client_bytes,
            server_bytes=flow.server_bytes,
            tcp_state=flow.state_machine.state.value,
            termination=FlowTermination(reason=flow.state_machine.termination_reason),
            reassembly=reassembly_meta
        )
        
        session = ReconstructedSession(
            metadata=metadata,
            client_stream=client_stream,
            server_stream=server_stream
        )
        
        self.export(session)
        logger.info("REASSEMBLY_COMPLETED", flow_id=flow.flow_id, retransmissions=total_retransmissions, overlaps=total_overlaps, gaps=total_gaps)
        
        return session
        
    def export(self, session: ReconstructedSession):
        flow_id = session.metadata.flow_id
        
        # Write Metadata JSON
        meta_path = self.sessions_dir / f"{flow_id}.json"
        with open(meta_path, "w") as f:
            f.write(session.metadata.model_dump_json(indent=2))
            
        # Write Binary Streams
        if session.client_stream:
            with open(self.streams_dir / f"{flow_id}-c2s.bin", "wb") as f:
                f.write(session.client_stream)
                
        if session.server_stream:
            with open(self.streams_dir / f"{flow_id}-s2c.bin", "wb") as f:
                f.write(session.server_stream)
