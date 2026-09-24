import hashlib
from pathlib import Path
from scapy.utils import PcapReader
from datetime import datetime
from uuid import uuid4

from app.models.session import Evidence
from app.ingestion.packet_normalizer import PacketNormalizer
from app.logger import logger

class PcapIngestor:
    def __init__(self, pcap_path: Path | str):
        self.pcap_path = Path(pcap_path)
        self.evidence: Evidence | None = None
        self.total_packets = 0
        self.tcp_packets = 0

    def calculate_sha256(self) -> str:
        sha256_hash = hashlib.sha256()
        with open(self.pcap_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    def ingest(self, flow_manager):
        """Streams PCAP, calculates hash, normalizes packets, and feeds flow manager"""
        logger.info("PCAP_LOADED", filename=self.pcap_path.name)
        
        sha256 = self.calculate_sha256()
        file_size = self.pcap_path.stat().st_size
        
        self.evidence = Evidence(
            id=f"EV-{datetime.now().year}-{uuid4().hex[:5].upper()}",
            filename=self.pcap_path.name,
            sha256=sha256,
            size_bytes=file_size,
            ingested_at=datetime.now()
        )
        
        logger.info("EVIDENCE_CREATED", evidence_id=self.evidence.id, sha256=sha256, size=file_size)
        
        # Stream packets
        with PcapReader(str(self.pcap_path)) as pcap_reader:
            for pkt in pcap_reader:
                self.total_packets += 1
                record = PacketNormalizer.normalize(pkt)
                
                if record:
                    self.tcp_packets += 1
                    flow_manager.process_packet(record)
                    
        logger.info("INGESTION_COMPLETED", total_packets=self.total_packets, tcp_packets=self.tcp_packets)
