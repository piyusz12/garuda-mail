import typer
from rich.console import Console
from rich.table import Table
import time
import json
from pathlib import Path

from app.config import config
from app.ingestion.pcap_reader import PcapIngestor
from app.flow.flow_manager import FlowManager
from app.reassembly.tcp_reassembler import TCPReassembler
from app.protocol.detector import ProtocolDetector
from app.protocol.smtp.parser import SMTPAnalyzer
from app.protocol.imap.parser import IMAPAnalyzer
from app.protocol.pop3.parser import POP3Analyzer
from app.encryption.transition_detector import EncryptionTransitionDetector
from app.tls.parser import TLSParser
from app.logger import logger

app = typer.Typer()
console = Console()

@app.command()
def ingest(pcap_path: str):
    """Ingest a PCAP file, reconstruct TCP sessions, and perform Phase 2 Protocol Analysis"""
    path = Path(pcap_path)
    if not path.exists():
        console.print(f"[red]Error: PCAP file {pcap_path} not found.[/red]")
        raise typer.Exit(1)
        
    console.print(f"[bold blue]Starting Phase 1 & 2 Analysis: {path.name}[/bold blue]")
    start_time = time.time()
    
    # 1. Ingestion & Flow Management (Phase 1)
    ingestor = PcapIngestor(path)
    flow_manager = FlowManager()
    ingestor.ingest(flow_manager)
    
    # 2. Reassembly (Phase 1)
    reassembler = TCPReassembler()
    
    # 3. Protocol & Encryption Analysis (Phase 2)
    protocol_detector = ProtocolDetector([
        SMTPAnalyzer(),
        IMAPAnalyzer(),
        POP3Analyzer()
    ])
    encryption_detector = EncryptionTransitionDetector()
    
    analysis_dir = config.OUTPUT_DIR / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    
    completed_flows = 0
    protocols_found = {"SMTP": 0, "IMAP": 0, "POP3": 0, "UNKNOWN": 0}
    starttls_detected = 0
    plaintext_auth_detected = 0
    
    for flow_id, flow in flow_manager.flows.items():
        # Phase 1 Reassembly
        session = reassembler.finalize(flow, ingestor.evidence.id)
        
        # Phase 2 Protocol Analysis
        if session.client_stream or session.server_stream:
            analysis = protocol_detector.detect(session)
            
            # Phase 2 Encryption Transition Detection
            encryption_detector.detect(session, analysis)
            
            # Phase 3 TLS Metadata Parsing
            if analysis.encryption.tls_detected and analysis.encryption.boundary:
                boundary = analysis.encryption.boundary
                if boundary.direction == "C2S":
                    tls_parser = TLSParser(session.client_stream, boundary.offset)
                else:
                    tls_parser = TLSParser(session.server_stream, boundary.offset)
                analysis.tls_metadata = tls_parser.parse()
                
            # Track stats
            protocols_found[analysis.protocol.name] = protocols_found.get(analysis.protocol.name, 0) + 1
            if analysis.encryption.tls_detected:
                starttls_detected += 1
            if any(ind.type == "PLAINTEXT_AUTHENTICATION" for ind in analysis.security_indicators):
                plaintext_auth_detected += 1
            
            # Export Phase 2 JSON
            analysis_path = analysis_dir / f"{flow.flow_id}.json"
            with open(analysis_path, "w") as f:
                f.write(analysis.model_dump_json(indent=2))
        
        completed_flows += 1
        
    end_time = time.time()
    duration = end_time - start_time
    
    # Report
    table = Table(title="Phase 1 & Phase 2 Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Evidence ID", ingestor.evidence.id)
    table.add_row("Packets", str(ingestor.total_packets))
    table.add_row("TCP Flows", str(len(flow_manager.flows)))
    table.add_row("SMTP Sessions", str(protocols_found.get("SMTP", 0)))
    table.add_row("IMAP Sessions", str(protocols_found.get("IMAP", 0)))
    table.add_row("POP3 Sessions", str(protocols_found.get("POP3", 0)))
    table.add_row("Unknown Sessions", str(protocols_found.get("UNKNOWN", 0)))
    table.add_row("TLS Detected", str(starttls_detected))
    table.add_row("Plaintext Auth Alerts", f"[red]{plaintext_auth_detected}[/red]")
    
    console.print(table)
    console.print(f"[green]Processing Time: {duration:.2f} sec[/green]")

@app.command()
def stats(pcap_path: str):
    """Quick stats without full export"""
    ingest(pcap_path)

if __name__ == "__main__":
    app()
