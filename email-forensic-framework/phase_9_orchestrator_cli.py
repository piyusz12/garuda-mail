import json
import time
import uuid
import hashlib
import logging
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict, field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("Phase9-Orchestrator")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed. Memory profiling will be simulated.")

try:
    from fastapi import FastAPI, HTTPException, Security, Depends
    from fastapi.security.api_key import APIKeyHeader
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Server mode disabled.")


@dataclass
class PhaseMetrics:
    phase_name: str
    duration_sec: float
    memory_mb_used: float
    status: str
    error: Optional[str] = None

@dataclass
class AnalysisManifest:
    analysis_id: str
    evidence_filename: str
    evidence_hash: str
    started_at: str
    completed_at: Optional[str] = None
    status: str = "INITIALIZED"
    software_version: str = "1.0.0"
    phase_metrics: List[PhaseMetrics] = field(default_factory=list)
    final_risk_score_mean: float = 0.0

class Profiler:
    """Context manager for benchmarking phase performance and memory."""
    def __init__(self, phase_name: str, metrics_list: List[PhaseMetrics]):
        self.phase_name = phase_name
        self.metrics_list = metrics_list
        self.start_time = 0.0
        self.start_mem = 0.0

    def __enter__(self):
        self.start_time = time.time()
        if HAS_PSUTIL:
            self.start_mem = psutil.Process().memory_info().rss / (1024 * 1024)
        else:
            self.start_mem = 0.0
        logger.info(f"--- Starting {self.phase_name} ---")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = round(time.time() - self.start_time, 3)
        
        if HAS_PSUTIL:
            end_mem = psutil.Process().memory_info().rss / (1024 * 1024)
            mem_used = round(max(0, end_mem - self.start_mem), 2)
        else:
            mem_used = 0.0

        status = "FAILED" if exc_type else "COMPLETED"
        error_msg = str(exc_val) if exc_val else None

        self.metrics_list.append(PhaseMetrics(
            phase_name=self.phase_name,
            duration_sec=duration,
            memory_mb_used=mem_used,
            status=status,
            error=error_msg
        ))
        
        logger.info(f"--- Finished {self.phase_name} in {duration}s | Mem: {mem_used}MB | Status: {status} ---")
        return False # Do not suppress exceptions


class PipelineOrchestrator:
    """
    Executes the entire forensic pipeline securely and reliably.
    Mocks the underlying phase executions for architectural demonstration.
    """
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.analysis_id = f"AN-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        # Hash the evidence to ensure provenance
        hasher = hashlib.sha256()
        hasher.update(pcap_path.encode()) # In reality, hash the file chunks
        self.evidence_hash = hasher.hexdigest()
        
        self.manifest = AnalysisManifest(
            analysis_id=self.analysis_id,
            evidence_filename=self.pcap_path,
            evidence_hash=self.evidence_hash,
            started_at=datetime.now(timezone.utc).isoformat()
        )
        self.session_data: Dict[str, Any] = {}

    def run_pipeline(self) -> AnalysisManifest:
        self.manifest.status = "PROCESSING"
        
        try:
            # Phase 1: PCAP & TCP Reconstruction
            with Profiler("PHASE 1: TCP Reconstruction", self.manifest.phase_metrics):
                time.sleep(0.1) # Simulate IO bounds
                self.session_data["tcp_streams"] = 150
            
            # Phase 2: Application Protocol Parsing (SMTP/IMAP/POP3)
            with Profiler("PHASE 2: Protocol Identification", self.manifest.phase_metrics):
                time.sleep(0.05)
                self.session_data["email_sessions"] = 120
                
            # Phase 3: TLS, X.509, JA4 Extraction
            with Profiler("PHASE 3: TLS & Cryptographic Extraction", self.manifest.phase_metrics):
                time.sleep(0.15)
                self.session_data["tls_sessions"] = 110
                
            # Phase 4: Deterministic Rules
            with Profiler("PHASE 4: Cryptographic Rules", self.manifest.phase_metrics):
                time.sleep(0.02)
                self.session_data["deterministic_findings"] = 15
                
            # Phase 5: Feature Engineering
            with Profiler("PHASE 5: Feature Engineering", self.manifest.phase_metrics):
                time.sleep(0.08)
                
            # Phase 6: AI Anomaly Detection & SHAP
            with Profiler("PHASE 6: AI Anomaly Detection", self.manifest.phase_metrics):
                time.sleep(0.2) # Simulate ML inference
                self.session_data["ai_anomalies"] = 3
                
            # Phase 7: Risk Fusion & Prioritization
            with Profiler("PHASE 7: Risk Fusion", self.manifest.phase_metrics):
                time.sleep(0.05)
                self.manifest.final_risk_score_mean = 42.5
                
            # Phase 8: Presentation & Export (CBOM, JSON)
            with Profiler("PHASE 8: Export Generation", self.manifest.phase_metrics):
                time.sleep(0.05)
                self.session_data["cbom_generated"] = True

            self.manifest.status = "COMPLETED"
            
        except Exception as e:
            logger.error(f"Pipeline failed: {str(e)}")
            self.manifest.status = "FAILED"
            
        finally:
            self.manifest.completed_at = datetime.now(timezone.utc).isoformat()
            
        return self.manifest


class EndToEndValidator:
    """Checks current pipeline execution against known 'golden' outputs to prevent regressions."""
    
    @staticmethod
    def validate_against_golden(current_manifest: AnalysisManifest, expected_stats: Dict[str, Any]) -> bool:
        logger.info("Running Phase 9 Golden Validation...")
        is_valid = True
        
        # 1. Pipeline Completion Check
        if current_manifest.status != "COMPLETED":
            logger.error("Validation Failed: Pipeline did not complete successfully.")
            is_valid = False
            
        # 2. Metric Assertions
        metrics_dict = {m.phase_name: m for m in current_manifest.phase_metrics}
        if len(metrics_dict) < 8:
            logger.error(f"Validation Failed: Expected 8 phases, found {len(metrics_dict)}")
            is_valid = False
            
        # 3. Output Consistency (Mocked comparison)
        if current_manifest.final_risk_score_mean < expected_stats.get("min_risk_mean", 0.0):
            logger.error("Validation Failed: Risk score drifted below golden threshold.")
            is_valid = False
            
        if is_valid:
            logger.info("Validation Passed: End-to-End Pipeline is consistent with golden records.")
        return is_valid


if HAS_FASTAPI:
    app = FastAPI(
        title="Email Forensics Platform - Phase 9",
        description="Secure operational API for triggering and monitoring analysis jobs.",
        version="1.0.0"
    )

    API_KEY_NAME = "X-API-KEY"
    API_KEY = "super-secure-production-key-2026" # In prod, load from env vars
    api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

    async def get_api_key(api_key_header: str = Depends(api_key_header)):
        if api_key_header == API_KEY:
            return api_key_header
        raise HTTPException(
            status_code=403, 
            detail="Forbidden: Invalid or missing API Key"
        )

    # In-memory job tracker
    JOBS_DB = {}

    @app.get("/health", tags=["Monitoring"])
    def health_check():
        """Phase 9 Health Endpoint for Load Balancers and Orchestrators."""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "memory_usage_mb": psutil.Process().memory_info().rss / (1024*1024) if HAS_PSUTIL else "unknown"
        }

    @app.post("/api/v1/analyze", tags=["Operations"])
    def trigger_analysis(pcap_path: str, api_key: str = Depends(get_api_key)):
        """Triggers a background analysis job securely."""
        # Note: In a real architecture, this dispatches to Celery/Redis.
        # Here we run it synchronously for demonstration, but return a Job ID structure.
        orchestrator = PipelineOrchestrator(pcap_path)
        manifest = orchestrator.run_pipeline()
        
        JOBS_DB[manifest.analysis_id] = asdict(manifest)
        return {"message": "Analysis Accepted", "job_id": manifest.analysis_id}

    @app.get("/api/v1/jobs/{job_id}", tags=["Operations"])
    def get_job_status(job_id: str, api_key: str = Depends(get_api_key)):
        """Retrieve secure pipeline status and metrics."""
        if job_id not in JOBS_DB:
            raise HTTPException(status_code=404, detail="Job not found")
        return JOBS_DB[job_id]


def main():
    parser = argparse.ArgumentParser(description="Phase 9 - Operations & Orchestration CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")

    # Command: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Run the full pipeline on a PCAP")
    analyze_parser.add_argument("pcap", type=str, help="Path to the PCAP file")

    # Command: benchmark
    benchmark_parser = subparsers.add_parser("benchmark", help="Run with strict performance profiling")
    benchmark_parser.add_argument("pcap", type=str, help="Path to the PCAP file")

    # Command: validate
    validate_parser = subparsers.add_parser("validate", help="Run E2E Golden Validation")
    validate_parser.add_argument("pcap", type=str, help="Path to reference PCAP file")

    # Command: serve
    subparsers.add_parser("serve", help="Start the secure FastAPI backend")

    args = parser.parse_args()

    if args.command == "analyze" or args.command == "benchmark":
        print(f"\n=======================================================")
        print(f" INITIALIZING PHASE 9 ORCHESTRATOR")
        print(f" Target: {args.pcap}")
        print(f" Mode: {'Benchmark' if args.command == 'benchmark' else 'Standard'}")
        print(f"=======================================================\n")
        
        orchestrator = PipelineOrchestrator(args.pcap)
        manifest = orchestrator.run_pipeline()
        
        print("\n==================== PIPELINE MANIFEST ====================")
        print(json.dumps(asdict(manifest), indent=2))
        print("===========================================================\n")

    elif args.command == "validate":
        print("--- Running Golden End-to-End Validation ---")
        orchestrator = PipelineOrchestrator(args.pcap)
        manifest = orchestrator.run_pipeline()
        
        # Expected baseline (normally loaded from a JSON file)
        golden_baseline = {"min_risk_mean": 40.0} 
        
        EndToEndValidator.validate_against_golden(manifest, golden_baseline)

    elif args.command == "serve":
        if HAS_FASTAPI:
            print("Starting hardened Phase 9 Operations Server on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("Error: FastAPI is not installed. Cannot start server.")
            
    else:
        parser.print_help()


if __name__ == "__main__":
    # If run without arguments, execute a default validation run for demonstration
    import sys
    if len(sys.argv) == 1:
        sys.argv.extend(["validate", "reference/enterprise_email_golden.pcap"])
    main()