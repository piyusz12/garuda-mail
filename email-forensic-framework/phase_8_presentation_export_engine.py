import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

try:
    from fastapi import FastAPI, HTTPException
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    print("Warning: FastAPI not installed. Dashboard API will not run.")

# --- NORMALIZED DATA MODELS ---

@dataclass
class NormalizedSession:
    """
    The ultimate Phase 8 output object. It contains the complete forensic chain
    from TCP stream to AI explanation and Risk Fusion.
    """
    analysis_id: str
    session_id: str
    timestamp: str
    
    # Phase 1 & 2
    network: Dict[str, Any]
    protocol: str
    
    # Phase 3
    tls_version: str
    cipher_suite: str
    ja4_fingerprint: str
    certificate_sha256: Optional[str]
    
    # Phase 4
    deterministic_findings: List[Dict[str, Any]]
    
    # Phase 6
    ai_anomaly_score: float
    ai_classification: str
    ai_explanation: Dict[str, Any]
    
    # Phase 7
    risk_score: float
    risk_category: str
    risk_confidence: float
    asset_context: Dict[str, Any]
    
    # Provenance
    provenance: Dict[str, str]


class CBOMGenerator:
    """
    Generates a Cryptographic Bill of Materials (CBOM) by scanning
    all normalized sessions and aggregating cryptographic assets.
    """
    def __init__(self, version: str = "1.0"):
        self.version = version
        self.certificates: Dict[str, Dict[str, Any]] = {}
        self.ciphers: Dict[str, Dict[str, Any]] = {}
        
    def ingest_session(self, session: NormalizedSession):
        # 1. Aggregate Certificates
        if session.certificate_sha256:
            cert_id = session.certificate_sha256
            if cert_id not in self.certificates:
                self.certificates[cert_id] = {
                    "asset_id": f"CERT-{cert_id[:8]}",
                    "type": "certificate",
                    "sha256": cert_id,
                    "associated_assets": set(),
                    "associated_sessions": set(),
                    "tls_versions_observed": set()
                }
            
            self.certificates[cert_id]["associated_assets"].add(session.asset_context.get("asset_id", "unknown"))
            self.certificates[cert_id]["associated_sessions"].add(session.session_id)
            self.certificates[cert_id]["tls_versions_observed"].add(session.tls_version)

        # 2. Aggregate Cipher Suites
        if session.cipher_suite:
            cipher_id = session.cipher_suite
            if cipher_id not in self.ciphers:
                self.ciphers[cipher_id] = {
                    "asset_id": f"CIPHER-{hashlib.md5(cipher_id.encode()).hexdigest()[:8]}",
                    "type": "cipher_suite",
                    "name": cipher_id,
                    "associated_sessions": set(),
                    "findings": set()
                }
            self.ciphers[cipher_id]["associated_sessions"].add(session.session_id)
            
            # Map deterministic findings to this cipher if relevant
            for finding in session.deterministic_findings:
                if finding.get("category") == "PROTOCOL" or finding.get("category") == "CIPHER":
                    self.ciphers[cipher_id]["findings"].add(finding.get("rule_id"))

    def generate_cbom(self) -> Dict[str, Any]:
        """Returns the fully aggregated CBOM in a structured JSON schema."""
        
        # Convert sets to lists for JSON serialization
        formatted_certs = []
        for cert in self.certificates.values():
            cert["associated_assets"] = list(cert["associated_assets"])
            cert["associated_sessions"] = list(cert["associated_sessions"])
            cert["tls_versions_observed"] = list(cert["tls_versions_observed"])
            formatted_certs.append(cert)
            
        formatted_ciphers = []
        for cipher in self.ciphers.values():
            cipher["associated_sessions"] = list(cipher["associated_sessions"])
            cipher["findings"] = list(cipher["findings"])
            formatted_ciphers.append(cipher)

        return {
            "cbom_version": self.version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_certificates": len(formatted_certs),
                "total_ciphers": len(formatted_ciphers)
            },
            "assets": {
                "certificates": formatted_certs,
                "cipher_suites": formatted_ciphers
            }
        }


class SIEMExporter:
    """
    Transforms Risk Fusion results into flattened, SIEM-friendly JSON events 
    for platforms like Splunk, Elastic, or Microsoft Sentinel.
    """
    @staticmethod
    def format_event(session: NormalizedSession) -> Dict[str, Any]:
        # Only export actionable/anomalous events to reduce SIEM noise
        if session.risk_category in ["LOW", "INFO"] and session.ai_classification == "NORMAL":
            return {}

        return {
            "timestamp": session.timestamp,
            "event_type": "crypto_security_finding",
            "severity": session.risk_category.lower(),
            "session_id": session.session_id,
            "src_ip": session.network.get("src_ip"),
            "dst_ip": session.network.get("dst_ip"),
            "protocol": session.protocol,
            "tls_version": session.tls_version,
            "affected_asset": session.asset_context.get("asset_id"),
            "risk_score": session.risk_score,
            "ai_anomaly_score": session.ai_anomaly_score,
            "primary_findings": [f.get("rule_id") for f in session.deterministic_findings],
            "ja4": session.ja4_fingerprint,
            "remediation_priority": "immediate" if session.risk_category == "CRITICAL" else "planned",
            "analysis_id": session.analysis_id
        }

class ReportBuilder:
    """
    Constructs the Executive Summary and High-Level JSON report.
    (In a full deployment, this feeds into a PDF/HTML generator like ReportLab).
    """
    @staticmethod
    def generate_executive_summary(sessions: List[NormalizedSession]) -> Dict[str, Any]:
        critical = sum(1 for s in sessions if s.risk_category == "CRITICAL")
        high = sum(1 for s in sessions if s.risk_category == "HIGH")
        ai_anomalies = sum(1 for s in sessions if s.ai_classification != "NORMAL")
        starttls_failures = sum(1 for s in sessions if any(f.get("rule_id") == "STARTTLS_FAILURE" for f in s.deterministic_findings))

        return {
            "title": "AI-Assisted Network Forensic Cryptographic Assessment",
            "date": datetime.now(timezone.utc).isoformat(),
            "scope": {
                "sessions_analyzed": len(sessions)
            },
            "posture": {
                "critical_findings": critical,
                "high_findings": high,
                "ai_behavioral_anomalies": ai_anomalies,
                "starttls_failures": starttls_failures
            },
            "conclusion": f"Analysis complete. {critical} critical sessions require immediate remediation."
        }


if HAS_FASTAPI:
    app = FastAPI(
        title="Phase 8 Dashboard API",
        description="Serves cryptographic posture, CBOM, and risk data to the frontend.",
        version="1.0"
    )

    # In-memory datastore for prototype
    DB: Dict[str, Any] = {
        "sessions": [],
        "cbom": {},
        "posture": {}
    }

    @app.get("/api/posture")
    def get_posture():
        """Returns the high-level enterprise risk posture."""
        return DB["posture"]

    @app.get("/api/cbom")
    def get_cbom():
        """Returns the Cryptographic Bill of Materials."""
        return DB["cbom"]

    @app.get("/api/sessions")
    def list_sessions(risk_category: Optional[str] = None):
        """Returns a list of sessions, optionally filtered by risk."""
        if risk_category:
            filtered = [s for s in DB["sessions"] if s["risk_category"] == risk_category.upper()]
            return {"data": filtered, "metadata": {"total": len(filtered)}}
        return {"data": DB["sessions"], "metadata": {"total": len(DB["sessions"])}}

    @app.get("/api/sessions/{session_id}")
    def get_session(session_id: str):
        """Deep drill-down for a specific session."""
        for s in DB["sessions"]:
            if s["session_id"] == session_id:
                return s
        raise HTTPException(status_code=404, detail="Session not found")


def build_mock_session() -> NormalizedSession:
    """Helper to generate a mock Phase 7 output for demonstration."""
    return NormalizedSession(
        analysis_id="AN-2026-0001",
        session_id="FLOW-00124",
        timestamp=datetime.now(timezone.utc).isoformat(),
        network={"src_ip": "10.0.0.15", "dst_ip": "203.0.113.20"},
        protocol="SMTP",
        tls_version="TLS 1.1",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        ja4_fingerprint="t11d150800_002f_a54b321",
        certificate_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        deterministic_findings=[
            {"rule_id": "TLS_DEPRECATED", "category": "PROTOCOL", "severity": "HIGH"},
            {"rule_id": "PLAINTEXT_AUTH", "category": "AUTH", "severity": "CRITICAL"}
        ],
        ai_anomaly_score=0.88,
        ai_classification="ANOMALOUS",
        ai_explanation={"top_features": ["JA4 rarity", "IAT variance"]},
        risk_score=91.4,
        risk_category="CRITICAL",
        risk_confidence=0.96,
        asset_context={"asset_id": "smtp.enterprise.com", "role": "MTA", "exposure": "INTERNET"},
        provenance={"pcap_hash": "a1b2c3d4", "risk_policy": "enterprise-default-v1.2"}
    )

if __name__ == "__main__":
    print("--- PHASE 8: PRESENTATION & EXPORT ENGINE INITIALIZING ---\n")
    
    # 1. Simulate data ingestion from Phase 7
    mock_sessions = [build_mock_session()]
    
    # 2. Generate CBOM
    cbom_gen = CBOMGenerator()
    for s in mock_sessions:
        cbom_gen.ingest_session(s)
    
    cbom_data = cbom_gen.generate_cbom()
    print(">> CBOM GENERATED:")
    print(json.dumps(cbom_data, indent=2))
    
    # 3. Generate SIEM Event Export
    print("\n>> SIEM EXPORT EVENT:")
    siem_event = SIEMExporter.format_event(mock_sessions[0])
    print(json.dumps(siem_event, indent=2))
    
    # 4. Generate Executive Summary Report
    print("\n>> EXECUTIVE REPORT:")
    report = ReportBuilder.generate_executive_summary(mock_sessions)
    print(json.dumps(report, indent=2))
    
    # 5. Populate Dashboard Database & Run (if FastAPI is available)
    if HAS_FASTAPI:
        print("\n>> POPULATING API DATABASE AND STARTING SERVER...")
        DB["sessions"] = [asdict(s) for s in mock_sessions]
        DB["cbom"] = cbom_data
        DB["posture"] = report["posture"]
        
        # Uncomment below to actually run the server locally
        # uvicorn.run(app, host="127.0.0.1", port=8000)
        print(">> FastAPI application ready (uncomment uvicorn.run to serve).")