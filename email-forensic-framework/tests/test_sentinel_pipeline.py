"""
GARUDA Sentinel — Automated Pipeline Test Suite (Phases 7, 8, 9, 10, 11, 12)
Tests:
1. Magic byte file signature validation (Classic PCAP, PCAPNG, Invalid bytes).
2. End-to-end forensic processing on real PCAPs (smtp_starttls.pcap, smtp_insecure.pcap).
3. Cryptographic evidence normalization (Phase 8).
4. Deterministic policy evaluation & CRS calculation (Phase 9).
5. AI anomaly score & Evidence confidence separation (Phase 10).
6. CycloneDX CBOM & NIST FIPS 203 PQC readiness export (Phase 11).
7. FastAPI REST upload and query endpoints (Phase 12).
"""

import os
import io
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from sentinel_engine import (
    validate_pcap_signature,
    run_real_forensic_pipeline,
    MAGIC_PCAP_LE,
    MAGIC_PCAP_BE,
    MAGIC_PCAPNG,
)
from server import app

client = TestClient(app)
PCAPS_DIR = Path(__file__).resolve().parent.parent / "pcaps"

def test_pcap_magic_byte_validation():
    """Phase 7: Magic byte verification checks header bytes instead of extension."""
    valid_le = MAGIC_PCAP_LE + b"\x00" * 30
    is_valid, desc = validate_pcap_signature(valid_le)
    assert is_valid is True
    assert "Classic PCAP" in desc

    valid_be = MAGIC_PCAP_BE + b"\x00" * 30
    is_valid, desc = validate_pcap_signature(valid_be)
    assert is_valid is True
    assert "Classic PCAP" in desc

    valid_ng = MAGIC_PCAPNG + b"\x00" * 30
    is_valid, desc = validate_pcap_signature(valid_ng)
    assert is_valid is True
    assert "PCAP-NG" in desc

    invalid = b"FAKE_HEADER_NOT_A_PCAP"
    is_valid, desc = validate_pcap_signature(invalid)
    assert is_valid is False
    assert "Invalid file header" in desc

def test_real_pcap_ingestion_smtp_starttls():
    """Phases 7-11: Full pipeline execution on real capture smtp_starttls.pcap."""
    pcap_file = PCAPS_DIR / "smtp_starttls.pcap"
    assert pcap_file.exists(), "Test fixture smtp_starttls.pcap missing!"

    result = run_real_forensic_pipeline(pcap_file, "smtp_starttls.pcap")
    assert result.status == "completed"
    assert result.packetsCount == 9
    assert result.sessionsCount >= 1
    assert result.durationSec >= 0.0

    # Phase 8: Verify normalized evidence records
    assert len(result.evidenceList) >= 1
    ev = result.evidenceList[0]
    assert ev.classification in ("Observed", "Derived", "External", "Unavailable")
    assert ev.confidence >= 0.0

    # Phase 9: Verify Deterministic Policy findings & CRS
    assert result.overallRisk >= 0
    assert result.overallRisk <= 100
    assert isinstance(result.findings, list)

    # Phase 10: Verify AI Anomaly Score & Evidence Confidence separation
    assert result.aiAnomalyScore >= 0 and result.aiAnomalyScore <= 100
    assert result.evidenceConfidence >= 0 and result.evidenceConfidence <= 100

    # Phase 11: Verify CBOM & PQC readiness
    assert len(result.cbom) >= 1
    assert "status" in result.pqcReadiness
    assert "NIST FIPS 203" in result.pqcReadiness["standard"]

def test_real_pcap_ingestion_smtp_insecure():
    """Phases 8-9: Verifies detection of unencrypted cleartext SMTP."""
    pcap_file = PCAPS_DIR / "smtp_insecure.pcap"
    assert pcap_file.exists(), "Test fixture smtp_insecure.pcap missing!"

    result = run_real_forensic_pipeline(pcap_file, "smtp_insecure.pcap")
    assert result.status == "completed"
    assert result.sessionsCount >= 1

    # Should detect unencrypted cleartext finding
    rule_ids = [f.ruleId for f in result.findings]
    assert "RULE-STARTTLS-MISSING-001" in rule_ids
    assert result.overallRisk >= 35

def test_api_upload_invalid_file_signature():
    """Phase 7: Server rejects uploaded files with invalid magic bytes."""
    corrupted_data = b"NOT_A_REAL_PCAP_STREAM_OF_BYTES"
    response = client.post(
        "/api/pcap/upload",
        files={"file": ("malicious.pcap", corrupted_data, "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Invalid capture file signature" in response.json()["detail"]

def test_api_upload_valid_pcap_and_query_endpoints():
    """Phases 7, 11, 12: Upload real PCAP to FastAPI and verify REST response."""
    pcap_file = PCAPS_DIR / "smtp_starttls.pcap"
    with open(pcap_file, "rb") as f:
        file_bytes = f.read()

    upload_res = client.post(
        "/api/pcap/upload",
        files={"file": ("smtp_starttls.pcap", file_bytes, "application/vnd.tcpdump.pcap")}
    )
    assert upload_res.status_code == 200
    data = upload_res.json()
    assert data["status"] == "completed"
    job_id = data["id"]
    assert job_id.startswith("AN-")
    assert data["packetsCount"] == 9

    # Query /api/analysis/{id}
    analysis_res = client.get(f"/api/analysis/{job_id}")
    assert analysis_res.status_code == 200
    analysis_data = analysis_res.json()
    assert analysis_data["id"] == job_id
    assert analysis_data["overallRisk"] == data["overallRisk"]

    # Query /api/analysis/{id}/evidence
    evidence_res = client.get(f"/api/analysis/{job_id}/evidence")
    assert evidence_res.status_code == 200
    ev_list = evidence_res.json()
    assert len(ev_list) >= 1

    # Query CycloneDX CBOM Export
    cbom_res = client.get("/api/cbom/export")
    assert cbom_res.status_code == 200
    cbom_data = cbom_res.json()
    assert cbom_data["bomFormat"] == "CycloneDX"
    assert cbom_data["specVersion"] == "1.5"
    assert len(cbom_data["components"]) >= 1

    # Query Downloadable Report
    report_res = client.get(f"/api/reports/download/{job_id}")
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert report_data["analysisId"] == job_id
    assert "cryptographicRiskScore" in report_data
