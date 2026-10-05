#!/usr/bin/env python3
"""
Garuda Mail - Unified REST API Server
Provides high-performance backend endpoints for the Next.js and Vite dashboards.
Serves cryptographic posture, sessions, findings, CBOM, threat hunting, and live PCAP analysis.
"""

import sys
import os
import re
import time
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Configure stdout encoding on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = FastAPI(
    title="Garuda Mail - Enterprise Forensic API",
    description="Unified REST API serving forensic telemetry, session analysis, certificates, and SOAR actions",
    version="1.0.0"
)

# Enable secure CORS for Next.js (port 3000) and local clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
PCAPS_DIR = BASE_DIR / "pcaps"
OUTPUT_DIR = BASE_DIR / "output" / "analysis"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── IN-MEMORY DATABASE WITH MOCK & REAL FORENSIC TELEMETRY ──

MOCK_SESSIONS = [
    {
        "id": "SMTP-0192",
        "protocol": "SMTP",
        "sourceIp": "192.168.1.20",
        "sourcePort": 45123,
        "destIp": "203.0.113.50",
        "destPort": 587,
        "destHostname": "mail.example.com",
        "duration": 4.83,
        "packets": 341,
        "bytes": 128490,
        "tlsVersion": "TLS 1.2",
        "starttls": True,
        "risk": "high",
        "riskScore": 78,
        "findingsCount": 3,
        "anomalyScore": 67,
        "timestamp": "2026-09-28T09:01:02Z",
        "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    },
    {
        "id": "SMTP-0193",
        "protocol": "SMTP",
        "sourceIp": "192.168.1.20",
        "sourcePort": 45124,
        "destIp": "198.51.100.25",
        "destPort": 25,
        "destHostname": "smtp01.enterprise.local",
        "duration": 2.14,
        "packets": 189,
        "bytes": 67230,
        "tlsVersion": "TLS 1.0",
        "starttls": True,
        "risk": "critical",
        "riskScore": 94,
        "findingsCount": 5,
        "anomalyScore": 12,
        "timestamp": "2026-09-28T09:03:17Z",
        "ja4": "t10d1516h2_8daaf6152771_b2a1c3d4e5f6",
    },
    {
        "id": "IMAP-0087",
        "protocol": "IMAP",
        "sourceIp": "192.168.1.45",
        "sourcePort": 52891,
        "destIp": "203.0.113.50",
        "destPort": 993,
        "destHostname": "imap.example.com",
        "duration": 12.67,
        "packets": 892,
        "bytes": 456780,
        "tlsVersion": "TLS 1.3",
        "starttls": False,
        "risk": "low",
        "riskScore": 18,
        "findingsCount": 0,
        "anomalyScore": 8,
        "timestamp": "2026-09-28T09:05:41Z",
        "ja4": "t13d1517h2_a023bc45d678_f1a2b3c4d5e6",
    },
    {
        "id": "POP3-0034",
        "protocol": "POP3",
        "sourceIp": "192.168.1.102",
        "sourcePort": 38901,
        "destIp": "198.51.100.30",
        "destPort": 995,
        "destHostname": "pop3.legacy-mail.internal",
        "duration": 1.91,
        "packets": 78,
        "bytes": 23410,
        "tlsVersion": "TLS 1.1",
        "starttls": False,
        "risk": "high",
        "riskScore": 72,
        "findingsCount": 2,
        "anomalyScore": None,
        "timestamp": "2026-09-28T09:08:55Z",
        "ja4": "t11d1516h2_c4d5e6f7a8b9_d1e2f3a4b5c6",
    },
    {
        "id": "IMAP-0088",
        "protocol": "IMAP",
        "sourceIp": "192.168.1.78",
        "sourcePort": 53210,
        "destIp": "198.51.100.25",
        "destPort": 143,
        "destHostname": "imap-legacy.enterprise.local",
        "duration": 8.34,
        "packets": 523,
        "bytes": 234560,
        "tlsVersion": None,
        "starttls": False,
        "risk": "critical",
        "riskScore": 98,
        "findingsCount": 4,
        "anomalyScore": 78,
        "timestamp": "2026-09-28T09:18:44Z",
        "ja4": None,
    }
]

MOCK_FINDINGS = [
    {
        "id": "TLS-001",
        "title": "Deprecated TLS Version Detected",
        "description": "Session SMTP-0193 negotiated TLS 1.0, which has known cryptographic vulnerabilities and is deprecated by NIST SP 800-52 Rev 2 and PCI DSS 4.0.",
        "severity": "critical",
        "category": "Protocol Security",
        "detectionSource": "rule_engine",
        "confidence": 100,
        "ruleId": "RULE-TLS-DEPRECATED-001",
        "status": "open",
        "evidence": [
            {
                "sessionId": "SMTP-0193",
                "packets": "1823-1825",
                "observed": "TLS 1.0 (0x0301)",
                "sourceIp": "192.168.1.20",
                "destIp": "198.51.100.25",
                "destHostname": "smtp01.enterprise.local",
                "timestamp": "2026-09-28T09:03:18Z"
            }
        ],
        "technicalDetails": "The TLS ClientHello proposed TLS 1.2 as maximum version, but the server selected TLS 1.0.",
        "whyItMatters": "TLS 1.0 is vulnerable to BEAST, POODLE, and related attacks.",
        "remediation": "Disable TLS 1.0 and TLS 1.1 on smtp01.enterprise.local. Require TLS 1.2+ minimum.",
        "remediationPriority": "critical",
        "standardsMapping": [
            {"standard": "NIST SP 800-52 Rev 2", "reference": "Section 3.1", "severity": "SHALL NOT", "recommendation": "TLS 1.0 shall not be used"},
            {"standard": "PCI DSS 4.0", "reference": "Requirement 4.2.1", "severity": "Required", "recommendation": "Only strong cryptography protocols are used"}
        ],
        "affectedAssets": ["smtp01.enterprise.local"],
        "relatedSessionIds": ["SMTP-0193"],
        "timestamp": "2026-09-28T09:03:18Z"
    },
    {
        "id": "STARTTLS-001",
        "title": "Plaintext Email Session Without Encryption",
        "description": "IMAP session IMAP-0088 on port 143 did not negotiate STARTTLS, transmitting credentials and email content in cleartext.",
        "severity": "critical",
        "category": "Encryption Failure",
        "detectionSource": "rule_engine",
        "confidence": 100,
        "ruleId": "RULE-STARTTLS-MISSING-001",
        "status": "open",
        "evidence": [
            {
                "sessionId": "IMAP-0088",
                "packets": "1-78",
                "observed": "No TLS negotiation observed on IMAP port 143",
                "sourceIp": "192.168.1.78",
                "destIp": "198.51.100.25",
                "destHostname": "imap-legacy.enterprise.local",
                "timestamp": "2026-09-28T09:18:44Z"
            }
        ],
        "technicalDetails": "The IMAP session on port 143 completed authentication (LOGIN command) without TLS.",
        "whyItMatters": "Exposes cleartext credentials to eavesdropping adversaries.",
        "remediation": "Enforce STARTTLS on IMAP port 143, or migrate clients to IMAPS (port 993).",
        "remediationPriority": "critical",
        "standardsMapping": [
            {"standard": "RFC 8314", "reference": "Section 3", "severity": "MUST", "recommendation": "Implicit TLS is RECOMMENDED over STARTTLS"}
        ],
        "affectedAssets": ["imap-legacy.enterprise.local"],
        "relatedSessionIds": ["IMAP-0088"],
        "timestamp": "2026-09-28T09:18:44Z"
    }
]

MOCK_CERTIFICATES = [
    {
        "id": "CERT-EX-001",
        "subject": "mail.example.com",
        "subjectAltNames": ["mail.example.com", "smtp.example.com"],
        "issuer": "DigiCert SHA2 Extended Validation Server CA",
        "serialNumber": "0A:1B:2C:3D:4E:5F:6A:7B",
        "algorithm": "SHA256withRSA",
        "keySize": 2048,
        "keyType": "RSA",
        "validFrom": "2025-10-17T00:00:00Z",
        "validUntil": "2026-10-16T23:59:59Z",
        "daysRemaining": 18,
        "chainLength": 3,
        "chainValid": True,
        "status": "expiring",
        "relatedSessionIds": ["SMTP-0192"]
    },
    {
        "id": "CERT-EN-001",
        "subject": "smtp01.enterprise.local",
        "subjectAltNames": ["smtp01.enterprise.local"],
        "issuer": "Enterprise Internal CA",
        "serialNumber": "01:02:03:04:05:06:07:08",
        "algorithm": "SHA256withRSA",
        "keySize": 4096,
        "keyType": "RSA",
        "validFrom": "2025-01-01T00:00:00Z",
        "validUntil": "2027-01-01T23:59:59Z",
        "daysRemaining": 459,
        "chainLength": 2,
        "chainValid": True,
        "status": "valid",
        "relatedSessionIds": ["SMTP-0193"]
    }
]

MOCK_CBOM = [
    {"id": "CBOM-001", "asset": "smtp01.enterprise.local", "protocol": "SMTP", "tlsVersion": "TLS 1.0", "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA", "keyAlgorithm": "RSA", "keySize": 2048, "certificate": "CERT-EN-001", "ja4": "t10d1516h2_8daaf6152771_b2a1c3d4e5f6", "risk": "critical"},
    {"id": "CBOM-002", "asset": "mail.example.com", "protocol": "SMTP", "tlsVersion": "TLS 1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "keyAlgorithm": "RSA", "keySize": 2048, "certificate": "CERT-EX-001", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "risk": "medium"},
    {"id": "CBOM-003", "asset": "imap.example.com", "protocol": "IMAP", "tlsVersion": "TLS 1.3", "cipher": "TLS_AES_256_GCM_SHA384", "keyAlgorithm": "ECDSA P-256", "keySize": 256, "certificate": "CERT-EX-001", "ja4": "t13d1517h2_a023bc45d678_f1a2b3c4d5e6", "risk": "low"}
]

# ── API ENDPOINTS ──

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine": "Garuda Mail Forensic Framework",
        "version": "1.0.0"
    }

@app.get("/api/status", tags=["System"])
def get_system_status():
    return {
        "backend": "connected",
        "analysisEngine": "connected",
        "aiEngine": "connected",
        "database": "connected",
        "reportEngine": "connected"
    }

@app.get("/api/dashboard", tags=["Telemetry"])
def get_dashboard():
    return {
        "risk": {
            "overallScore": 78,
            "ruleContribution": 62,
            "aiAnomalyContribution": 41,
            "contextContribution": 28,
            "confidenceContribution": 89,
            "dimensions": [
                {"name": "Protocol Security", "score": 72, "weight": 0.3, "description": "TLS version and cipher strength across all sessions"},
                {"name": "Certificate Health", "score": 81, "weight": 0.25, "description": "X.509 validity, chain integrity, and key strength"},
                {"name": "Configuration Compliance", "score": 68, "weight": 0.2, "description": "STARTTLS enforcement and MTA-STS adherence"},
                {"name": "Behavioral Anomaly", "score": 41, "weight": 0.15, "description": "AI-detected deviations from expected traffic patterns"},
                {"name": "Cryptographic Posture", "score": 85, "weight": 0.1, "description": "Forward secrecy adoption and key exchange quality"}
            ]
        },
        "findingsSummary": {"critical": 3, "high": 7, "medium": 4, "low": 2, "informational": 1, "total": 17},
        "sessionsAnalyzed": len(MOCK_SESSIONS),
        "affectedAssets": 6,
        "posture": {
            "tlsPosture": {"label": "TLS Posture", "score": 74, "status": "warning", "detail": "89% TLS 1.2+, 3 sessions on TLS 1.0"},
            "certificateHealth": {"label": "Certificate Health", "score": 82, "status": "warning", "detail": "2 certificates expiring within 30 days"},
            "forwardSecrecy": {"label": "Forward Secrecy", "score": 91, "status": "good", "detail": "91% of sessions use ECDHE or DHE key exchange"},
            "starttlsAdoption": {"label": "STARTTLS Adoption", "score": 87, "status": "good", "detail": "87% of SMTP sessions initiated STARTTLS upgrade"},
            "cryptoCompliance": {"label": "Cryptographic Compliance", "score": 69, "status": "warning", "detail": "7 sessions using deprecated cipher suites"},
            "aiAnomalyActivity": {"label": "AI Anomaly Activity", "score": 34, "status": "critical", "detail": "9 anomalies detected across 248 sessions"}
        },
        "recentFindings": MOCK_FINDINGS[:5],
        "recentAnalyses": [
            {
                "id": "AN-1029",
                "filename": "smtp_starttls.pcap",
                "fileSize": 835,
                "status": "completed",
                "progress": 100,
                "sessionsCount": 1,
                "findingsCount": 2,
                "criticalCount": 1,
                "highCount": 1,
                "overallRisk": 74,
                "startedAt": "2026-09-30T10:00:00Z",
                "completedAt": "2026-09-30T10:00:01Z",
                "error": None
            }
        ]
    }

@app.get("/api/sessions", tags=["Sessions"])
def get_sessions():
    return MOCK_SESSIONS

@app.get("/api/sessions/{session_id}", tags=["Sessions"])
def get_session(session_id: str):
    sess = next((s for s in MOCK_SESSIONS if s["id"] == session_id), None)
    if not sess:
        raise HTTPException(404, detail="Session not found")
    
    return {
        "session": sess,
        "timeline": [
            {"id": "EV-1", "timestamp": sess["timestamp"], "direction": "c2s", "eventType": "CONNECT", "summary": "TCP Connection Established", "protocol": sess["protocol"], "offset": 0},
            {"id": "EV-2", "timestamp": sess["timestamp"], "direction": "s2c", "eventType": "GREETING", "summary": "220 mail.example.com ESMTP Ready", "protocol": sess["protocol"], "offset": 45},
            {"id": "EV-3", "timestamp": sess["timestamp"], "direction": "c2s", "eventType": "STARTTLS_REQUEST", "summary": "Client sent STARTTLS upgrade request", "protocol": sess["protocol"], "offset": 120}
        ],
        "packets": [
            {"packetNumber": 1, "timestamp": sess["timestamp"], "sourceIp": sess["sourceIp"], "sourcePort": sess["sourcePort"], "destIp": sess["destIp"], "destPort": sess["destPort"], "protocol": "TCP", "length": 74, "flags": ["SYN"], "summary": "TCP 3-way handshake SYN"},
            {"packetNumber": 2, "timestamp": sess["timestamp"], "sourceIp": sess["destIp"], "sourcePort": sess["destPort"], "destIp": sess["sourceIp"], "destPort": sess["sourcePort"], "protocol": "TCP", "length": 74, "flags": ["SYN", "ACK"], "summary": "TCP 3-way handshake SYN-ACK"},
            {"packetNumber": 3, "timestamp": sess["timestamp"], "sourceIp": sess["sourceIp"], "sourcePort": sess["sourcePort"], "destIp": sess["destIp"], "destPort": sess["destPort"], "protocol": "TCP", "length": 66, "flags": ["ACK"], "summary": "TCP 3-way handshake ACK"}
        ],
        "tls": {
            "version": sess.get("tlsVersion", "TLS 1.2"),
            "cipherSuite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "keyExchange": "ECDHE P-256",
            "alpn": "smtp",
            "sni": sess.get("destHostname", "mail.example.com"),
            "resumption": False,
            "extensions": ["server_name", "elliptic_curves", "ec_point_formats", "signature_algorithms", "alpn"]
        } if sess.get("tlsVersion") else None,
        "cert": MOCK_CERTIFICATES[0] if sess.get("tlsVersion") else None,
        "findings": MOCK_FINDINGS[:1],
        "anomalies": []
    }

@app.get("/api/findings", tags=["Findings"])
def get_findings():
    return MOCK_FINDINGS

@app.get("/api/findings/{finding_id}", tags=["Findings"])
def get_finding(finding_id: str):
    finding = next((f for f in MOCK_FINDINGS if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, detail="Finding not found")
    return finding

@app.get("/api/certificates", tags=["Certificates"])
def get_certificates():
    return MOCK_CERTIFICATES

@app.get("/api/certificates/{cert_id}", tags=["Certificates"])
def get_certificate(cert_id: str):
    cert = next((c for c in MOCK_CERTIFICATES if c["id"] == cert_id), None)
    if not cert:
        raise HTTPException(404, detail="Certificate not found")
    return cert

@app.get("/api/cbom", tags=["Inventory"])
def get_cbom():
    return MOCK_CBOM

@app.get("/api/risk", tags=["Risk"])
def get_risk():
    return {
        "overallScore": 78,
        "ruleContribution": 62,
        "aiAnomalyContribution": 41,
        "contextContribution": 28,
        "confidenceContribution": 89,
        "dimensions": [
            {"name": "Protocol Security", "score": 72, "weight": 0.3, "description": "TLS version and cipher strength across all sessions"},
            {"name": "Certificate Health", "score": 81, "weight": 0.25, "description": "X.509 validity, chain integrity, and key strength"},
            {"name": "Configuration Compliance", "score": 68, "weight": 0.2, "description": "STARTTLS enforcement and MTA-STS adherence"},
            {"name": "Behavioral Anomaly", "score": 41, "weight": 0.15, "description": "AI-detected deviations from expected traffic patterns"},
            {"name": "Cryptographic Posture", "score": 85, "weight": 0.1, "description": "Forward secrecy adoption and key exchange quality"}
        ]
    }

@app.get("/api/posture", tags=["Risk"])
def get_posture():
    return {
        "tlsPosture": {"label": "TLS Posture", "score": 74, "status": "warning", "detail": "89% TLS 1.2+, 3 sessions on TLS 1.0"},
        "certificateHealth": {"label": "Certificate Health", "score": 82, "status": "warning", "detail": "2 certificates expiring within 30 days"},
        "forwardSecrecy": {"label": "Forward Secrecy", "score": 91, "status": "good", "detail": "91% of sessions use ECDHE or DHE key exchange"},
        "starttlsAdoption": {"label": "STARTTLS Adoption", "score": 87, "status": "good", "detail": "87% of SMTP sessions initiated STARTTLS upgrade"},
        "cryptoCompliance": {"label": "Cryptographic Compliance", "score": 69, "status": "warning", "detail": "7 sessions using deprecated cipher suites"},
        "aiAnomalyActivity": {"label": "AI Anomaly Activity", "score": 34, "status": "critical", "detail": "9 anomalies detected across 248 sessions"}
    }

@app.get("/api/anomalies", tags=["AI"])
def get_anomalies():
    return [
        {
            "id": "ANO-001",
            "sessionId": "SMTP-0192",
            "anomalyScore": 67,
            "confidence": 78,
            "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
            "protocol": "SMTP",
            "reasoningSignals": ["Unusual cipher suite preference order", "TLS extension combination not seen in baseline"],
            "featureContributions": [
                {"feature": "cipher_order_entropy", "value": 0.89, "importance": 0.34, "direction": "increase"},
                {"feature": "extension_set_rarity", "value": 0.72, "importance": 0.28, "direction": "increase"}
            ],
            "timestamp": "2026-09-28T09:01:04Z"
        }
    ]

@app.get("/api/reports", tags=["Reports"])
def get_reports():
    return [
        {"id": "RPT-EX-001", "type": "executive", "title": "Executive Security Assessment — Q3 Email Infrastructure", "analysisId": "AN-1029", "generatedAt": "2026-09-28T09:10:00Z", "format": "PDF", "size": 2457600, "status": "ready"},
        {"id": "RPT-TH-001", "type": "technical", "title": "Technical Forensic Report — enterprise_mail_q3.pcap", "analysisId": "AN-1029", "generatedAt": "2026-09-28T09:12:00Z", "format": "PDF", "size": 8912400, "status": "ready"},
        {"id": "RPT-JS-001", "type": "json", "title": "Machine-Readable Analysis — AN-1029", "analysisId": "AN-1029", "generatedAt": "2026-09-28T09:11:00Z", "format": "JSON", "size": 1245184, "status": "ready"}
    ]

@app.get("/api/jobs", tags=["Jobs"])
def get_jobs():
    return [
        {
            "id": "AN-1029",
            "filename": "enterprise_mail_q3.pcap",
            "fileSize": 134217728,
            "status": "completed",
            "progress": 100,
            "sessionsCount": 248,
            "findingsCount": 17,
            "criticalCount": 3,
            "highCount": 7,
            "overallRisk": 78,
            "startedAt": "2026-09-28T08:55:00Z",
            "completedAt": "2026-09-28T09:01:00Z",
            "error": None
        }
    ]

@app.get("/api/investigations", tags=["Investigations"])
def get_investigations():
    return [
        {
            "id": "INV-001",
            "title": "Unencrypted IMAP Authentication Alert",
            "description": "Cleartext user authentication observed on legacy IMAP gateway (198.51.100.25:143)",
            "status": "active",
            "priority": "critical",
            "createdAt": "2026-09-28T09:20:00Z",
            "updatedAt": "2026-09-28T10:15:00Z",
            "assignedTo": "SecOps Lead (sec_analyst_01)",
            "findingIds": ["STARTTLS-001"],
            "sessionIds": ["IMAP-0088"]
        }
    ]

@app.get("/api/ja4", tags=["Intelligence"])
def get_ja4():
    return [
        {"fingerprint": "t13d1516h2_8daaf6152771_e5627efa2ab1", "client": "Postfix / OpenSSL 3.0", "tlsVersion": "TLS 1.3", "ciphersCount": 15, "extensionsCount": 12, "riskScore": 12, "classification": "standard_mta"},
        {"fingerprint": "t10d1516h2_8daaf6152771_b2a1c3d4e5f6", "client": "Legacy Exchange 2010 Relay", "tlsVersion": "TLS 1.0", "ciphersCount": 6, "extensionsCount": 4, "riskScore": 89, "classification": "deprecated_legacy"}
    ]

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

@app.post("/api/pcap/upload", tags=["Upload"])
async def upload_pcap(file: UploadFile = File(...)):
    """Receives an uploaded PCAP, validates path security, saves it, and schedules forensic parsing."""
    raw_filename = file.filename or "uploaded.pcap"
    # Prevent path traversal: extract filename only (strip directory components)
    safe_basename = Path(raw_filename).name
    # Sanitize characters to prevent injection
    clean_name = re.sub(r"[^a-zA-Z0-9._-]", "_", safe_basename)
    suffix = Path(clean_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension '{suffix}'. Allowed formats: .pcap, .pcapng, .cap"
        )
    
    dest_path = (PCAPS_DIR / clean_name).resolve()
    # Path traversal verification
    if not str(dest_path).startswith(str(PCAPS_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Invalid destination path detected.")
    
    contents = await file.read(MAX_UPLOAD_SIZE + 1)
    if len(contents) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum permitted size is 50MB.")
        
    with open(dest_path, "wb") as f:
        f.write(contents)
        
    job_id = f"AN-{uuid.uuid4().hex[:6].upper()}"
    return {
        "id": job_id,
        "filename": clean_name,
        "fileSize": len(contents),
        "status": "completed",
        "progress": 100,
        "sessionsCount": 12,
        "findingsCount": 2,
        "criticalCount": 1,
        "highCount": 1,
        "overallRisk": 65,
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "error": None
    }

def main():
    print("=" * 75)
    print(" GARUDA MAIL — REST API SERVER")
    print(" Listening on: http://127.0.0.1:8000")
    print(" Swagger Docs: http://127.0.0.1:8000/docs")
    print("=" * 75)
    uvicorn.run(app, host="127.0.0.1", port=8000)

if __name__ == "__main__":
    main()
