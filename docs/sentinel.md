# GARUDA Sentinel — Forensic Packet Analysis & Evidence Engine

## 1. Architectural Purpose

GARUDA Sentinel is an evidence-driven forensic platform that audits authorized network captures (PCAP/PCAPNG), extracts observable cryptographic telemetry, evaluates deterministic security policies, and detects anomalies via explainable machine learning.

Sentinel operates strictly as a **defensive security auditing and posture verification tool**. It never performs offensive credential harvesting or packet injection.

---

## 2. Ingestion & Preprocessing Pipeline (Phase 7)

```
[ Raw Capture Upload (.pcap / .pcapng) ]
               │
               ▼
   [ Magic Byte Signature Validation ]
   ├─ 0xd4c3b2a1 / 0xa1b2c3d4 (Classic PCAP)
   ├─ 0x4d3cb2a1 / 0xa1b23c4d (Nanosecond PCAP)
   └─ 0x0a0d0d0a (PCAP-NG)
   (Rejects corrupted headers with HTTP 400)
               │
               ▼
    [ Path & Resource Sanitization ]
    ├─ Filename regex: [^a-zA-Z0-9._-]
    ├─ Strict 50 MB file size cap
    └─ Directory traversal defense
               │
               ▼
      [ Flow Demultiplexing ]
      └─ Groups packets by 5-tuple: (SrcIP, SrcPort, DstIP, DstPort, Protocol)
               │
               ▼
     [ TCP Stream Reassembly ]
     └─ TCPReassembler resolves out-of-order packets, retransmissions, and overlaps
```

---

## 3. Cryptographic Evidence Model (Phase 8)

Every cryptographic observation extracted from a network stream is normalized into a structured schema with explicit classification:

### 3.1 Four-Tier Evidence Classification
1. **Observed:** Directly extracted from unencrypted packet headers (e.g., ClientHello proposed ciphers, SNI extension, ALPN protocols).
2. **Derived:** Computed from available evidence through deterministic logic (e.g., JA4 fingerprint hash computed from cipher order and extension IDs).
3. **External:** Retrieved from an external authoritative source (e.g., CRL/OCSP certificate revocation status, DNSSEC TLSA record).
4. **Unavailable:** Explicitly recorded when information cannot be extracted (e.g., TLS 1.3 encrypted certificates without private key decryption secrets).

### 3.2 Evidence Record Schema
```json
{
  "evidence_id": "EV-9C5323",
  "analysis_id": "AN-20261019-9C5323",
  "session_id": "SMTP-0001",
  "protocol": "SMTP",
  "observed_attribute": "TLS_VERSION",
  "observed_value": "TLS 1.2",
  "evidence_source": "TCP Flow FLOW-00001 Reassembly",
  "confidence": 1.0,
  "classification": "Observed",
  "packet_reference": "Packets 1-9",
  "timestamp": "2026-10-19T13:20:17Z"
}
```

---

## 4. Deterministic Security Policy Rules (Phase 9)

Rules evaluate normalized evidence independently of AI models:

| Rule ID | Name | Severity | Condition | Standard Reference |
|---|---|---|---|---|
| `RULE-TLS-DEPRECATED-001` | Deprecated TLS Version | **CRITICAL** | TLS 1.0 or TLS 1.1 negotiated | NIST SP 800-52r2 Sec 3.1 / PCI DSS 4.0 |
| `RULE-STARTTLS-MISSING-001` | Plaintext Email Transmission | **CRITICAL** | Port 25/110/143/587 without TLS record | RFC 8314 Section 3 |
| `RULE-PFS-ABSENT-001` | Static RSA Key Exchange (No PFS) | **HIGH** | Static RSA cipher suite (no ECDHE/DHE) | NIST SP 800-52r2 Sec 3.3.1 |
| `RULE-CIPHER-WEAK-001` | Deprecated / Broken Cipher | **HIGH** | 3DES, RC4, or CBC-mode ciphers | NIST SP 800-131A |
| `RULE-CERT-EXPIRED-001` | Expired Server Certificate | **CRITICAL** | `daysRemaining < 0` | RFC 5280 Section 4.1.2.5 |
| `RULE-CERT-EXPIRING-002` | Certificate Expiring Soon | **MEDIUM** | `daysRemaining <= 30` | Operational Best Practice |
| `RULE-PQC-VULNERABLE-001` | Classical Quantum-Vulnerable KEX | **MEDIUM** | Classical RSA/ECC without ML-KEM hybrid | NIST FIPS 203 |
