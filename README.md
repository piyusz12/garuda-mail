# GARUDA — SIH26159: Full-Stack Secure Mail & Cryptographic Forensic Platform

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Next.js 16](https://img.shields.io/badge/Next.js-16.0+-black.svg)](https://nextjs.org/)
[![Forensic Tests](https://img.shields.io/badge/Forensic%20Tests-412%2F412%20Passing-brightgreen.svg)](email-forensic-framework/tests/)
[![Crypto E2EE Tests](https://img.shields.io/badge/Crypto%20E2EE-7%2F7%20Passed-brightgreen.svg)](frontend/test-crypto-e2ee.js)
[![CycloneDX](https://img.shields.io/badge/CBOM-CycloneDX%201.5-blueviolet.svg)](#)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM-orange.svg)](#)

> **GARUDA (SIH26159)** is an enterprise cybersecurity and cryptographic intelligence platform integrating **GARUDA Mail** (true asymmetric zero-knowledge E2EE mail transfer across local networks) with **GARUDA Sentinel** (evidence-driven passive network forensics, deterministic policy risk scoring, explainable AI anomaly detection, CycloneDX 1.5 CBOM cataloging, and NIST FIPS 203 post-quantum readiness).

---

## 1. Executive Summary & Capabilities

GARUDA delivers two complementary, unified cybersecurity capabilities:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 GARUDA (SIH26159)                                      │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│               GARUDA MAIL                 │              GARUDA SENTINEL               │
│  • True Asymmetric End-to-End Encryption  │  • Magic Byte PCAP/PCAPNG Verification     │
│    (RSA-OAEP 2048/4096 + AES-256-GCM)     │  • TCP Flow Reassembly & Protocol Parsing  │
│  • Digital Signatures (RSA-PSS SHA-256)   │  • 4-Tier Normalized Evidence Hierarchy    │
│  • Colon-Delimited Fingerprint Trust      │    (Observed, Derived, External, Unavail)  │
│    (SHA256:XX:YY:ZZ:...)                  │  • Deterministic Policy Engine (CRS 0–100) │
│  • Zero-Knowledge Server Database Relay   │  • Isolation Forest AI Anomaly Detection   │
│  • Client-Side Passphrase Locked Keys     │  • Metric Separation (CRS vs AI vs Conf)   │
│  • Peer Key Discovery & Rotation Audits   │  • CycloneDX 1.5 Cryptographic BOM (CBOM)  │
│  • WhatsApp-Style Live Online Presence    │  • NIST FIPS 203 ML-KEM PQC Readiness      │
│  • Quick Mail Dispatch Drawer on LAN      │  • Full-Spectrum SOC & SOAR Playbooks      │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 2. Master Implementation Status (Phases 1–12)

Every phase from the Master Development Specification is implemented, integrated, and verified:

| Phase | Domain / Component | Status | Verification Reference |
| :---: | :--- | :---: | :--- |
| **Phase 1** | Repository Audit, Threat Model & Environment | **100% COMPLETE** | `docs/threat-model.md`, `docs/phase-checklist.md`, `.env.example` |
| **Phase 2** | Two-Computer LAN & Transport Security | **100% COMPLETE** | `frontend/package.json` (`-H 0.0.0.0`), `docs/deployment-two-pc.md` |
| **Phase 3** | Quick Mail Dispatch & Live Presence | **100% COMPLETE** | `frontend/src/app/inbox/page.tsx`, `usePeerPresence` polling |
| **Phase 4** | Asymmetric E2EE & Digital Signatures | **100% COMPLETE** | `frontend/src/lib/crypto.ts`, `frontend/test-crypto-e2ee.js` (7/7 pass) |
| **Phase 5** | Client-Side Key Management & Trust Store | **100% COMPLETE** | `frontend/src/lib/keyStore.ts`, `frontend/src/components/crypto/KeyLifecycleManager.tsx` |
| **Phase 6** | Public Key Discovery & Zero-Knowledge Relay | **100% COMPLETE** | `frontend/src/app/api/keys/route.ts`, `frontend/src/app/api/keys/verify/route.ts` |
| **Phase 7** | Sentinel Forensics & Magic Byte Verification | **100% COMPLETE** | `email-forensic-framework/sentinel_engine.py`, `validate_pcap_signature` |
| **Phase 8** | 4-Tier Cryptographic Evidence Normalization | **100% COMPLETE** | `EvidenceRecord`, `EvidenceTier` (Observed/Derived/External/Unavailable) |
| **Phase 9** | Deterministic Policy Engine & CRS Scoring | **100% COMPLETE** | `evaluate_deterministic_policy`, CRS 0–100 calculation |
| **Phase 10** | Explainable AI Anomaly & Metric Separation | **100% COMPLETE** | `detect_ai_anomalies` (Isolation Forest), CRS vs AI vs Confidence |
| **Phase 11** | CycloneDX 1.5 CBOM & NIST FIPS 203 PQC | **100% COMPLETE** | `generate_cbom_cyclonedx`, `assess_pqc_readiness` |
| **Phase 12** | Integrated Testing, Hardening & Documentation | **100% COMPLETE** | 412/412 Pytest passed, 7/7 Crypto passed, 10 Architecture docs |

---

## 3. Architecture & Data Flow

```
                                LAN PEER-TO-PEER MAIL FLOW
 ┌────────────────────────┐                                ┌────────────────────────┐
 │   Computer A (Alice)   │                                │    Computer B (Bob)    │
 │  192.168.1.100:3000    │                                │   192.168.1.105:3000   │
 └───────────┬────────────┘                                └───────────▲────────────┘
             │ 1. Discover Bob's Public Key                            │ 4. Decrypt with
             │ 2. Encrypt with Bob's Public Key (RSA-OAEP)             │    Bob's Private Key
             │ 3. Sign envelope with Alice Private Key (RSA-PSS)       │ 5. Verify Alice
             ▼                                                         │    Signature
 ┌─────────────────────────────────────────────────────────────────────┴────────────┐
 │                     GARUDA RELAY SERVER (Zero-Knowledge)                         │
 │  • Holds ONLY ciphertext envelopes (GARUDA-E2EE-v2)                              │
 │  • Cannot decrypt message payloads (Zero Plaintext stored)                       │
 │  • Distributes public keys & tracks online peer presence                         │
 └──────────────────────────────────────┬───────────────────────────────────────────┘
                                        │
                                        ▼
                             PASSIVE FORENSIC MIRROR
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │                     GARUDA SENTINEL ENGINE (Backend)                             │
 │  1. Ingestion: PCAP / PCAPNG magic byte verification                             │
 │  2. Stream Reassembly: TCP packet defragmentation & protocol classification      │
 │  3. Evidence Extraction: 4-tier normalization (Observed/Derived/External/Unavail)│
 │  4. Deterministic Scoring: Cryptographic Risk Score (CRS: 0–100)                 │
 │  5. Explainable AI: Isolation Forest Anomaly Detection (AI Score: 0–100)         │
 │  6. CBOM Generation: CycloneDX 1.5 Cryptographic Bill of Materials               │
 │  7. PQC Readiness: NIST FIPS 203 ML-KEM migration & SNDL vulnerability matrix    │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Quick Start Guide

The repository includes a unified root CLI runner (`run.py`):

```bash
# Display help and all available commands
python run.py help
```

### 4.1 Launching the Complete Platform

```bash
# Terminal 1: Launch FastAPI Forensic REST Backend (Port 8000)
python run.py server

# Terminal 2: Launch Next.js Enterprise Webmail & Forensic Portal (Port 3000)
python run.py web
```

- **Frontend Portal**: Open [http://localhost:3000](http://localhost:3000)
- **Backend API & Swagger Docs**: Open [http://localhost:8000/docs](http://localhost:8000/docs)

### 4.2 Running Passive Forensic Analysis via CLI

```bash
# Run Sentinel multi-phase forensic analysis on capture
python run.py sentinel pcaps/smtp_starttls.pcap
```

*Sample Output:*
```text
======================================================================
 GARUDA Sentinel — Passive Forensic Analysis Engine
 Target Capture: smtp_starttls.pcap
======================================================================
[+] Analysis Job ID:        AN-20261019-EC2D98
[+] Capture SHA-256:        84c77e5d083a597eca7763356bf624d663333b89e097c7d27e8102f981fb75f1
[+] Packets Processed:      9
[+] Reassembled Sessions:   1
[+] Processing Time:        0.006s

--- METRICS SEPARATION ---
[+] Cryptographic Risk Score (CRS): 35/100
[+] AI Anomaly Score (IsoForest):   85/100
[+] Evidence Confidence:            94%

--- FINDINGS DETECTED (1) ---
 • [CRITICAL] Unencrypted Cleartext Email Session (CRS: +35)
   Affected Assets: 192.168.1.50:587 | Priority: critical
   Remediation:     Enforce mandatory STARTTLS upgrade or migrate clients to dedicated implicit TLS ports.

--- CBOM ASSETS IDENTIFIED (1) ---
 • Asset: 192.168.1.50:587 | Protocol: None (Cleartext) | Cipher: UNKNOWN
   Key: None (0 bit) | PQC Ready: False

--- PQC READINESS (NIST FIPS 203) ---
[!] Status:         Quantum-Vulnerable (Classical RSA/ECC Only)
[!] SNDL Exposure:  CRITICAL — Long-term confidential communications exposed to harvest-now-decrypt-later
[!] Recommendation: Deploy hybrid post-quantum key establishment (X25519 + ML-KEM-768 Draft-00).
======================================================================
```

---

## 5. Automated Verification & Test Suites

```bash
# 1. Run full Python forensic test suite (412 tests across Phases 1–30 + Sentinel)
python run.py test

# 2. Run TypeScript E2EE cryptographic verification suite (7 cryptographic tests)
python run.py test-crypto

# 3. Run all test suites simultaneously
python run.py test-all
```

### Test Results Summary:
- **Python Pytest Suite**: `412 passed` in `2.85s`
- **Crypto E2EE Suite**: `7 passed, 0 failed`
  - RSA-OAEP 2048 & 4096 keypair generation
  - Zero-knowledge server storage verification
  - Asymmetric encryption & RSA-PSS digital signature verification
  - Unauthorized Mallory decryption blocking (asymmetric isolation)
  - Tamper detection (single-bit modification in ciphertext fails verification)
  - Signature replay & timestamp modification rejection
  - Passphrase-protected client private key storage (PBKDF2 + AES-GCM)

---

## 6. Two-Computer LAN Demonstration Runbook

For a live demonstration between two separate laptops/workstations on the same local network:

1. **Host Computer (Computer A - e.g., IP `192.168.1.100`)**:
   ```bash
   cd "c:\garuda mail"
   # Start backend
   python run.py server
   # Start frontend bound to 0.0.0.0
   python run.py web
   ```
2. **Client Computer (Computer B - e.g., IP `192.168.1.105`)**:
   - Open browser and navigate to: `http://192.168.1.100:3000`
3. **End-to-End Encrypted Communication Flow**:
   - On Computer A: Login as `alice@garuda.gov.in`. In **Crypto Settings** (`/crypto`), generate an RSA-OAEP / RSA-PSS keypair protected by a passphrase. Alice's public key automatically registers with fingerprint `SHA256:XX:YY:...`.
   - On Computer B: Login as `bob@garuda.gov.in`. Generate Bob's keypair. Notice Alice appears as **Online (Active Now)** in the live presence bar.
   - Click Alice's card to open the **Quick Mail Dispatch Drawer**.
   - Bob selects **"Verify Fingerprint & Trust"** to verify Alice's SHA-256 fingerprint out-of-band.
   - Compose a sensitive message: *"Tactical defense briefing coordinates confirmed."*
   - Click **"Send E2EE Encrypted"**. Bob's browser encrypts using Alice's RSA-OAEP public key and signs with Bob's RSA-PSS private key.
   - On Computer A: Alice receives the message. Alice enters her private key passphrase to decrypt. Alice sees the verified green badge: **"Digitally Signed by Bob (Valid Signature)"**.
   - Check Server Logs: The server relay stores *only* the ciphertext envelope `GARUDA-E2EE-v2`. Plaintext is never exposed.

For full network setup, firewall configurations, and offline demo options, see [`docs/deployment-two-pc.md`](file:///c:/garuda%20mail/docs/deployment-two-pc.md).

---

## 7. Cryptographic & Forensic Specifications

### 7.1 GARUDA Mail Cryptography
- **Asymmetric Envelope**: `GARUDA-E2EE-v2`
- **Key Exchange / Envelope**: RSA-OAEP (2048/4096-bit, SHA-256 MGF1) + AES-256-GCM session key + Post-Quantum Kyber-768 hybrid encapsulation payload.
- **Digital Signatures**: RSA-PSS (2048/4096-bit, Salt Length 32, SHA-256).
- **Client Key Derivation**: PBKDF2 with 100,000 SHA-256 iterations + AES-256-GCM.
- **Fingerprinting**: Full SHA-256 colon-delimited uppercase hex (`SHA256:XX:YY:...`).

### 7.2 GARUDA Sentinel Forensics
- **Magic Byte Signatures**:
  - `0xd4c3b2a1` / `0xa1b2c3d4`: Classic PCAP (Little / Big Endian)
  - `0x4d3cb2a1` / `0xa1b23c4d`: Nanosecond PCAP (Little / Big Endian)
  - `0x0a0d0d0a`: PCAP-NG Block Header
- **Evidence Hierarchy**:
  - `Observed`: Directly extracted wire packets (TLS records, handshake bytes).
  - `Derived`: Computed properties (JA4 fingerprints, CRS values).
  - `External`: Corroborated databases (CVE, CWE, NIST SP 800-52r2 ratings).
  - `Unavailable`: Encrypted or missing segments (e.g., ciphertext payload post-STARTTLS).
- **Metric Independence**:
  - **Deterministic CRS (0–100)**: Cryptographic Risk Score calculated by explicit deterministic policy rules.
  - **AI Anomaly Score (0–100)**: Unsupervised Isolation Forest detecting statistical deviations.
  - **Evidence Confidence (0–100%)**: Proportion of verifiable observed packets vs gaps.
- **CBOM Standard**: CycloneDX v1.5 JSON with `cryptographic-asset` components.
- **PQC Standard**: NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) readiness assessment.

---

## 8. Master Documentation Index

All architectural, security, and operational documentation is available in the [`docs/`](file:///c:/garuda%20mail/docs/) directory:

- [**Phase Checklist & Progress Matrix**](file:///c:/garuda%20mail/docs/phase-checklist.md) — 12-phase delivery & verification matrix.
- [**STRIDE Threat Model**](file:///c:/garuda%20mail/docs/threat-model.md) — Threat boundaries, attack vectors, and countermeasure designs.
- [**System Architecture**](file:///c:/garuda%20mail/docs/architecture.md) — End-to-end component diagrams, data flows, and state machines.
- [**Security & Defenses**](file:///c:/garuda%20mail/docs/security.md) — Vulnerability defenses, zero-knowledge storage, and sanitization.
- [**API Reference**](file:///c:/garuda%20mail/docs/api.md) — REST endpoints, WebSocket protocols, and JSON schemas.
- [**Database Schemas**](file:///c:/garuda%20mail/docs/database.md) — Relay database, key registry, and parquet forensic lakehouse.
- [**Cryptographic Design**](file:///c:/garuda%20mail/docs/crypto-design.md) — Asymmetric E2EE, envelope format, and key rotation.
- [**Sentinel Forensic Architecture**](file:///c:/garuda%20mail/docs/sentinel.md) — Magic bytes, reassembly, and 4-tier evidence.
- [**Risk Scoring & Metrics**](file:///c:/garuda%20mail/docs/risk-scoring.md) — CRS deterministic engine vs AI anomaly metric separation.
- [**Post-Quantum Readiness**](file:///c:/garuda%20mail/docs/pqc-readiness.md) — NIST FIPS 203 ML-KEM migration and SNDL defense.
- [**Testing & QA Matrix**](file:///c:/garuda%20mail/docs/testing.md) — Test strategy, coverage, and automated suites.
- [**Two-Computer LAN Deployment**](file:///c:/garuda%20mail/docs/deployment-two-pc.md) — Physical LAN demonstration guide and troubleshooting.

---

## 9. Compliance Standards

- **RFC 8996**: Deprecation of TLS 1.0 and TLS 1.1 with automated detection.
- **RFC 9325**: Current recommendations for secure TLS and DTLS usage.
- **NIST SP 800-52 Rev. 2**: Selection, configuration, and use of TLS.
- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
- **CycloneDX v1.5**: Cryptographic Bill of Materials (CBOM) specification.
- **MITRE ATT&CK**: Enterprise matrix mapping (`T1557.002` Downgrade, `T1573.002` Encrypted Channel, `T1048.003` Exfiltration, `T1588.003` Key Compromise).

---

## 10. Enterprise License

GARUDA (SIH26159) is developed for national cybersecurity initiatives, enterprise security operations centers (SOCs), and defense infrastructures. All rights reserved.
