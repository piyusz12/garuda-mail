# GARUDA (SIH26159) — System Architecture Specification

## 1. Architectural Philosophy

GARUDA is an integrated cybersecurity engineering system combining:
1. **GARUDA Mail:** Operational, end-to-end encrypted messaging designed for cross-computer local area network (LAN) communication with real-time peer presence and zero-knowledge servers.
2. **GARUDA Sentinel:** An evidence-driven cryptographic security assessment platform that ingests authorized network captures (PCAP/PCAPNG), extracts observable cryptographic parameters, evaluates security policy compliance via a deterministic engine, and performs AI-driven anomaly detection.

Both systems are connected through an integrated architecture: GARUDA Mail generates authentic network traffic (SMTP, SMTPS, STARTTLS, LAN Mesh), and GARUDA Sentinel inspects and audits this traffic to verify cryptographic hygiene and post-quantum readiness.

---

## 2. High-Level Component Map

```
+===================================================================================================+
|                                    GARUDA UNIFIED PLATFORM                                        |
+===================================================================================================+
|                                                                                                   |
|  [ LAYER 1: CLIENT APPLICATIONS ]                                                                 |
|  +-------------------------------------+         +-------------------------------------+          |
|  |           CLIENT NODE A             |         |           CLIENT NODE B             |          |
|  |  - WebCrypto Asymmetric E2EE        |         |  - WebCrypto Asymmetric E2EE        |          |
|  |  - Passphrase-Encrypted Key Store   |         |  - Passphrase-Encrypted Key Store   |          |
|  |  - Digital Signature Generation     |         |  - Digital Signature Verification   |          |
|  |  - Fingerprint Verification UI      |         |  - Fingerprint Verification UI      |          |
|  |  - Local Air-Gapped DPI Engine      |         |  - Local Air-Gapped DPI Engine      |          |
|  +------------------+------------------+         +------------------+------------------+          |
|                     |                                               |                             |
|                     | HTTPS / TLS 1.3 / WSS (Local LAN or Wi-Fi)    |                             |
|                     +-----------------------+-----------------------+                             |
|                                             |                                                     |
|  [ LAYER 2: SERVICE & RELAY GATEWAY ]       |                                                     |
|  +------------------------------------------v--------------------------------------------------+  |
|  |  NEXT.JS 16 ENTERPRISE GATEWAY & PROTOCOL ROUTER (Port 3000)                                |  |
|  |  - NextAuth Session & Device Authentication                                                 |  |
|  |  - Zero-Knowledge Message Routing & Enveloping                                              |  |
|  |  - Real-Time WebSocket & Server-Sent Events (SSE) Hub                                        |  |
|  |  - Multi-Protocol Mail Dispatcher (SMTP, SMTPS, STARTTLS, LAN Mesh)                          |  |
|  |  - Key Registry & Peer Discovery Endpoints                                                  |  |
|  +---------------------+------------------------------------------------+----------------------+  |
|                        |                                                |                         |
|  [ LAYER 3: PERSISTENCE ]                                [ LAYER 4: SENTINEL FORENSIC BACKEND ]   |
|  +---------------------v--------------------+            +--------------v----------------------+  |
|  |  DATABASE STORAGE                        |            |  FASTAPI FORENSIC SERVICE (Port 8000)|  |
|  |  - PostgreSQL / Prisma / Resilient Store |            |  - PCAP/PCAPNG Upload & Ingestion   |  |
|  |  - Encrypted Envelopes (No Plaintext)    |            |  - Magic-Byte & Header Validation   |  |
|  |  - Public Keys & Hashes                  |            |  - TCP Stream Reassembly (Scapy)    |  |
|  |  - User Credentials (Bcrypt hashed)      |            |  - TLS Handshake & JA4 Extractor    |  |
|  |  - Audit & Telemetry Events              |            |  - Deterministic Policy Engine (CRS)|  |
|  +------------------------------------------+            |  - AI Anomaly Pipeline (IF / AE)    |  |
|                                                          |  - CycloneDX CBOM Generator         |  |
|                                                          |  - NIST FIPS 203 PQC Assessor       |  |
|                                                          +-------------------------------------+  |
+===================================================================================================+
```

---

## 3. Data Flow Pipelines

### 3.1 GARUDA Mail: End-to-End Encrypted Message Flow

```
[ Sender Client (Alice) ]
  │
  ├─ 1. Retrieve Bob's Public Key (from Server Key Registry)
  ├─ 2. Generate random 256-bit symmetric session key (K_session)
  ├─ 3. Encrypt message body: C_msg = AES-256-GCM(K_session, plaintext, IV)
  ├─ 4. Encrypt session key: C_key = RSA-OAEP(Bob_PublicKey, K_session)
  ├─ 5. Sign message digest: Sig = RSA-PSS(Alice_PrivateKey, SHA-256(C_msg))
  ├─ 6. Package into EncryptedEnvelope JSON
  │
  ▼  POST /api/emails (HTTPS / TLS 1.3)
[ GARUDA Hub Server ]
  │
  ├─ 7. Authenticate Alice's session token
  ├─ 8. Verify rate limits and input constraints
  ├─ 9. Persist raw EncryptedEnvelope (Server CANNOT decrypt C_msg)
  ├─ 10. Route envelope to Bob via WebSocket / SSE / Polling
  │
  ▼  Delivery Notification (WSS / SSE)
[ Recipient Client (Bob) ]
  │
  ├─ 11. Retrieve Alice's Public Key
  ├─ 12. Verify digital signature: RSA-PSS-Verify(Alice_PublicKey, Sig, SHA-256(C_msg))
  ├─ 13. Decrypt session key: K_session = RSA-OAEP-Decrypt(Bob_PrivateKey, C_key)
  ├─ 14. Decrypt message body: plaintext = AES-256-GCM-Decrypt(K_session, C_msg, IV)
  └─ 15. Display authenticated message with "Signed & Verified" badge in UI
```

### 3.2 GARUDA Sentinel: PCAP Ingestion & Forensic Processing Flow

```
[ Authorized Operator ]
  │
  ├─ 1. Upload authorized PCAP/PCAPNG capture
  │
  ▼  POST /api/pcap/upload (FastAPI Backend)
[ Forensic Ingestion Pipeline ]
  │
  ├─ 2. Signature Validation: Verify magic bytes (0xa1b2c3d4, 0xd4c3b2a1, 0x0a0d0d0a)
  ├─ 3. Path Sanitation: Strip directory components, enforce 50MB bound
  ├─ 4. Flow Management: Demultiplex packets into bidirectional TCP flows (5-tuple)
  ├─ 5. TCP Stream Reassembly: Sequence reordering and boundary reconstruction
  ├─ 6. Protocol Parser: Extract SMTP/IMAP/POP3 commands and STARTTLS transitions
  ├─ 7. Cryptographic Extractor:
  │      - TLS Handshake (ClientHello / ServerHello)
  │      - Advertised vs Negotiated Cipher Suites
  │      - Key Exchange Parameters (PFS, ECDHE curves)
  │      - X.509 Certificate Chain & Expiration
  │      - Cleartext credential leak detection
  ├─ 8. Deterministic Policy Engine:
  │      - Evaluate 15+ versioned security rules
  │      - Calculate Cryptographic Risk Score (CRS: 0-100)
  ├─ 9. AI Anomaly Engine:
  │      - Extract normalized continuous features
  │      - Run Isolation Forest inference
  │      - Calculate independent AI Anomaly Score (0-100)
  │      - Calculate Evidence Confidence (0-100)
  ├─ 10. CBOM & PQC Engine:
  │      - Generate CycloneDX 1.5 JSON/XML inventory
  │      - Map primitives against NIST FIPS 203 (ML-KEM) readiness
  │
  ▼  GET /api/analysis/{jobId}
[ Unified Security Dashboard & Reports ]
  └─ Executive PDF, Deep Forensic PDF, and Machine-Readable JSON Export
```

---

## 4. Security Boundaries

1. **Client Isolation:** All private cryptographic material resides in the browser. Decryption never occurs on the server.
2. **Network Transport:** Plain HTTP/WS connections are rejected. TLS 1.3 is enforced with local CA trust pinning for LAN testing.
3. **Forensic Sandbox:** Network capture files are parsed in isolated worker threads with strict execution bounds, preventing command injection and memory exhaustion.
4. **Scoring Integrity:** The Deterministic Policy Engine operates independently of the AI Anomaly Detector. AI models cannot suppress or downgrade confirmed security violations.
