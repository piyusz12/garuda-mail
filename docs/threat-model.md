# GARUDA (SIH26159) — Threat Model & Risk Register

## 1. System Overview & Security Boundaries

GARUDA comprises two complementary systems:
1. **GARUDA Mail:** An operational, end-to-end encrypted messaging system designed for secure peer-to-peer and relayed communication across local networks (LAN) and beyond.
2. **GARUDA Sentinel:** An evidence-driven cryptographic security assessment platform that ingests PCAP/PCAPNG network captures, extracts observable cryptographic parameters, evaluates security policy compliance via a deterministic engine, and performs AI-driven anomaly detection.

```
+---------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY                                     |
|                                                                                       |
|   +-----------------------+                         +-----------------------+         |
|   |   Client Node A       |                         |   Client Node B       |         |
|   |   (Browser / Local)   |                         |   (Browser / Local)   |         |
|   |  - WebCrypto E2EE     |                         |  - WebCrypto E2EE     |         |
|   |  - Encrypted Storage  |                         |  - Encrypted Storage  |         |
|   |  - Private Key (User) |                         |  - Private Key (User) |         |
|   +-----------+-----------+                         +-----------+-----------+         |
|               |                                                 |                     |
|               | TLS 1.3 / WSS (Local Area Network / Wi-Fi)       |                     |
|               +-----------------------+-------------------------+                     |
|                                       |                                               |
|                    +------------------v-------------------+                           |
|                    |         GARUDA Hub / Relay           |                           |
|                    |     (FastAPI / Next.js Proxy)        |                           |
|                    |  - Zero-Knowledge Message Routing    |                           |
|                    |  - Authenticated Envelopes Only      |                           |
|                    |  - Key Registry & Peer Discovery     |                           |
|                    +------------------+-------------------+                           |
|                                       |                                               |
|                  +--------------------+--------------------+                          |
|                  |                                         |                          |
|   +--------------v-------------+           +---------------v---------------+          |
|   |      Database Store        |           |   GARUDA Sentinel Engine      |          |
|   |  - Ciphertext Envelopes    |           |  - PCAP / PCAPNG Ingestion    |          |
|   |  - Public Keys & Hashes    |           |  - Scapy / WASM DPI Parser    |          |
|   |  - Audit & Telemetry Logs  |           |  - Deterministic Policy Engine|          |
|   |  (No Plaintext Messages)   |           |  - AI Anomaly Detector (IF)   |          |
|   +----------------------------+           |  - CBOM & PQC Assessor        |          |
|                                            +-------------------------------+          |
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

---

## 2. Trust Boundaries

| Boundary | Description | Protected Assets | Mitigations |
|---|---|---|---|
| **Boundary 1: Client Browser Runtime** | Isolates user private keys and decrypted plaintexts from the network and server. | Unencrypted messages, private keys, passphrases | WebCrypto client-side execution; private keys never leave browser; passphrase PBKDF2/AES-GCM encrypted local store. |
| **Boundary 2: LAN Transport** | Network link between client devices and the GARUDA gateway. | Session tokens, encrypted envelopes, public key queries | TLS 1.3 / TLS 1.2 with PFS; strict certificate validation; WSS; HSTS; disable plain HTTP/WS. |
| **Boundary 3: Server Application Layer** | The API gateway, envelope routing service, and session manager. | User identities, authentication records, routing tables | Strict JWT/session authorization; rate limiting; input validation via Zod and Pydantic schemas. |
| **Boundary 4: Persistent Data Store** | The relational database (PostgreSQL / Prisma / JSON store). | Message history, public keys, audit logs | Zero-knowledge architecture: database stores only encrypted envelopes; no server-side decryption keys exist. |
| **Boundary 5: Forensic Analysis Pipeline** | The PCAP ingestion, packet parsing, and AI inference sandbox. | Server memory, file system, parser processes | Subprocess isolation, strict file signature verification, path traversal sanitation, memory & execution bounds. |

---

## 3. Threat Analysis (STRIDE Model)

### 3.1 Unauthorized Access & Impersonation (Spoofing)
- **Threat:** An adversary on the LAN attempts to register as another user or forge message sender headers.
- **Impact:** High. Adversary can read messages intended for the victim or send malicious messages under victim's identity.
- **Mitigation:**
  - Password hashing with bcrypt (cost factor 10).
  - Cryptographic digital signatures: every message must be signed with the sender's private key. The recipient verifies the signature against the sender's public key; header spoofing results in immediate signature mismatch.
  - Active session authentication via HTTP-only, secure, SameSite cookies or signed tokens.

### 3.2 LAN Interception & Man-in-the-Middle (Information Disclosure)
- **Threat:** An attacker on the same Wi-Fi/LAN uses ARP spoofing or DNS poisoning to intercept traffic between PC-A and PC-B.
- **Impact:** Critical. Eavesdropping on communications and credential theft.
- **Mitigation:**
  - **Transport Layer:** Mandatory TLS 1.3 encryption prevents plaintext eavesdropping on the network.
  - **Application Layer (E2EE):** Even if TLS is terminated or intercepted via a malicious proxy, messages are encrypted client-side using the recipient's public key (AES-256-GCM + Kyber hybrid). The intercepted payload is cryptographically indecipherable without the recipient's private key.

### 3.3 Message Tampering & Replay Attacks (Tampering)
- **Threat:** An attacker intercepts an encrypted envelope in transit and alters bits or replays previously sent valid messages.
- **Impact:** High. Delivery of corrupted data or unauthorized repetition of transactions.
- **Mitigation:**
  - Authenticated Encryption: AES-256-GCM provides authenticated ciphertext with 128-bit authentication tags (`authTag`). Any bit modification causes decryption to fail.
  - Nonce & Timestamp Verification: Every envelope includes a monotonically increasing timestamp and unique message UUID (`envelopeId`). Messages older than 5 minutes or with reused nonces are rejected.

### 3.4 Public-Key Substitution (Tampering / Spoofing)
- **Threat:** A compromised or malicious server replaces Bob's public key with Mallory's public key when Alice requests Bob's key.
- **Impact:** Critical. Alice unknowingly encrypts messages for Mallory.
- **Mitigation:**
  - Out-of-band fingerprint verification: Alice and Bob can visually inspect and compare public key SHA-256 fingerprints in the UI.
  - Trust State Warning: Once Alice marks Bob's key as "Verified", if the server returns a different public key for Bob in the future, the UI issues a prominent warning: `"WARNING: Public Key Changed! Previous key was replaced. Potential MITM attack."`
  - Append-only key audit log recorded on the server.

### 3.5 Private-Key Theft (Information Disclosure)
- **Threat:** Malicious scripts, browser extensions, or physical access to PC-A compromise the user's private key.
- **Impact:** Critical. Total loss of confidentiality for past and future messages.
- **Mitigation:**
  - Private keys are NEVER stored in plaintext in `localStorage`.
  - Private keys are encrypted using AES-256-GCM derived from a user passphrase using PBKDF2 (100,000 iterations).
  - Private keys are NEVER transmitted to the backend server or logged in console telemetry.

### 3.6 Malicious or Malformed PCAP Uploads (Denial of Service / Elevation of Privilege)
- **Threat:** An attacker uploads a crafted PCAP file containing malformed packet headers, memory-corrupting exploit payloads, or path traversal strings (`../../etc/passwd`).
- **Impact:** Critical. Remote code execution or server crash.
- **Mitigation:**
  - File signature validation: Magic bytes checked at file start (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x0a0d0d0a`). Files failing signature validation are rejected before parsing.
  - Path traversal defense: Filenames are stripped of directory paths using `Path.name` and sanitized with strict regex `[^a-zA-Z0-9._-]`.
  - Resource bounds: Enforce a strict 50MB upload limit and a 30-second parsing timeout with subprocess isolation.
  - Safe parsing APIs: Subprocesses never use shell interpolation (`shell=False`).

### 3.7 Database Compromise (Information Disclosure)
- **Threat:** An attacker gains read-only or read-write access to the database (SQL injection or leaked database credentials).
- **Impact:** High. Data exposure.
- **Mitigation:**
  - Zero-Knowledge Architecture: The database stores ONLY ciphertext envelopes. No plaintext message bodies, plain attachments, or private keys exist in the database.
  - Parameterized queries enforced through Prisma ORM / SQLAlchemy.

### 3.8 AI False Positives & Hallucinations (Repudiation / Misleading Risk)
- **Threat:** An anomaly detection model generates high risk scores for benign traffic or fails to flag malicious unencrypted traffic.
- **Impact:** Medium. Alert fatigue or overlooked vulnerabilities.
- **Mitigation:**
  - Strict separation of concerns: The **Deterministic Policy Engine** is the sole source of truth for cryptographic policy findings (e.g., deprecated TLS, plaintext passwords).
  - AI Anomaly Scores are presented as a distinct, separate indicator from the Cryptographic Risk Score (CRS).
  - Evidence Confidence metric clearly indicates when evidence is insufficient to draw conclusions.

---

## 4. Risk Register

| Risk ID | Vulnerability / Threat | Likelihood | Impact | Severity | Status | Mitigation Strategy |
|---|---|---|---|---|---|---|
| **RSK-01** | Server-side decryption exposing plaintext in API routes | High | Critical | **CRITICAL** | Remediating (Phase 4) | Transition to client-side WebCrypto encryption and decryption. |
| **RSK-02** | Symmetric key derived from server secret instead of asymmetric user keys | High | Critical | **CRITICAL** | Remediating (Phase 4) | Implement asymmetric RSA-OAEP / Curve25519 key pairs per user. |
| **RSK-03** | Lack of digital signatures allowing message sender spoofing | Medium | High | **HIGH** | Remediating (Phase 5) | Implement client-side digital signatures on all envelopes. |
| **RSK-04** | Missing public key change warning allowing key substitution | Low | Critical | **HIGH** | Remediating (Phase 6) | Build trust verification state and key change alerts. |
| **RSK-05** | PCAP upload path traversal or parser memory exhaustion | Medium | High | **HIGH** | Remediating (Phase 7) | Strict file signature checks, sanitized paths, and 50MB resource caps. |
| **RSK-06** | Conflating AI anomaly scores with deterministic security violations | High | Medium | **MEDIUM** | Remediating (Phase 9/10)| Separate CRS (policy) from AI Anomaly Score and Evidence Confidence. |
| **RSK-07** | Local LAN deployment certificate rejection on remote PC | High | Medium | **MEDIUM** | Remediating (Phase 3) | Provide dedicated root CA installer and self-signed certificate guide. |
