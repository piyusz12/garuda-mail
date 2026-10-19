# GARUDA (SIH26159) — Security Controls, Residual Risks & Hardening Guide

## 1. Security Architecture & Threat Defenses

GARUDA implements defense-in-depth across the transport, application, cryptographic, and forensic layers.

### 1.1 Authentication & Session Management
- **Password Protection:** User passwords are encrypted with bcrypt (10 rounds).
- **Session Tokens:** Stateless JWT / NextAuth session tokens with `HttpOnly`, `SameSite=Lax`, and `Secure` cookie flags.
- **Session Invalidation:** Administrative credential reset endpoint (`/api/admin/reset-credentials`) securely purges all sessions and resets built-in test fixtures with role-based access control.

### 1.2 End-to-End Cryptography (Zero-Knowledge Server)
- **Asymmetric Key Pairs:** Client-side WebCrypto RSA-OAEP 2048/4096-bit for confidentiality; RSA-PSS for digital signatures.
- **Zero Plaintext Storage:** The server database and transit envelopes store only ciphertext envelopes (`format: 'GARUDA-E2EE-v2'`).
- **Private Key Isolation:** Private keys are encrypted client-side using PBKDF2 (100,000 iterations, SHA-256) + AES-256-GCM before saving in browser storage. Plaintext private keys are never transmitted to the backend.

### 1.3 Forensic File Upload & Subprocess Hardening
- **Signature Verification:** Magic bytes (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x0a0d0d0a`) are validated on incoming PCAP/PCAPNG files; spoofed extensions are rejected with HTTP 400.
- **Path Traversal Defense:** Uploaded filenames are stripped of path separators via `Path.name` and sanitized using `[^a-zA-Z0-9._-]`.
- **Resource Constraints:** Strict 50 MB upload size limit and memory bounds prevent denial-of-service via decompression bombs or parser loops.

---

## 2. Residual Risks & Technical Limitations

| Risk Factor | Residual Impact | Mitigation Strategy |
|---|---|---|
| **Local Browser Storage vs HSM** | Private keys stored encrypted in browser `localStorage` are vulnerable if the host operating system or browser profile is compromised. | Hardware-backed FIDO2 / WebAuthn integration recommended for military-grade deployments. |
| **Passive Handshake Visibility** | TLS 1.3 encrypts handshake extensions and certificates after `ServerHello`. A passive PCAP without TLS secrets cannot inspect encrypted server certificates. | Sentinel explicitly flags encrypted certificates as `Derived` or `Unavailable`, preventing false assumptions. |
| **Out-of-Band Key Verification** | If users do not actively verify fingerprints out-of-band, an active MITM gateway could replace public keys upon initial registration. | User trust warnings trigger automatically if a previously verified peer's key changes. |

---

## 3. Production Hardening Checklist

- [x] Enforce TLS 1.3 / WSS on all production endpoints.
- [x] Configure Content-Security-Policy (CSP) headers preventing untrusted script execution.
- [x] Enable HTTP Strict Transport Security (HSTS) with `max-age=31536000; includeSubDomains`.
- [x] Ensure `DATABASE_URL` connects over TLS with certificate verification.
- [x] Change all default secrets and API keys in `.env`.
