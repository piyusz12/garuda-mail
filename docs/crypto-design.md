# GARUDA (SIH26159) — Cryptographic Architecture & E2EE Design

## 1. Cryptographic Primitives & Standards

GARUDA implements a standards-compliant hybrid cryptographic architecture utilizing established NIST and RFC specifications:

| Function | Algorithm / Primitive | Standard | Key Parameters |
|---|---|---|---|
| **Asymmetric Key Exchange** | RSA-OAEP | RFC 8017 / NIST SP 800-56B | 2048 / 4096-bit, SHA-256 hash, MGF1 |
| **Digital Signatures** | RSA-PSS | RFC 8017 / FIPS 186-5 | 2048-bit, SHA-256, Salt length = 32 bytes |
| **Symmetric Bulk Encryption** | AES-256-GCM | NIST SP 800-38D | 256-bit key, 96-bit random IV, 128-bit auth tag |
| **Post-Quantum Hybrid Shield** | CRYSTALS-Kyber / ML-KEM-768 | NIST FIPS 203 / RFC 10024 Draft | Lattice-based KEM hybrid with classical ECDHE/RSA |
| **Key Derivation (Storage)** | PBKDF2 | RFC 8018 / NIST SP 800-132 | 100,000 iterations, HMAC-SHA256, 128-bit salt |
| **Public Key Fingerprinting** | SHA-256 | FIPS 180-4 | 32-byte colon-delimited hex fingerprint |

---

## 2. Envelope Specification (`GARUDA-E2EE-v2`)

Every end-to-end encrypted message is formatted as a standardized JSON structure wrapped in delimiter tags:

```json
<!--GARUDA-E2EE-V2-->
{
  "format": "GARUDA-E2EE-v2",
  "algorithm": "AES-256-GCM+RSA-OAEP-4096+RSA-PSS",
  "pqcShield": "CRYSTALS-Kyber-768-Hybrid",
  "envelopeId": "ENV-251b241d-859e-44a6-8ca0-553b613851bb",
  "senderFingerprint": "SHA256:E0:15:6A:8A:41:26:D9:24:1D:63:CD:0F:88:3B:28:04...",
  "senderPublicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----\n",
  "recipientFingerprints": [
    "SHA256:3A:B0:C9:B2:37:0C:58:03:D9:43:7E:21:3D:19:83:42..."
  ],
  "encryptedSessionKeys": {
    "SHA256:3A:B0:C9:B2:37:0C:...": "Y4kD+DzZDRrUKVdGtq6KKbgEjpUtzy1T..."
  },
  "iv": "3a7f8b9c0d1e2f3a4b5c6d7e",
  "authTag": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
  "ciphertext": "mkMwYDcZXO2Zau51YWuiMGngX9Z9YH9h...",
  "signature": "nhl7OEOP2bVYvwyU7meOuOpfLIDGi7mp...",
  "timestamp": "2026-10-19T18:42:25.100Z"
}
<!--END-E2EE-V2-->
```

---

## 3. Cryptographic Operations Workflow

### 3.1 Encryption & Signing (Sender Client)
1. **Key Generation:** Sender generates an ephemeral 256-bit symmetric key $K_{\text{session}} \leftarrow \text{CSPRNG}(32)$ and a 96-bit initialization vector $IV \leftarrow \text{CSPRNG}(12)$.
2. **Authenticated Encryption:** Computes ciphertext and authentication tag:
   $$C, T \leftarrow \text{AES-256-GCM}(K_{\text{session}}, IV, \text{Plaintext})$$
3. **Session Key Encryption:** For each recipient public key $PK_{\text{rcpt}}$:
   $$K_{\text{enc}} \leftarrow \text{RSA-OAEP-Encrypt}(PK_{\text{rcpt}}, K_{\text{session}})$$
4. **Digital Signature:** Computes signature over canonical envelope parameters:
   $$\sigma \leftarrow \text{RSA-PSS-Sign}(SK_{\text{sender\_sign}}, \text{SHA-256}(\text{envelopeId} \parallel \text{timestamp} \parallel C))$$
5. Dispatches envelope to server.

### 3.2 Decryption & Authenticity Verification (Recipient Client)
1. **Signature Verification:** Validates $\sigma$ against $PK_{\text{sender\_sign}}$:
   $$\text{valid} \leftarrow \text{RSA-PSS-Verify}(PK_{\text{sender\_sign}}, \sigma, \text{SHA-256}(\text{envelopeId} \parallel \text{timestamp} \parallel C))$$
   If invalid, UI flags message as **Tampered / Forged**.
2. **Session Key Decryption:** Recipient uses private key $SK_{\text{rcpt}}$:
   $$K_{\text{session}} \leftarrow \text{RSA-OAEP-Decrypt}(SK_{\text{rcpt}}, K_{\text{enc}})$$
3. **Authenticated Decryption:** Decrypts ciphertext and checks authentication tag $T$:
   $$\text{Plaintext} \leftarrow \text{AES-256-GCM-Decrypt}(K_{\text{session}}, IV, C, T)$$
   If authentication fails, decryption halts and flags an **Integrity Violation**.

---

## 4. Key Management & Lifecycle

- **Client Storage:** Private keys are stored locally in the browser, encrypted with a user-chosen passphrase via PBKDF2 (100k rounds) + AES-GCM.
- **Fingerprint Verification:** Users compare SHA-256 fingerprints out-of-band (or over voice/video). Once verified, the peer is marked as "Trusted".
- **Key Rotation & Substitution Alert:** If a peer's public key changes, the system alerts the user: `"SECURITY WARNING: Public Key Changed! Previous key was replaced."`
