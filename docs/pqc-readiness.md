# GARUDA Sentinel — Post-Quantum Readiness Assessment & CBOM Specification

## 1. Context: The Quantum Threat to Email Infrastructure

Classical email security relies heavily on public-key cryptography (RSA-2048, RSA-4096, and ECDSA P-256) for:
- Transport Layer Key Establishment (TLS ECDHE / RSA)
- Digital Signatures (DKIM, S/MIME, PGP, TLS Server Verification)
- Certificate Authority Trust Anchors (X.509 chains)

A cryptanalytically relevant quantum computer (CRQC) running Shor's algorithm will break RSA and elliptic curve discrete logarithms. Adversaries are actively engaging in **Store-Now-Decrypt-Later (SNDL)** attacks, intercepting and archiving encrypted enterprise communications today to decrypt them retroactively once quantum computing arrives.

---

## 2. NIST Standards Reference Framework

GARUDA aligns with the official NIST Post-Quantum Cryptography standards finalized in August 2024:

1. **NIST FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism Standard (**ML-KEM**, derived from CRYSTALS-Kyber).
   - Primary standard for general encryption and TLS key establishment.
   - Recommended Parameter Set: `ML-KEM-768` (NIST Security Category 3, AES-192 equivalent).
2. **NIST FIPS 204:** Module-Lattice-Based Digital Signature Standard (**ML-DSA**, derived from CRYSTALS-Dilithium).
   - Primary standard for electronic signatures and PKI certificate authority chains.
3. **NIST FIPS 205:** Stateless Hash-Based Digital Signature Standard (**SLH-DSA**, derived from SPHINCS+).
   - Backup standard providing hash-based signature resilience against lattice cryptanalysis.

---

## 3. Cryptographic Bill of Materials (CBOM) Schema

GARUDA Sentinel exports a machine-readable Cryptographic Bill of Materials adhering to the **CycloneDX 1.5/1.6 standard**:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-19T13:20:17Z",
    "tools": [{ "vendor": "GARUDA", "name": "GARUDA Sentinel", "version": "1.0.0" }]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "mail.enterprise.local:587",
      "version": "TLS 1.3",
      "cryptoProperties": {
        "assetType": "protocol",
        "algorithm": "TLS_AES_256_GCM_SHA384",
        "keyLength": 256,
        "oid": "urn:garuda:crypto:CBOM-001",
        "classicalSecurityLevel": 256,
        "nistQuantumSecurityLevel": 0
      }
    }
  ]
}
```

---

## 4. Four-Tier PQC Readiness Classification

When analyzing network captures and cryptographic inventory, Sentinel assigns every asset one of four clear statuses:

| Tier | Status | Technical Criteria | Remediation Priority |
|---|---|---|---|
| **Tier 1** | **Post-Quantum Certified** | Pure post-quantum algorithm active (e.g. ML-KEM-768 or ML-DSA-65). | Long-term monitoring. |
| **Tier 2** | **Hybrid Post-Quantum Ready** | Hybrid key establishment active combining classical ECDHE (X25519) + ML-KEM-768 per RFC 10024. | Optimal transition state; quantum-safe against SNDL. |
| **Tier 3** | **Quantum-Vulnerable (Classical)** | Modern classical algorithms (TLS 1.3 with X25519 or AES-256), but lacks lattice KEM. | Moderate Priority: Plan hybrid upgrade within 12–24 months. |
| **Tier 4** | **Legacy / Critical Risk** | Obsolete classical algorithms (RSA static key exchange, 1024-bit keys, SHA-1). | Immediate Priority: Upgrade to modern TLS with PFS first. |

---

## 5. Migration Roadmap & Cryptographic Agility

1. **Step 1: Cryptographic Inventory (Complete):** Discover all cipher suites, keys, and certificates via Sentinel CBOM.
2. **Step 2: Deploy Hybrid TLS 1.3 Key Establishment:** Configure servers to offer `X25519MLKEM768` hybrid groups.
3. **Step 3: Dual-Certificate PKI:** Issue leaf certificates supporting hybrid classical and ML-DSA digital signatures.
