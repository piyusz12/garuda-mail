# GARUDA (SIH26159) — API Reference & Contract Specification

## 1. Gateway & Authentication Endpoints

### `POST /api/auth/[...nextauth]`
Handles participant login and session creation via credentials.
- **Request:** `{ email: string, password: string }`
- **Response:** Session cookie set, redirects to `/inbox`.

### `GET /api/presence`
Retrieves live participant directory with online status and heartbeat timestamps.
- **Response:**
```json
{
  "users": [
    {
      "id": "cuid-1",
      "name": "Defense Analyst",
      "email": "user@garudamail.local",
      "role": "analyst",
      "avatarColor": "#38BDF8",
      "isOnline": true,
      "statusText": "Active now",
      "lastActive": 1792348000000
    }
  ],
  "onlineCount": 1
}
```

---

## 2. Key Management & Trust Endpoints (Phases 4, 5, 6)

### `GET /api/keys`
List all registered public keys and SHA-256 fingerprints.
- **Query Params:** `audit=true` returns append-only key lifecycle audit logs.
- **Response:**
```json
{
  "keys": [
    {
      "userId": "cuid-1",
      "userEmail": "user@garudamail.local",
      "userName": "Defense Analyst",
      "fingerprint": "SHA256:E0:15:6A:8A:41:26:D9:24:...",
      "signingFingerprint": "SHA256:12:34:56:...",
      "encryptionPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
      "signingPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
      "algorithm": "RSA-4096-OAEP / RSA-PSS (SHA-256)",
      "version": 1
    }
  ]
}
```

### `POST /api/keys`
Registers or rotates the authenticated user's public key pair.
- **Request Body:**
```json
{
  "encryptionPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "signingPublicKey": "-----BEGIN PUBLIC KEY-----\n..."
}
```
- **Response:** `{ "success": true, "record": { ... }, "warning": null }`

### `POST /api/keys/verify`
Marks a peer's public key fingerprint as verified out-of-band.
- **Request Body:** `{ "peerEmail": "bob@enterprise.local", "verified": true }`
- **Response:** `{ "success": true, "trust": { ... } }`

---

## 3. GARUDA Mail Messaging Endpoints (Phase 2, 4, 5)

### `GET /api/emails`
Fetches paginated encrypted email envelopes for the authenticated user.
- **Query Params:** `folder=inbox|sent|drafts|starred|trash`, `page=1`, `limit=50`.
- **Response:**
```json
{
  "emails": [
    {
      "id": "cuid-email-1",
      "subject": "Mission Briefing",
      "body": "<!--GARUDA-E2EE-V2-->{...}<!--END-E2EE-V2-->",
      "isEncrypted": true,
      "preview": "[Asymmetric E2EE Encrypted Envelope]",
      "tlsVersion": "TLS 1.3",
      "cipher": "AES-256-GCM-PQC-KYBER",
      "sentAt": "2026-10-19T18:00:00Z",
      "from": { "name": "Alice", "email": "alice@garuda.local" },
      "recipients": [{ "name": "Bob", "address": "bob@enterprise.local" }]
    }
  ],
  "unreadCounts": { "inbox": 2 }
}
```

### `POST /api/emails`
Dispatches an encrypted message envelope to local or external recipients.
- **Request Body:**
```json
{
  "to": [{ "email": "bob@enterprise.local", "name": "Bob" }],
  "subject": "Classified Directive",
  "body": "<!--GARUDA-E2EE-V2-->{\"format\":\"GARUDA-E2EE-v2\",...}<!--END-E2EE-V2-->",
  "encrypted": true,
  "protocol": "auto"
}
```

---

## 4. GARUDA Sentinel Forensic Endpoints (Phases 7, 8, 9, 10, 11)

### `POST /api/pcap/upload` (FastAPI Port 8000 / Proxied Port 3000)
Uploads an authorized capture file, verifies magic bytes, reassembles flows, and evaluates deterministic rules and AI anomaly detection.
- **Request:** `multipart/form-data` with `file: [filename.pcap]`
- **Response:**
```json
{
  "id": "AN-20261019-9C5323",
  "filename": "smtp_starttls.pcap",
  "fileSize": 835,
  "signature": "Classic PCAP",
  "status": "completed",
  "progress": 100,
  "packetsCount": 9,
  "sessionsCount": 1,
  "findingsCount": 1,
  "overallRisk": 35,
  "aiAnomalyScore": 18,
  "evidenceConfidence": 94,
  "startedAt": "2026-10-19T13:20:17Z",
  "completedAt": "2026-10-19T13:20:17Z"
}
```

### `GET /api/analysis/{id}`
Returns full forensic analysis results including sessions, findings, CRS, posture, and PQC readiness.

### `GET /api/analysis/{id}/evidence`
Returns normalized 4-tier cryptographic observations (Observed, Derived, External, Unavailable).

### `GET /api/cbom/export`
Exports the Cryptographic Bill of Materials in CycloneDX 1.5 JSON standard.

### `GET /api/reports/download/{id}`
Generates a downloadable machine-readable JSON forensic audit report.
