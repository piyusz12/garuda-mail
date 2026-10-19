# GARUDA (SIH26159) — Database Schema & Migration Guide

## 1. Schema Design Principles

The database is designed with a strict **Zero-Knowledge Architecture**:
- **Confidentiality:** Plaintext email bodies, plain attachments, and user private keys are **NEVER stored** on the server.
- **Envelope Storage:** Messages are persisted exclusively as authenticated, encrypted envelopes (`body` stores ciphertext with IV, auth tag, and digital signature).
- **Public-Key Discovery:** The schema stores only public keys (`spki` format) and cryptographic fingerprints (`SHA256:...`).

---

## 2. Entity-Relationship Model

```
+-------------------+             +-----------------------+
|       User        | 1         * |         Email         |
|-------------------|-------------|-----------------------|
| id (PK)           |             | id (PK)               |
| email (Unique)    |             | subject               |
| password (Bcrypt) |             | body (Ciphertext ENV) |
| role              |             | preview (Encrypted)   |
| department        |             | fromId (FK -> User)   |
| avatarColor       |             | tlsVersion            |
| createdAt         |             | cipher                |
+---------+---------+             | forwardSecrecy        |
          | 1                     | riskScore             |
          |                       | sentAt                |
          | *                     +-----------+-----------+
+---------v---------+                         | 1
|  EmailRecipient   |                         |
|-------------------|                         | *
| id (PK)           |             +-----------v-----------+
| emailId (FK)      |<------------+      Attachment       |
| userId (FK)       |             |-----------------------|
| address           |             | id (PK)               |
| folder            |             | emailId (FK -> Email) |
| read              |             | filename              |
| starred           |             | mimeType              |
+-------------------+             | size                  |
                                  | url                   |
                                  +-----------------------+
```

---

## 3. Core Models

### `User`
Stores authenticated participants.
- `id`: Unique cuid identifier.
- `email`: Normalized unique email address.
- `password`: Hashed with bcrypt (cost factor 10).
- `role`: Role-based access control (`admin`, `officer`, `analyst`, `user`).

### `Email`
Stores zero-knowledge message envelopes.
- `body`: Contains raw ciphertext string (`<!--GARUDA-E2EE-V2-->{...}<!--END-E2EE-V2-->`).
- `tlsVersion`: Transport-level protocol observed during transmission.
- `cipher`: Cryptographic cipher applied (e.g. `AES-256-GCM-PQC-KYBER`).
- `riskScore`: Cryptographic risk score derived from forensic policy rules.

### `EmailRecipient`
Manages per-recipient delivery, unread indicators, folders (inbox, archive, trash), and starring.

---

## 4. Migration & Seeding Commands

```bash
# Generate Prisma Client
cd frontend
npx prisma generate

# Apply migrations to PostgreSQL
npx prisma migrate deploy

# Seed baseline test participants (Alice, Bob, Analyst)
node prisma/seed.js
```
