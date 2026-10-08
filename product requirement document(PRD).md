# Garuda Mail Product Requirements Document

## Document Status

- Version: 1.0
- Date: 2026-10-04
- Source revision: `2ed6b22`
- Product: Garuda Mail
- Primary application: `frontend/`

## 1. Product Vision

Garuda Mail is a secure, multi-device web email workspace for enterprise security and forensic teams. It combines ordinary mailbox workflows with visible transport-security intelligence: protocol selection, TLS posture, cipher metadata, delivery transcripts, and operational controls.

The product must feel like a practical email client first and a forensic console second. Common mail actions should be fast, while security context remains available at the moment a message is composed, delivered, inspected, or configured.

## 2. Users

### Security Analyst

Needs to read, search, classify, compose, reply to, forward, archive, star, and delete messages while understanding transport risk.

### Security Administrator

Needs to configure mail transport, inspect protocol capabilities, verify SMTP/IMAP connectivity, and manage operational settings.

### Multi-device Team Member

Needs mailbox state and messages to appear consistently across PCs on the same network or through the configured deployment.

## 3. Goals

1. Provide authenticated mailbox access with per-user data isolation.
2. Support inbox, sent, drafts, starred, archive, and trash workflows.
3. Persist users, messages, recipients, labels, attachments, and security metadata.
4. Support protocol-aware dispatch for automatic routing, STARTTLS SMTP, SMTPS, direct SMTP, LAN mesh, and IMAP synchronization concepts.
5. Make delivery evidence understandable through protocol badges and handshake transcripts.
6. Support local zero-configuration development using SQLite.
7. Allow production SMTP credentials and database settings to be supplied through environment variables.

## 4. Non-goals

- The application is not a full replacement for a hardened enterprise mail server.
- LAN P2P delivery is not a substitute for authenticated, encrypted production federation until its transport implementation is independently verified.
- IMAP and POP3 inbound synchronization is currently a connection-verification workflow, not a complete remote mailbox importer.
- The application must not claim that simulated handshake text proves a real network handshake.

## 5. Functional Requirements

### Authentication

- Users can sign in with email and password.
- Passwords are stored as bcrypt hashes.
- Sessions use NextAuth JWT strategy.
- Unauthenticated API requests return HTTP 401.
- Users can sign out and access protected mailbox pages only with a valid session.

### Mailbox

- A signed-in user can view inbox messages and unread counts.
- A user can view sent, draft, starred, archived, and trashed messages.
- A user can search message subject and body.
- A user can open a message, mark it read, star it, reply, forward, archive, trash, restore, or permanently delete it where supported.
- Inbox polling must make new internal messages visible without a full page reload.

### Composition and delivery

- A user can enter one or more To recipients, optional Cc recipients, subject, and body.
- The system validates recipients and required content before persistence.
- A user can save a draft.
- A user can select automatic protocol routing or an explicit supported protocol.
- Internal recipients are resolved to local users when possible.
- External SMTP delivery is attempted only when complete SMTP credentials are configured.
- The system always records a local delivery result and security metadata for the message.

### Security intelligence

- Messages may include TLS version, cipher, forward secrecy, STARTTLS, protocol, and risk score metadata.
- Composition and delivery views expose a readable handshake transcript.
- Protocol catalog entries show default port, encryption, cipher, RFC reference, and PFS state.
- Protocol and user APIs require authentication.

### Configuration

- Local development supports SQLite through `DATABASE_URL=file:./dev.db`.
- Production deployment must use a managed database and secret manager.
- SMTP settings must be supplied through environment variables or an explicitly configured server-side transport profile.

## 6. Quality Requirements

- TypeScript must compile with `npx tsc --noEmit`.
- The production frontend build must pass with `npm run build` from `frontend/`.
- API errors must use stable HTTP status codes and JSON error messages.
- Secrets must never be committed or exposed to client components.
- Database mutations must be authorized against the current session user.
- Security metadata must distinguish simulated/local dispatch from externally confirmed SMTP delivery.
- The UI must remain usable at desktop and mobile widths.

## 7. Acceptance Criteria

- A seeded analyst can sign in locally.
- The seeded analyst can see seeded forensic messages.
- A message sent to another seeded user appears in that user's inbox after polling or refresh.
- A message sent to an external address is persisted even if SMTP is unavailable, with the failure represented in delivery evidence.
- `frontend` builds successfully against the declared Prisma version.
- No placeholder production database or SMTP credential is used during a production deployment.
