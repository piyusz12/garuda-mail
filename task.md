# Garuda Mail Implementation Task Plan

## Current Baseline

- Source revision: `2ed6b22`
- Frontend location: `frontend/`
- Local dev command: `npm run dev` from `frontend/`
- Local build command: `npm run build` from `frontend/`
- Local database: SQLite with `DATABASE_URL=file:./dev.db`

## Completed Baseline Work

- [x] Authentication with NextAuth credentials provider.
- [x] Prisma schema for users, messages, recipients, attachments, labels, accounts, and sessions.
- [x] Inbox, sent, drafts, starred, archive, and trash workflows.
- [x] Internal recipient resolution and mailbox delivery.
- [x] Protocol catalog for SMTP STARTTLS, SMTPS, direct SMTP, P2P mesh, and IMAP sync.
- [x] Dynamic Nodemailer transport and SMTP verification path.
- [x] Protocol and user API routes.
- [x] Local seed data for development.
- [x] Production build validation after Prisma client generation.

## Priority 0: Release Blockers

- [ ] Replace placeholder production database settings with deployment-specific managed database configuration.
- [ ] Move all production secrets to a secret manager and rotate development secrets before release.
- [ ] Enforce certificate validation in SMTP transport by default; document any enterprise CA override.
- [ ] Confirm Next.js 16 and NextAuth 4 compatibility in CI or upgrade the authentication stack.
- [ ] Add CI checks for typecheck, build, focused API tests, and dependency audit.
- [ ] Ensure `.env*`, SQLite files, `.next`, and local artifacts remain ignored.

## Priority 1: Reliability and Security

- [ ] Add integration tests for unauthorized access to every email, user, and protocol route.
- [ ] Add tests proving one user cannot read or mutate another user's message or recipient state.
- [ ] Add tests for duplicate recipients, malformed addresses, oversized bodies, and invalid protocol values.
- [ ] Add transactional handling for message plus recipient creation.
- [ ] Add structured audit events for send, delete, restore, configuration change, and SMTP verification.
- [ ] Sanitize HTML email rendering and define an attachment validation policy.
- [ ] Add rate limiting for login, registration, send, and connection verification endpoints.

## Priority 2: Product Completion

- [ ] Implement true inbound IMAP/POP3 synchronization or rename the current path clearly as a connectivity simulation.
- [ ] Implement authenticated and encrypted LAN peer discovery before calling P2P mesh production-ready.
- [ ] Add message threading and conversation grouping.
- [ ] Add attachment upload, storage, download authorization, and malware scanning hooks.
- [ ] Add labels and user-configurable mailbox rules.
- [ ] Add real-time updates with Server-Sent Events or WebSockets where polling is insufficient.
- [ ] Add administrative user and role management.
- [ ] Add delivery retry, queue state, and dead-letter visibility for external SMTP failures.

## Priority 3: Operations and UX

- [ ] Add health and readiness endpoints that do not disclose secrets.
- [ ] Add metrics for send latency, SMTP failures, mailbox polling, and database errors.
- [ ] Add responsive accessibility review and keyboard-flow tests.
- [ ] Add empty, loading, error, offline, and retry states to every network-backed screen.
- [ ] Replace placeholder project README content with Garuda Mail setup and operations guidance.
- [ ] Document LAN firewall requirements and secure deployment topology.

## Validation Checklist

- [ ] `npm ci` from `frontend/` succeeds with the committed lockfile.
- [ ] Prisma client generation succeeds using the declared Prisma version.
- [ ] `npx tsc --noEmit` passes.
- [ ] `npm run build` passes.
- [ ] Seeded user can sign in.
- [ ] Internal user-to-user send and receive passes.
- [ ] External SMTP failure is visible and does not lose the local message record.
- [ ] Unauthorized API calls return 401.
- [ ] Cross-user data access tests pass.
- [ ] LAN access is tested only on a trusted development network.
