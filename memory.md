# Garuda Mail Project Memory

## Repository

- Git remote: `https://github.com/piyusz12/garuda-mail.git`
- Active branch: `main`
- Documentation baseline revision: `2ed6b22`
- Main updated web product: `frontend/`
- Separate legacy/root Vite app and Python forensic framework also exist in the repository.

## Runtime

- Frontend uses Next.js 16.3.6, React 19, TypeScript, Prisma, NextAuth, Nodemailer, Tailwind, Framer Motion, Recharts, and Lucide React.
- Start locally with `npm run dev` from `frontend/`.
- The dev script binds Next.js to `0.0.0.0` and defaults to port 3000.
- Local browser URL is `http://localhost:3000`; LAN access uses the host's current IPv4 address and port 3000.

## Database

- Prisma schema: `frontend/prisma/schema.prisma`.
- Local development uses SQLite with `DATABASE_URL=file:./dev.db`, creating `frontend/prisma/dev.db`.
- The validated local Prisma pair is `prisma@6.12.0` and `@prisma/client@6.12.0`.
- Initialize with `npx prisma db push` and seed with `node prisma/seed.js` from `frontend/`.
- The seed accounts use the development password `password123`; never reuse those credentials in production.
- Production must use a managed database, pooling, migrations, backups, and secret management.

## Authentication

- NextAuth uses credentials authentication, Prisma adapter, and JWT sessions.
- Server handlers authorize with `getServerSession(authOptions)`.
- The auth implementation currently falls back to a development secret if `NEXTAUTH_SECRET` is absent; production must always define and rotate the secret.

## Mail Delivery

- Internal recipients are persisted as recipient records and can receive mail without external SMTP.
- `src/lib/protocols.ts` defines protocol metadata and generated handshake transcripts.
- `src/lib/mailer.ts` uses Nodemailer when SMTP credentials are configured.
- SMTP environment variables include `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `GMAIL_USER`, and `GMAIL_APP_PASSWORD`.
- External delivery errors are recorded in the dispatch result while local persistence remains the source of mailbox truth.
- Current SMTP TLS configuration disables certificate verification; treat this as a release-blocking security issue for production.

## Validation

- `npm run build` must be run from `frontend/`.
- A generated Prisma client is required before type checking/building.
- The repository has had dependency state mismatches before; verify installed `@prisma/client` and `prisma` versions match `frontend/package.json` and the lockfile.
- Run `npx tsc --noEmit` and focused end-to-end checks after API or auth changes.
- Do not commit `.env.local`, `.env`, SQLite databases, `node_modules`, `.next`, or generated build output.

## Product Truths

- Garuda Mail is an email workspace with forensic security context, not a hardened mail server by itself.
- Generated protocol logs are application evidence and must not be presented as packet-capture evidence.
- P2P mesh and inbound IMAP/POP3 paths require further production implementation and verification.
- User-scoped authorization is more important than UI hiding; every route must enforce it server-side.
