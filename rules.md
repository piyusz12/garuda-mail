# Garuda Mail Engineering and Product Rules

## Security Rules

1. Never commit passwords, app passwords, SMTP credentials, database URLs, JWT secrets, or private keys.
2. Keep authentication and authorization checks in server-side route handlers; client visibility is not authorization.
3. Scope every mailbox query and mutation to the current session user.
4. Normalize email addresses before lookup, persistence, and comparison.
5. Hash passwords with bcrypt or a reviewed password hashing algorithm; never store plaintext passwords.
6. Use HTTPS in deployed environments and secure cookies for sessions.
7. Treat LAN traffic as untrusted. P2P or mesh delivery must authenticate peers and encrypt payloads before production use.
8. Do not use `rejectUnauthorized: false` in production SMTP transport unless a documented enterprise CA exception exists.
9. Escape or safely encode message content when rendering HTML email. Do not interpolate untrusted content into raw HTML without sanitization.
10. Do not claim that simulated handshake logs are network evidence. Label simulated, local, and externally confirmed delivery separately.

## Data Rules

1. Use Prisma migrations or an explicitly reviewed schema operation for production data changes.
2. Preserve recipient-specific folder, read, and starred state.
3. Keep external recipient addresses even when no internal user is resolved.
4. Do not delete messages permanently without an explicit user action or retention policy.
5. Use UTC timestamps in persisted data and display localized values only at the UI edge.
6. Keep forensic security metadata immutable after delivery unless a correction is audited.

## API Rules

1. Validate all request bodies with Zod or an equivalent schema.
2. Return JSON errors with stable, meaningful HTTP status codes.
3. Use `401` for missing authentication, `403` for authenticated but disallowed actions, `404` for missing resources, and `400` for invalid input.
4. Avoid leaking database, SMTP, or stack-trace details in public error responses.
5. Add pagination and bounded limits to collection endpoints.
6. Keep API contracts backward-compatible or document breaking changes in the task log.

## Frontend Rules

1. Preserve keyboard accessibility, visible focus, readable contrast, and responsive layouts.
2. Use familiar icons with accessible labels and tooltips where needed.
3. Keep mailbox actions predictable and reversible where possible.
4. Do not expose secrets or server-only configuration to client components.
5. Show loading, empty, error, and success states for network-backed workflows.
6. Avoid unnecessary polling; use bounded intervals and clean up timers on unmount.
7. Keep security context near the action it explains, especially in compose and message detail views.

## Development Rules

1. Use the package versions declared by `frontend/package.json` and `frontend/package-lock.json`.
2. Run `npx tsc --noEmit` and `npm run build` from `frontend/` before merging substantial changes.
3. Run focused API or end-to-end checks for authentication, send/receive, folders, and SMTP configuration changes.
4. Do not mix unrelated refactors into a feature change.
5. Prefer existing repository patterns over new abstractions.
6. Document environment variables and local setup changes.
7. Keep generated databases, `.env*` files, build output, and dependency directories out of version control.

## Definition of Done

A change is complete when its behavior is implemented, its authorization boundary is tested, its documentation is updated where needed, its focused validation passes, and known residual risks are recorded rather than hidden.
