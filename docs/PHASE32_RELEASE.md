# Phase 32 Release Foundation

This release foundation establishes the first production-hardening contracts for Garuda Mail.

## Health endpoints

| Endpoint | Purpose | Dependency check |
| --- | --- | --- |
| `/api/live` | Process liveness | None |
| `/api/ready` | Request readiness | PostgreSQL |
| `/api/health` | Human and deployment health summary | PostgreSQL |

`/api/live` remains successful when the database is unavailable. Use `/api/ready` for traffic admission and `/api/health` for operational status.

## Runtime configuration

Copy `frontend/.env.example` to `.env.local` for local development. Production secrets must be configured in the deployment environment and must not be committed to Git.

The template includes database, authentication, AI service, storage, logging, CORS, demo-mode, and air-gapped-mode variables.

## Validation

```powershell
Set-Location frontend
npm run build

Set-Location ../email-forensic-framework
pytest tests/phase31 tests/phase30/test_phase30_e2e.py -q
```

The remaining Phase 32 work should extend this foundation with durable audit storage, rate limiting, model health/fallback, worker reliability, backup/restore verification, and the SIH golden-path test.