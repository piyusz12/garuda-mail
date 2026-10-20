# Garuda Mail — Enterprise Frontend

The Next.js enterprise web interface for **Garuda Mail (SIH26159)**, providing sovereign email operations, forensic PCAP visualization, zero-trust RBAC governance, and end-to-end cryptographic key management.

## Tech Stack

- **Framework**: Next.js 16 (App Router) + React 19 + TypeScript
- **Styling**: Tailwind CSS + Framer Motion
- **ORM & Database**: Prisma with SQLite (local dev) / PostgreSQL (production)
- **Authentication**: NextAuth.js (JWT session tokens with RBAC)
- **Cryptography**: Web Crypto API & Node.js Crypto (RSA-OAEP, RSA-PSS, AES-256-GCM, SHA-256)
- **Data Visualization**: Recharts, @xyflow/react, Cytoscape

## Getting Started

From the `frontend/` directory:

```bash
# 1. Install dependencies
npm install

# 2. Generate Prisma Client & seed development database
npx prisma db push
node prisma/seed.js

# 3. Start local development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to access the console.

## Testing & Quality

From the repository root:

```bash
# Run all test suites (Pytest + Crypto + Audit + RBAC)
python run.py test-all

# Or run frontend-specific suites
python run.py test-crypto
python run.py test-audit
python run.py test-rbac
```
