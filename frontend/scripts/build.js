const { execSync } = require('child_process');
const path = require('path');

const frontendDir = path.resolve(__dirname, '..');

// 1. Ensure DATABASE_URL is set so prisma generate never crashes on Vercel
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/garuda_mail?schema=public';
}

// Ensure AUTH_TRUST_HOST is set for the deployment runtime.
process.env.AUTH_TRUST_HOST = 'true';

console.log('[Build] Ensuring Prisma Client is generated...');
try {
  execSync('npx prisma generate', {
    cwd: frontendDir,
    stdio: 'inherit',
    env: { ...process.env, DATABASE_URL: process.env.DATABASE_URL },
  });
} catch (e) {
  console.warn('[Build] Prisma generate warning (proceeding with Next.js build):', e.message);
}

console.log('[Build] Building Next.js production bundle...');
execSync('npx next build', {
  cwd: frontendDir,
  stdio: 'inherit',
  env: process.env,
});
console.log('[Build] Build completed successfully!');
