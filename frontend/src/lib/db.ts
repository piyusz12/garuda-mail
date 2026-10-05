import { PrismaClient } from '@prisma/client';

const databaseUrl = process.env.DATABASE_URL || (process.env.VERCEL ? 'file:/tmp/dev.db' : 'file:./dev.db');

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

const prisma =
  global.prisma ||
  new PrismaClient({
    datasourceUrl: databaseUrl,
    log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
  });

if (process.env.NODE_ENV !== 'production') {
  global.prisma = prisma;
}

export { prisma };
export default prisma;
