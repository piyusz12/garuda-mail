import { PrismaClient } from '@prisma/client';

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

function createUnavailablePrisma(): PrismaClient {
  return new Proxy({} as PrismaClient, {
    get() {
      throw new Error('Prisma database is not configured');
    },
  });
}

const prisma =
  global.prisma ||
  (process.env.DATABASE_URL
    ? new PrismaClient({
        log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
      })
    : createUnavailablePrisma());

if (process.env.NODE_ENV !== 'production') {
  global.prisma = prisma;
}

export { prisma };
export default prisma;
