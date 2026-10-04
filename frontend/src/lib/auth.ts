import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { PrismaAdapter } from '@next-auth/prisma-adapter';
import bcrypt from 'bcryptjs';
import prisma from '@/lib/db';

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },

  pages: {
    signIn: '/login',
    newUser: '/inbox',
  },

  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error('Email and password required');
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email.toLowerCase().trim() },
        });

        if (!user || !user.password) {
          throw new Error('Invalid email or password');
        }

        const passwordMatch = await bcrypt.compare(credentials.password, user.password);
        if (!passwordMatch) {
          throw new Error('Invalid email or password');
        }

        return {
          id: user.id,
          email: user.email!,
          name: user.name,
          image: user.image,
          role: user.role,
        };
      },
    }),
  ],

  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.role = (user as any).role;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string;
        (session.user as any).role = token.role;
      }
      return session;
    },
    async redirect({ url, baseUrl }) {
      if (!url) return '/inbox';
      if (url.startsWith('/')) return url;
      try {
        const base = baseUrl || process.env.NEXTAUTH_URL || 'http://localhost:3000';
        const parsed = new URL(url, base);
        return parsed.pathname + parsed.search;
      } catch {
        return '/inbox';
      }
    },
  },

  secret: process.env.NEXTAUTH_SECRET || 'garuda-mail-super-secret-production-jwt-2026-key',

  debug: process.env.NODE_ENV === 'development',
};

// Type augmentation
declare module 'next-auth' {
  interface User {
    role?: string;
  }
  interface Session {
    user: {
      id: string;
      email: string;
      name?: string | null;
      image?: string | null;
      role?: string;
    };
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    id: string;
    role?: string;
  }
}
