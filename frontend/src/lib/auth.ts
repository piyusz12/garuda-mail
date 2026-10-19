import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { findUserByEmail, verifyUserPassword } from '@/lib/users';
import { normalizeUserRole } from '@/lib/roles';
import { logAuditEvent } from '@/lib/audit';

const authSecret = (() => {
  const s = process.env.NEXTAUTH_SECRET;
  if (!s && process.env.NODE_ENV === 'production') {
    console.error('[SECURITY WARNING] NEXTAUTH_SECRET is not configured for production. Please generate a strong 256-bit secret with: openssl rand -base64 32');
  }
  return s || 'garuda-mail-sovereign-production-secret-2026';
})();

export const authOptions: NextAuthOptions = {
  // Using JWT strategy without PrismaAdapter avoids runtime database errors on serverless environments
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },

  pages: {
    signIn: '/login',
    newUser: '/user/dashboard',
  },

  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials, req) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error('Email and password required');
        }

        const email = credentials.email.toLowerCase().trim();
        const cookieHeader = req?.headers?.cookie || null;

        const user = await findUserByEmail(email, cookieHeader);

        if (!user || !user.password) {
          await logAuditEvent({
            action: 'LOGIN_FAILURE',
            targetEmail: email,
            details: 'Account not found or password not configured',
            status: 'FAILURE',
          });
          throw new Error('Invalid email or password');
        }

        // Account status check: reject suspended or disabled accounts
        if (user.status === 'suspended' || user.status === 'disabled') {
          await logAuditEvent({
            action: 'LOGIN_BLOCKED_SUSPENDED',
            actorEmail: user.email,
            actorRole: user.role,
            targetEmail: user.email,
            details: `Account ${user.email} attempted login but status is ${user.status}`,
            status: 'FAILURE',
          });
          throw new Error('Account is suspended. Please contact system administrator.');
        }

        const passwordMatch = await verifyUserPassword(user, credentials.password);
        if (!passwordMatch) {
          await logAuditEvent({
            action: 'LOGIN_FAILURE',
            actorEmail: user.email,
            actorRole: user.role,
            targetEmail: user.email,
            details: 'Incorrect password supplied',
            status: 'FAILURE',
          });
          throw new Error('Invalid email or password');
        }

        await logAuditEvent({
          action: 'LOGIN_SUCCESS',
          actorEmail: user.email,
          actorRole: user.role,
          targetEmail: user.email,
          details: `User ${user.email} signed in successfully with role ${user.role}`,
          status: 'SUCCESS',
        });

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          image: null,
          role: user.role,
          status: user.status || 'active',
        };
      },
    }),
  ],

  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.role = normalizeUserRole(user.role);
        token.status = (user as any).status || 'active';
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = normalizeUserRole(token.role);
        (session.user as any).status = token.status || 'active';
      }
      return session;
    },
    async redirect({ url, baseUrl }) {
      const fallbackOrigin = 'http://localhost:3000';
      let origin = fallbackOrigin;

      try {
        origin = new URL(baseUrl || process.env.NEXTAUTH_URL || fallbackOrigin).origin;
      } catch {
        origin = fallbackOrigin;
      }

      if (!url) return `${origin}/user/dashboard`;

      try {
        const parsed = new URL(url, origin);
        if (parsed.origin !== origin) return `${origin}/user/dashboard`;
        const nextPath = parsed.pathname;
        if (nextPath.startsWith('/admin')) return `${origin}/admin/dashboard`;
        if (nextPath.startsWith('/user')) return `${origin}/user/dashboard`;
        return `${origin}/user/dashboard`;
      } catch {
        return `${origin}/user/dashboard`;
      }
    },
  },

  secret: authSecret,

  debug: process.env.NODE_ENV === 'development',
};

// Type augmentation
declare module 'next-auth' {
  interface User {
    role?: string;
    status?: string;
  }
  interface Session {
    user: {
      id: string;
      email: string;
      name?: string | null;
      image?: string | null;
      role?: string;
      status?: string;
    };
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    id: string;
    role?: string;
    status?: string;
  }
}
