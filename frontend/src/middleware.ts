import { withAuth } from 'next-auth/middleware';
import { NextResponse } from 'next/server';

// Protect all routes except auth pages and API auth routes
export default withAuth(
  function middleware(req) {
    return NextResponse.next();
  },
  {
    callbacks: {
      authorized: ({ token }) => !!token,
    },
  }
);

export const config = {
  matcher: [
    /*
     * Match all request paths EXCEPT:
     * - /login (auth page)
     * - /register (auth page)
     * - /api/auth (NextAuth endpoints)
     * - /api/register (public registration)
     * - /_next (Next.js internals)
     * - /favicon.ico, /logo.png (static files)
     */
    '/((?!login|register|api/auth|api/register|_next|favicon\\.ico|logo\\.png).*)',
  ],
};
