import { getToken } from 'next-auth/jwt';
import { NextRequest, NextResponse } from 'next/server';

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Allow public routes and static assets
  if (
    pathname.startsWith('/login') ||
    pathname.startsWith('/register') ||
    pathname.startsWith('/api/auth') ||
    pathname.startsWith('/api/register') ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/rootCA.pem') ||
    pathname.includes('.') // static files like favicon.ico, images, certs
  ) {
    return NextResponse.next();
  }

  // Verify JWT session token safely
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET || 'garuda-mail-super-secret-production-jwt-2026-key',
  });

  if (!token) {
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = '/login';
    loginUrl.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!login|register|api/auth|api/register|_next|static|favicon\\.ico|rootCA\\.pem).*)',
  ],
};
