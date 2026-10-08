import { getToken } from 'next-auth/jwt';
import { NextRequest, NextResponse } from 'next/server';

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const isAdminRoute = pathname === '/admin' || pathname.startsWith('/admin/');
  const isOfficerRoute = pathname === '/officer' || pathname.startsWith('/officer/');

  // Allow public routes and static assets
  if (
    pathname.startsWith('/login') ||
    pathname.startsWith('/register') ||
    pathname.startsWith('/api/auth') ||
    pathname.startsWith('/api/register') ||
    pathname.startsWith('/api/health') ||
      pathname.startsWith('/api/live') ||
      pathname.startsWith('/api/ready') ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/rootCA.pem') ||
    pathname.includes('.')
  ) {
    return NextResponse.next();
  }

  // Verify JWT session token safely
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET || 'garuda-mail-super-secret-production-jwt-2026-key',
  });

  if (!token) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = '/login';
    loginUrl.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }

  const role = String((token as any)?.role || 'user').toLowerCase();

  if (isAdminRoute && role !== 'admin') {
    const deniedUrl = req.nextUrl.clone();
    deniedUrl.pathname = '/login';
    deniedUrl.searchParams.set('callbackUrl', pathname);
    deniedUrl.searchParams.set('error', 'admin_required');
    return NextResponse.redirect(deniedUrl);
  }

  if (isOfficerRoute && role !== 'officer' && role !== 'admin') {
    const deniedUrl = req.nextUrl.clone();
    deniedUrl.pathname = '/login';
    deniedUrl.searchParams.set('callbackUrl', pathname);
    deniedUrl.searchParams.set('error', 'officer_required');
    return NextResponse.redirect(deniedUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
      '/((?!login|register|api/auth|api/register|api/health|api/live|api/ready|_next|static|favicon\\.ico|rootCA\\.pem).*)',
  ],
};
