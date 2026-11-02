import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { verifyDomainAuthentication } from '@/lib/dns/verifier';

const DOMAIN_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized: Session required' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { domain, selector = 'garuda' } = body;

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json(
        { error: 'Valid domain string is required' },
        { status: 400 }
      );
    }

    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!DOMAIN_REGEX.test(cleanDomain)) {
      return NextResponse.json(
        { error: 'Invalid domain format. Please provide a valid FQDN (e.g. example.com)' },
        { status: 400 }
      );
    }

    const verification = await verifyDomainAuthentication(cleanDomain, selector);
    return NextResponse.json({
      success: true,
      data: verification,
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'DNS verification failed';
    return NextResponse.json(
      { error: msg },
      { status: 500 }
    );
  }
}
