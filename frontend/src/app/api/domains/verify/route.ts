import { NextRequest, NextResponse } from 'next/server';
import { verifyDomainAuthentication } from '@/lib/dns/verifier';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { domain, selector = 'garuda' } = body;

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json(
        { error: 'Valid domain string is required' },
        { status: 400 }
      );
    }

    const verification = await verifyDomainAuthentication(domain, selector);
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

