import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { z } from 'zod';
import { setPeerTrust, getPeerTrust } from '@/lib/keyStore';

const verifyPeerSchema = z.object({
  peerEmail: z.string().email(),
  verified: z.boolean(),
});

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id || !session?.user?.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const validation = verifyPeerSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
    }

    const { peerEmail, verified } = validation.data;
    const result = setPeerTrust(session.user.email, peerEmail, verified);

    return NextResponse.json({
      success: true,
      trust: result,
      message: verified ? `Successfully marked ${peerEmail} as verified peer.` : `Untrusted ${peerEmail}.`,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: `Verification update failed: ${msg}` }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const peerEmail = searchParams.get('peerEmail');

  if (!peerEmail) {
    return NextResponse.json({ error: 'Missing peerEmail parameter' }, { status: 400 });
  }

  const trust = getPeerTrust(session.user.email, peerEmail);
  return NextResponse.json({ trust });
}
