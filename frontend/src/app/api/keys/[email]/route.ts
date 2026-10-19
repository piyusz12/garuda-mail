import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { getPublicKey, getPeerTrust } from '@/lib/keyStore';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ email: string }> }
) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { email } = await params;
  if (!email) {
    return NextResponse.json({ error: 'Missing email parameter' }, { status: 400 });
  }

  const decodedEmail = decodeURIComponent(email);
  const keyRecord = getPublicKey(decodedEmail);

  if (!keyRecord) {
    return NextResponse.json({ error: 'Public key not found for specified user' }, { status: 404 });
  }

  const currentEmail = session.user.email || '';
  const trust = getPeerTrust(currentEmail, decodedEmail);

  return NextResponse.json({
    publicKey: keyRecord,
    trust: trust || {
      ownerEmail: currentEmail,
      peerEmail: decodedEmail,
      trustedFingerprint: keyRecord.fingerprint,
      isVerified: false,
      warningFlag: false,
    },
  });
}
