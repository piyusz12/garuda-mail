import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { z } from 'zod';
import { listPublicKeys, registerPublicKey, getKeyAuditLog } from '@/lib/keyStore';

const registerKeySchema = z.object({
  encryptionPublicKey: z.string().min(64, 'Invalid public key format'),
  signingPublicKey: z.string().min(64, 'Invalid signing public key format').optional(),
});

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const audit = searchParams.get('audit') === 'true';

  if (audit) {
    const logs = getKeyAuditLog(50);
    return NextResponse.json({ auditLogs: logs });
  }

  const keys = listPublicKeys();
  return NextResponse.json({ keys });
}

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const validation = registerKeySchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
    }

    const { encryptionPublicKey, signingPublicKey } = validation.data;
    const clientIp = request.headers.get('x-forwarded-for') || '127.0.0.1';

    const result = registerPublicKey({
      userId: session.user.id,
      userEmail: session.user.email || 'user@garudamail.local',
      userName: session.user.name || 'Garuda User',
      encryptionPublicKey,
      signingPublicKey,
      clientIp,
    });

    return NextResponse.json({
      success: true,
      record: result.record,
      warning: result.warning,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: `Key registration failed: ${msg}` }, { status: 500 });
  }
}
