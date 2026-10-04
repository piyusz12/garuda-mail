import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { SUPPORTED_PROTOCOLS, ProtocolType } from '@/lib/protocols';
import { verifySmtpConnection, verifyImapConnection } from '@/lib/mailer';
import os from 'os';

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Detect network interfaces to give the user their multi-PC connection URL
  const interfaces = os.networkInterfaces();
  const lanIps: string[] = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        lanIps.push(iface.address);
      }
    }
  }

  return NextResponse.json({
    protocols: Object.values(SUPPORTED_PROTOCOLS),
    lanIps,
    suggestedUrl: lanIps.length > 0 ? `http://${lanIps[0]}:3000` : 'http://localhost:3000',
    envSmtpConfigured: !!(process.env.SMTP_HOST || process.env.GMAIL_USER),
  });
}

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { action, config } = body;

    if (action === 'test-smtp') {
      const res = await verifySmtpConnection(config || {});
      return NextResponse.json(res);
    }

    if (action === 'test-imap') {
      const res = await verifyImapConnection({
        host: config?.host || 'imap.enterprise.local',
        port: config?.port || 993,
        user: config?.user || '',
        pass: config?.pass || '',
        protocol: config?.protocol || 'imap',
      });
      return NextResponse.json(res);
    }

    return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Operation failed' }, { status: 500 });
  }
}
