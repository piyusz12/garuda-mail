import { NextRequest, NextResponse } from 'next/server';
import { verifyUnsubscribeToken, suppressEmail, isEmailSuppressed, unsuppressEmail } from '@/lib/email/rfc8058';

/**
 * RFC 8058 One-Click Unsubscribe Handler
 * POST /api/unsubscribe/[token]
 * Mandated by Google/Yahoo to complete and return HTTP 200 within 2 seconds.
 */
export async function POST(
  req: NextRequest,
  context: { params: Promise<{ token: string }> }
) {
  const startTime = Date.now();
  const { token } = await context.params;

  if (!token) {
    return NextResponse.json(
      { error: 'Missing unsubscribe token' },
      { status: 400 }
    );
  }

  const payload = verifyUnsubscribeToken(token);
  if (!payload) {
    return NextResponse.json(
      { error: 'Invalid or forged unsubscribe signature' },
      { status: 403 }
    );
  }

  // Register in global suppression set immediately (< 1ms execution)
  suppressEmail(payload.email);

  const durationMs = Date.now() - startTime;

  return NextResponse.json(
    {
      success: true,
      message: 'Unsubscribed successfully under RFC 8058 one-click protocol',
      email: payload.email,
      campaignId: payload.campaignId,
      executionDurationMs: durationMs,
      timestamp: new Date().toISOString(),
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    }
  );
}

/**
 * GET /api/unsubscribe/[token]
 * Browser-based manual link check
 */
export async function GET(
  req: NextRequest,
  context: { params: Promise<{ token: string }> }
) {
  const { token } = await context.params;

  if (!token) {
    return NextResponse.json({ error: 'Missing token' }, { status: 400 });
  }

  const payload = verifyUnsubscribeToken(token);
  if (!payload) {
    return NextResponse.json({ error: 'Invalid or expired token' }, { status: 403 });
  }

  return NextResponse.json({
    valid: true,
    email: payload.email,
    campaignId: payload.campaignId,
    isSuppressed: isEmailSuppressed(payload.email),
  });
}

/**
 * PATCH /api/unsubscribe/[token]
 * Resubscribe recovery endpoint (for accidental opt-outs)
 */
export async function PATCH(
  req: NextRequest,
  context: { params: Promise<{ token: string }> }
) {
  const { token } = await context.params;
  const payload = verifyUnsubscribeToken(token);

  if (!payload) {
    return NextResponse.json({ error: 'Invalid token' }, { status: 403 });
  }

  unsuppressEmail(payload.email);

  return NextResponse.json({
    success: true,
    message: 'Subscription restored successfully',
    email: payload.email,
  });
}

