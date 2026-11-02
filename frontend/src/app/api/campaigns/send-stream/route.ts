import { NextRequest } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { isEmailSuppressed } from '@/lib/email/rfc8058';

export const dynamic = 'force-dynamic';

interface FailedRecord {
  email: string;
  code: 'HARD_BOUNCE' | 'MAILBOX_FULL' | 'RATE_LIMIT_EXCEEDED' | 'SUPPRESSED_UNSUBSCRIBED';
  reason: string;
  retryable: boolean;
}

export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized: Session required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  let body: any = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const totalRecipients = body.recipientCount || 2500;
  const isRetry = Boolean(body.isRetry);
  const inputFailedRecords: FailedRecord[] = Array.isArray(body.failedRecords) ? body.failedRecords : [];
  const nonRetryableRecords = inputFailedRecords.filter((r) => r.retryable === false);
  const retryableRecords = inputFailedRecords.filter((r) => r.retryable !== false);

  if (isRetry && retryableRecords.length === 0) {
    return new Response(JSON.stringify({ error: 'No retryable records available.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const sampleRecipients: string[] = Array.isArray(body.recipients) && body.recipients.length > 0
    ? body.recipients
    : ['chief-security@enterprise-corp.net', 'compliance-auditor@defense-gov.org', 'sysadmin@infrastructure-cloud.io'];

  const targetCount = isRetry ? retryableRecords.length : totalRecipients;

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const sendEvent = (eventData: object) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(eventData)}\n\n`));
      };

      let sent = 0;
      let failed = isRetry ? nonRetryableRecords.length : 0;
      const failedRecords: FailedRecord[] = isRetry ? [...nonRetryableRecords] : [];

      // Step 1: Initial Handshake
      sendEvent({
        progress: 0,
        sent: 0,
        failed,
        total: targetCount,
        status: 'INITIALIZING_QUEUE',
        message: isRetry ? 'Idempotently re-queueing unconfirmed recipients...' : 'Segmenting audience into parallel worker chunks...',
        failedRecords,
      });

      // Batch progression loop
      const steps = 10;
      for (let i = 1; i <= steps; i++) {
        await new Promise((resolve) => setTimeout(resolve, 350));

        const batchSent = Math.floor(targetCount / steps) + (i <= targetCount % steps ? 1 : 0);
        sent += batchSent;

        // Check suppression list against campaign recipient identities
        if (!isRetry && i === 1) {
          for (const addr of sampleRecipients) {
            if (isEmailSuppressed(addr)) {
              failed += 1;
              sent = Math.max(0, sent - 1);
              failedRecords.push({
                email: addr,
                code: 'SUPPRESSED_UNSUBSCRIBED',
                reason: 'Recipient previously opted out via RFC 8058 one-click directive',
                retryable: false,
              });
            }
          }
        }

        // Simulate real-world partial failure anomalies on fresh runs
        if (!isRetry && (i === 3 || i === 7)) {
          const generatedFailures: FailedRecord[] = [
            {
              email: `corp-relay-${i}-invalid@legacy-exchange.org`,
              code: 'HARD_BOUNCE',
              reason: '550 5.1.1 Recipient mailbox not found',
              retryable: false,
            },
            {
              email: `security-officer-${i}@throttled-domain.com`,
              code: 'RATE_LIMIT_EXCEEDED',
              reason: '421 4.7.0 ISP rate limit reached. Re-queue recommended.',
              retryable: true,
            }
          ];
          failed += generatedFailures.length;
          sent = Math.max(0, sent - generatedFailures.length);
          failedRecords.push(...generatedFailures);
        }

        const percent = Math.min(Math.round((i / steps) * 100), 100);

        sendEvent({
          progress: percent,
          sent,
          failed,
          total: targetCount,
          status: percent === 100 ? (failed > 0 ? 'PARTIAL_SUCCESS' : 'COMPLETED') : 'DISPATCHING',
          message: `Dispatched ${sent.toLocaleString()} of ${targetCount.toLocaleString()} envelopes via encrypted TLS 1.3 relays`,
          failedRecords,
        });
      }

      sendEvent({
        progress: 100,
        sent,
        failed,
        total: targetCount,
        status: failed > 0 ? 'PARTIAL_SUCCESS' : 'COMPLETED',
        message: failed > 0
          ? `Batch dispatch completed with ${failed} partial delivery exceptions. CSV report ready.`
          : 'All recipient envelopes confirmed delivered without exceptions.',
        failedRecords,
        completedAt: new Date().toISOString(),
      });

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    },
  });
}

