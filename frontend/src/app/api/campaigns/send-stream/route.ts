import { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';

interface FailedRecord {
  email: string;
  code: 'HARD_BOUNCE' | 'MAILBOX_FULL' | 'RATE_LIMIT_EXCEEDED' | 'SUPPRESSED_UNSUBSCRIBED';
  reason: string;
  retryable: boolean;
}

export async function POST(req: NextRequest) {
  let body: any = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const totalRecipients = body.recipientCount || 2500;
  const isRetry = Boolean(body.isRetry);
  const previousFailedCount = body.failedRecords?.length || 38;

  const targetCount = isRetry ? previousFailedCount : totalRecipients;

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const sendEvent = (eventData: object) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(eventData)}\n\n`));
      };

      let sent = 0;
      let failed = 0;
      const failedRecords: FailedRecord[] = [];

      // Step 1: Initial Handshake
      sendEvent({
        progress: 0,
        sent: 0,
        failed: 0,
        total: targetCount,
        status: 'INITIALIZING_QUEUE',
        message: isRetry ? 'Idempotently re-queueing unconfirmed recipients...' : 'Segmenting audience into parallel worker chunks...',
        failedRecords: [],
      });

      // Batch progression loop
      const steps = 10;
      for (let i = 1; i <= steps; i++) {
        await new Promise((resolve) => setTimeout(resolve, 350));

        const batchSent = Math.floor(targetCount / steps);
        sent += batchSent;

        // Simulate real-world partial failure anomalies on fresh runs
        if (!isRetry && (i === 3 || i === 7)) {
          const failBatchCount = i === 3 ? 12 : 8;
          failed += failBatchCount;
          sent -= failBatchCount;
          failedRecords.push(
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
          );
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

