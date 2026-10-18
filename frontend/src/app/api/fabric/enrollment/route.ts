import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import {
  listEnrollmentRequests,
  submitEnrollmentRequest,
  approveEnrollment,
  rejectEnrollment,
} from '@/lib/fabric/node-registry';

const newEnrollmentSchema = z.object({
  hostname: z.string().min(1).max(80),
  ipAddress: z.string().min(1).max(50),
  role: z.enum(['WORKER_GPU', 'WORKER_CPU', 'STORAGE_RAG', 'GATEWAY']),
  advertisedGpu: z.string().min(1).max(80),
  advertisedVramGb: z.number().min(0),
  advertisedRamGb: z.number().min(0),
  advertisedCapabilities: z.array(z.string()).min(1),
  requestedZone: z.enum(['RESTRICTED_AI', 'INTERNAL_AI', 'GENERAL_AI', 'STORAGE_NET']),
});

const reviewEnrollmentSchema = z.object({
  action: z.enum(['approve', 'reject']),
  requestId: z.string().min(1),
  reason: z.string().optional(),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const requests = listEnrollmentRequests();
  return NextResponse.json({ requests, count: requests.length });
}

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await request.json().catch(() => null);

  // If review action (approve/reject)
  if (body?.action) {
    const role = (session.user as { role?: string }).role;
    if (role !== 'admin') {
      return NextResponse.json({ error: 'Administrator access required for enrollment approval' }, { status: 403 });
    }

    const parsed = reviewEnrollmentSchema.safeParse(body);
    if (!parsed.success) return NextResponse.json({ error: 'Invalid review payload' }, { status: 400 });

    if (parsed.data.action === 'approve') {
      const node = approveEnrollment(parsed.data.requestId, session.user.email || 'admin');
      if (!node) return NextResponse.json({ error: 'Request not found or not pending' }, { status: 404 });
      return NextResponse.json({ success: true, node });
    } else {
      const rejected = rejectEnrollment(parsed.data.requestId, parsed.data.reason || 'Rejected by admin');
      if (!rejected) return NextResponse.json({ error: 'Request not found' }, { status: 404 });
      return NextResponse.json({ success: true, request: rejected });
    }
  }

  // Otherwise, submit new enrollment request
  const parsed = newEnrollmentSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: 'Invalid enrollment request payload' }, { status: 400 });

  const req = submitEnrollmentRequest(parsed.data);
  return NextResponse.json({ success: true, request: req }, { status: 201 });
}
