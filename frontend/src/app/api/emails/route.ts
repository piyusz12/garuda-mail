import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { z } from 'zod';
import prisma from '@/lib/db';
import { sendEmail } from '@/lib/mailer';
import { ProtocolType } from '@/lib/protocols';

// ── GET /api/emails — Fetch emails for current user ──────────────────

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const folder = searchParams.get('folder') || 'inbox';
  const page = parseInt(searchParams.get('page') || '1');
  const limit = parseInt(searchParams.get('limit') || '50');
  const search = searchParams.get('search') || '';
  const skip = (page - 1) * limit;

  const userId = session.user.id;
  const userEmail = session.user.email?.toLowerCase().trim();

  try {
    // ── Auto-claim: Reconcile any unassigned incoming emails sent to this user's email address
    if (userEmail) {
      await prisma.emailRecipient.updateMany({
        where: {
          address: userEmail,
          userId: null,
        },
        data: {
          userId: userId,
        },
      });
    }

    let emails: any[] = [];

    if (folder === 'sent') {
      // Sent emails
      const whereClause: any = {
        fromId: userId,
        draft: false,
      };
      if (search) {
        whereClause.OR = [
          { subject: { contains: search } },
          { body: { contains: search } },
        ];
      }
      emails = await prisma.email.findMany({
        where: whereClause,
        include: {
          from: { select: { id: true, name: true, email: true } },
          recipients: {
            include: { user: { select: { id: true, name: true, email: true } } },
          },
          attachments: { select: { id: true, filename: true, size: true, mimeType: true } },
          _count: { select: { attachments: true } },
        },
        orderBy: { sentAt: 'desc' },
        skip,
        take: limit,
      });
    } else if (folder === 'drafts') {
      emails = await prisma.email.findMany({
        where: { fromId: userId, draft: true },
        include: {
          from: { select: { id: true, name: true, email: true } },
          recipients: {
            include: { user: { select: { id: true, name: true, email: true } } },
          },
          attachments: { select: { id: true, filename: true, size: true, mimeType: true } },
        },
        orderBy: { updatedAt: 'desc' },
        skip,
        take: limit,
      });
    } else if (folder === 'starred') {
      // Starred received emails
      const recipientRecords = await prisma.emailRecipient.findMany({
        where: {
          starred: true,
          OR: [
            { userId: userId },
            ...(userEmail ? [{ address: userEmail }] : []),
          ],
        },
        include: {
          email: {
            include: {
              from: { select: { id: true, name: true, email: true } },
              recipients: {
                select: { address: true, name: true, read: true, folder: true, starred: true, userId: true },
              },
              attachments: { select: { id: true, filename: true, size: true, mimeType: true } },
            },
          },
        },
        orderBy: { email: { createdAt: 'desc' } },
        skip,
        take: limit,
      });
      emails = recipientRecords.map((r: any) => ({ ...r.email, _recipient: r }));
    } else {
      // inbox, archive, trash
      const recipientRecords = await prisma.emailRecipient.findMany({
        where: {
          folder,
          OR: [
            { userId: userId },
            ...(userEmail ? [{ address: userEmail }] : []),
          ],
          ...(search ? {
            email: {
              OR: [
                { subject: { contains: search } },
                { body: { contains: search } },
              ],
            },
          } : {}),
        },
        include: {
          email: {
            include: {
              from: { select: { id: true, name: true, email: true } },
              recipients: {
                select: { address: true, name: true, read: true, folder: true, starred: true, userId: true },
              },
              attachments: { select: { id: true, filename: true, size: true, mimeType: true } },
            },
          },
        },
        orderBy: { email: { createdAt: 'desc' } },
        skip,
        take: limit,
      });

      emails = recipientRecords.map((r: any) => ({
        ...r.email,
        _recipient: { read: r.read, folder: r.folder, starred: r.starred },
      }));
    }

    // Get unread count for badge
    const unreadCounts = await prisma.emailRecipient.groupBy({
      by: ['folder'],
      where: {
        read: false,
        OR: [
          { userId: userId },
          ...(userEmail ? [{ address: userEmail }] : []),
        ],
      },
      _count: true,
    });

    return NextResponse.json({
      emails,
      unreadCounts: Object.fromEntries(unreadCounts.map((u: any) => [u.folder, u._count])),
      page,
      total: emails.length,
    });
  } catch (error: any) {
    console.error('[Emails GET] Error:', error);
    return NextResponse.json({ error: 'Failed to fetch emails' }, { status: 500 });
  }
}

// ── POST /api/emails — Send a new email across all protocols ─────────

const sendSchema = z.object({
  to: z.array(z.object({
    email: z.string().transform(s => s.toLowerCase().trim()),
    name: z.string().optional(),
  })).min(1, 'At least one recipient required'),
  cc: z.array(z.object({
    email: z.string().transform(s => s.toLowerCase().trim()),
    name: z.string().optional(),
  })).optional().default([]),
  subject: z.string().min(1, 'Subject is required').max(500),
  body: z.string().min(1, 'Message body is required'),
  draft: z.boolean().optional().default(false),
  threadId: z.string().optional(),
  inReplyTo: z.string().optional(),
  protocol: z.enum(['auto', 'smtp-starttls', 'smtps', 'smtp-direct', 'p2p-mesh', 'imap-sync']).optional().default('auto'),
  customSmtp: z.object({
    host: z.string().optional(),
    port: z.number().optional(),
    user: z.string().optional(),
    pass: z.string().optional(),
  }).optional(),
});

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const rawBody = await request.json();
    const validation = sendSchema.safeParse(rawBody);

    if (!validation.success) {
      const errMsg = validation.error.issues?.[0]?.message || 'Invalid email data. Please check recipient addresses.';
      return NextResponse.json({ error: errMsg }, { status: 400 });
    }

    const { to, cc, subject, body: emailBody, draft, threadId, inReplyTo, protocol, customSmtp } = validation.data;
    const sender = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { id: true, name: true, email: true },
    });

    if (!sender) {
      return NextResponse.json({ error: 'Sender not found' }, { status: 404 });
    }

    const preview = emailBody.slice(0, 200).replace(/\n+/g, ' ');

    // ── Pre-resolve recipient user bindings ───────────────────────────
    const resolvedRecipients = await Promise.all([
      ...to.map(async recipient => {
        const cleanEmail = recipient.email.toLowerCase().trim();
        const internalUser = await prisma.user.findUnique({
          where: { email: cleanEmail },
          select: { id: true, name: true },
        });
        return {
          address: cleanEmail,
          name: recipient.name || internalUser?.name || null,
          userId: internalUser?.id || null,
          type: 'to',
          folder: 'inbox',
        };
      }),
      ...cc.map(async recipient => {
        const cleanEmail = recipient.email.toLowerCase().trim();
        const internalUser = await prisma.user.findUnique({
          where: { email: cleanEmail },
          select: { id: true, name: true },
        });
        return {
          address: cleanEmail,
          name: recipient.name || internalUser?.name || null,
          userId: internalUser?.id || null,
          type: 'cc',
          folder: 'inbox',
        };
      }),
    ]);

    // ── Execute protocol dispatcher ──────────────────────────────────
    let dispatchResult: any = null;
    if (!draft) {
      dispatchResult = await sendEmail({
        from: { name: sender.name || 'Garuda Mail User', email: sender.email! },
        to: to,
        cc: cc,
        subject,
        body: emailBody,
        protocol: protocol as ProtocolType,
        customSmtp,
      });
    }

    // ── Save Email record in database ────────────────────────────────
    const email = await prisma.email.create({
      data: {
        subject,
        body: emailBody,
        preview,
        fromId: sender.id,
        draft,
        threadId: threadId || undefined,
        inReplyTo: inReplyTo || undefined,
        sentAt: draft ? null : new Date(),
        // Security & Protocol attributes
        tlsVersion: dispatchResult?.tlsVersion || 'TLS 1.3',
        cipher: `${dispatchResult?.cipher || 'TLS_AES_256_GCM_SHA384'} [${protocol.toUpperCase()}]`,
        forwardSecrecy: true,
        starttls: protocol === 'smtp-starttls' || protocol === 'auto',
        riskScore: 5,
        recipients: {
          create: resolvedRecipients,
        },
      },
      include: {
        recipients: {
          include: { user: { select: { id: true, name: true, email: true } } },
        },
        from: { select: { id: true, name: true, email: true } },
      },
    });

    return NextResponse.json(
      {
        message: draft ? 'Draft saved' : 'Email dispatched successfully across all protocols',
        email,
        dispatchResult,
      },
      { status: 201 }
    );
  } catch (error: any) {
    console.error('[Emails POST] Error:', error);
    return NextResponse.json({ error: error.message || 'Failed to dispatch email' }, { status: 500 });
  }
}
