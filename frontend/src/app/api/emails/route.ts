import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { z } from 'zod';
import prisma from '@/lib/db';
import { sendEmail } from '@/lib/mailer';

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

  try {
    let emails: any[] = [];
    const userId = session.user.id;

    if (folder === 'sent') {
      // Emails sent by this user
      const whereClause: any = {
        fromId: userId,
        draft: false,
      };
      if (search) {
        whereClause.OR = [
          { subject: { contains: search, mode: 'insensitive' } },
          { body: { contains: search, mode: 'insensitive' } },
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
      // Starred emails (received)
      const recipientRecords = await prisma.emailRecipient.findMany({
        where: { userId, starred: true },
        include: {
          email: {
            include: {
              from: { select: { id: true, name: true, email: true } },
              recipients: {
                where: { userId },
                select: { read: true, folder: true, starred: true },
              },
              attachments: { select: { id: true, filename: true, size: true, mimeType: true } },
            },
          },
        },
        orderBy: { email: { createdAt: 'desc' } },
        skip,
        take: limit,
      });
      emails = recipientRecords.map(r => ({ ...r.email, _recipient: r }));
    } else {
      // inbox, archive, trash
      const whereClause: any = {
        userId,
        folder,
      };
      if (search) {
        whereClause.email = {
          OR: [
            { subject: { contains: search, mode: 'insensitive' } },
            { body: { contains: search, mode: 'insensitive' } },
          ],
        };
      }
      const recipientRecords = await prisma.emailRecipient.findMany({
        where: whereClause,
        include: {
          email: {
            include: {
              from: { select: { id: true, name: true, email: true } },
              recipients: {
                where: { userId },
                select: { read: true, folder: true, starred: true },
              },
              attachments: { select: { id: true, filename: true, size: true, mimeType: true } },
            },
          },
        },
        orderBy: { email: { createdAt: 'desc' } },
        skip,
        take: limit,
      });
      emails = recipientRecords.map(r => ({
        ...r.email,
        _recipient: { read: r.read, folder: r.folder, starred: r.starred },
      }));
    }

    // Get unread counts
    const unreadCounts = await prisma.emailRecipient.groupBy({
      by: ['folder'],
      where: { userId, read: false },
      _count: true,
    });

    return NextResponse.json({
      emails,
      unreadCounts: Object.fromEntries(unreadCounts.map(u => [u.folder, u._count])),
      page,
      total: emails.length,
    });
  } catch (error: any) {
    console.error('[Emails GET] Error:', error);
    return NextResponse.json({ error: 'Failed to fetch emails' }, { status: 500 });
  }
}

// ── POST /api/emails — Send a new email ──────────────────────────────

const sendSchema = z.object({
  to: z.array(z.object({
    email: z.string().email(),
    name: z.string().optional(),
  })).min(1, 'At least one recipient required'),
  cc: z.array(z.object({
    email: z.string().email(),
    name: z.string().optional(),
  })).optional().default([]),
  subject: z.string().min(1, 'Subject is required').max(500),
  body: z.string().min(1, 'Message body is required'),
  draft: z.boolean().optional().default(false),
  threadId: z.string().optional(),
  inReplyTo: z.string().optional(),
});

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const validation = sendSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error.errors[0].message },
        { status: 400 }
      );
    }

    const { to, cc, subject, body: emailBody, draft, threadId, inReplyTo } = validation.data;
    const sender = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { id: true, name: true, email: true },
    });

    if (!sender) {
      return NextResponse.json({ error: 'Sender not found' }, { status: 404 });
    }

    const preview = emailBody.slice(0, 200).replace(/\n+/g, ' ');

    // Create email in database
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
        recipients: {
          create: [
            ...to.map(recipient => ({
              address: recipient.email,
              name: recipient.name || null,
              type: 'to',
              folder: 'inbox',
              // Link to internal user if exists
            })),
            ...cc.map(recipient => ({
              address: recipient.email,
              name: recipient.name || null,
              type: 'cc',
              folder: 'inbox',
            })),
          ],
        },
      },
      include: {
        recipients: true,
        from: { select: { id: true, name: true, email: true } },
      },
    });

    // For internal users — link recipient records to their user accounts
    const allRecipients = [...to, ...cc];
    for (const recipient of allRecipients) {
      const internalUser = await prisma.user.findUnique({
        where: { email: recipient.email.toLowerCase() },
      });
      if (internalUser) {
        await prisma.emailRecipient.updateMany({
          where: { emailId: email.id, address: recipient.email },
          data: { userId: internalUser.id },
        });
      }
    }

    // Send real email via SMTP if not a draft
    if (!draft) {
      const externalRecipients = to.filter(r => !r.email.endsWith('@' + (sender.email?.split('@')[1] || 'internal')));
      if (externalRecipients.length > 0 && process.env.GMAIL_USER) {
        await sendEmail({
          from: { name: sender.name || 'Garuda Mail User', email: sender.email! },
          to: to,
          cc: cc.length > 0 ? cc : undefined,
          subject,
          body: emailBody,
        });
      }
    }

    return NextResponse.json(
      { message: draft ? 'Draft saved' : 'Email sent', email },
      { status: 201 }
    );
  } catch (error: any) {
    console.error('[Emails POST] Error:', error);
    return NextResponse.json({ error: 'Failed to send email' }, { status: 500 });
  }
}
