import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import prisma from '@/lib/db';

type Params = { params: Promise<{ id: string }> };

// ── GET /api/emails/[id] — Fetch single email ────────────────────────

export async function GET(request: NextRequest, { params }: Params) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  try {
    const email = await prisma.email.findFirst({
      where: {
        id,
        OR: [
          { fromId: session.user.id },
          { recipients: { some: { userId: session.user.id } } },
        ],
      },
      include: {
        from: { select: { id: true, name: true, email: true, avatarColor: true } },
        recipients: {
          include: {
            user: { select: { id: true, name: true, email: true } },
          },
        },
        attachments: true,
      },
    });

    if (!email) {
      return NextResponse.json({ error: 'Email not found' }, { status: 404 });
    }

    // Mark as read for this user
    await prisma.emailRecipient.updateMany({
      where: { emailId: id, userId: session.user.id, read: false },
      data: { read: true, readAt: new Date() },
    });

    return NextResponse.json({ email });
  } catch (error: any) {
    console.error('[Email GET] Error:', error);
    return NextResponse.json({ error: 'Failed to fetch email' }, { status: 500 });
  }
}

// ── PATCH /api/emails/[id] — Update email (read, star, move folder) ──

export async function PATCH(request: NextRequest, { params }: Params) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;
  const body = await request.json();
  const { read, starred, folder } = body;

  try {
    const updates: any = {};
    if (read !== undefined) updates.read = read;
    if (starred !== undefined) updates.starred = starred;
    if (folder !== undefined) updates.folder = folder;

    await prisma.emailRecipient.updateMany({
      where: { emailId: id, userId: session.user.id },
      data: updates,
    });

    return NextResponse.json({ message: 'Updated' });
  } catch (error: any) {
    console.error('[Email PATCH] Error:', error);
    return NextResponse.json({ error: 'Failed to update email' }, { status: 500 });
  }
}

// ── DELETE /api/emails/[id] — Delete email (move to trash or permanent) ──

export async function DELETE(request: NextRequest, { params }: Params) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;
  const { searchParams } = new URL(request.url);
  const permanent = searchParams.get('permanent') === 'true';

  try {
    if (permanent) {
      // Check if user owns this email
      const recipientRecord = await prisma.emailRecipient.findFirst({
        where: { emailId: id, userId: session.user.id, folder: 'trash' },
      });
      if (recipientRecord) {
        await prisma.emailRecipient.deleteMany({
          where: { emailId: id, userId: session.user.id },
        });
      }
    } else {
      // Move to trash
      await prisma.emailRecipient.updateMany({
        where: { emailId: id, userId: session.user.id },
        data: { folder: 'trash' },
      });
    }

    return NextResponse.json({ message: permanent ? 'Deleted permanently' : 'Moved to trash' });
  } catch (error: any) {
    console.error('[Email DELETE] Error:', error);
    return NextResponse.json({ error: 'Failed to delete email' }, { status: 500 });
  }
}
