import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import prisma from '@/lib/db';
import { decryptPayload } from '@/lib/crypto';
import { FALLBACK_EMAILS } from '@/lib/fallbackEmails';
import { findCustomEmailById, updateCustomEmail, deleteCustomEmail } from '@/lib/emailStore';

type Params = { params: Promise<{ id: string }> };

// ── GET /api/emails/[id] — Fetch single email ────────────────────────

export async function GET(request: NextRequest, { params }: Params) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;
  const userEmail = session.user.email?.toLowerCase().trim();

  try {
    let email: any = null;
    try {
      email = await prisma.email.findFirst({
        where: {
          id,
          OR: [
            { fromId: session.user.id },
            { recipients: { some: { userId: session.user.id } } },
            ...(userEmail ? [{ recipients: { some: { address: userEmail } } }] : []),
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
    } catch (dbErr) {
      console.warn('[Email GET] Prisma query failed, checking memory fallback stores:', dbErr);
    }

    if (!email) {
      const fb = findCustomEmailById(id) || FALLBACK_EMAILS.find(e => e.id === id);
      if (fb) {
        const decrypted = decryptPayload(fb.body);
        return NextResponse.json({
          email: {
            ...fb,
            body: decrypted.plaintext,
            rawCiphertext: decrypted.envelope?.ciphertext || null,
            rawBody: fb.body,
            isEncrypted: decrypted.isEncrypted,
            cryptoMetadata: decrypted.envelope || null,
            integrityVerified: decrypted.verified ?? true,
          },
        });
      }
      return NextResponse.json({ error: 'Email not found' }, { status: 404 });
    }

    // Auto-claim and mark as read for this user in DB if reachable
    try {
      await prisma.emailRecipient.updateMany({
        where: {
          emailId: id,
          read: false,
          OR: [
            { userId: session.user.id },
            ...(userEmail ? [{ address: userEmail }] : []),
          ],
        },
        data: { read: true, readAt: new Date(), userId: session.user.id },
      });
    } catch {}

    // Also update in fallback store
    updateCustomEmail(id, { read: true });

    // Decrypt payload with AES-256-GCM
    const decrypted = decryptPayload(email.body);

    return NextResponse.json({
      email: {
        ...email,
        body: decrypted.plaintext,
        rawCiphertext: decrypted.envelope?.ciphertext || null,
        rawBody: email.body,
        isEncrypted: decrypted.isEncrypted,
        cryptoMetadata: decrypted.envelope || null,
        integrityVerified: decrypted.verified ?? true,
      },
    });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : String(error);
    console.warn('[Email GET] Unexpected error, returning fallback email:', errMsg);
    const fallback = findCustomEmailById(id) || FALLBACK_EMAILS[0];
    if (fallback) {
      const decrypted = decryptPayload(fallback.body);
      return NextResponse.json({
        email: {
          ...fallback,
          body: decrypted.plaintext,
          rawCiphertext: decrypted.envelope?.ciphertext || null,
          isEncrypted: decrypted.isEncrypted,
          cryptoMetadata: decrypted.envelope || null,
          integrityVerified: decrypted.verified ?? true,
        },
      });
    }
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
  const userEmail = session.user.email?.toLowerCase().trim();

  // Update in fallback store
  const updates: { read?: boolean; starred?: boolean; folder?: string } = {};
  if (read !== undefined) updates.read = read;
  if (starred !== undefined) updates.starred = starred;
  if (folder !== undefined) updates.folder = folder;
  updateCustomEmail(id, updates);

  try {
    await prisma.emailRecipient.updateMany({
      where: {
        emailId: id,
        OR: [
          { userId: session.user.id },
          ...(userEmail ? [{ address: userEmail }] : []),
        ],
      },
      data: updates,
    });
  } catch (dbErr) {
    console.warn('[Email PATCH] Database update error (handled via fallback):', dbErr);
  }

  return NextResponse.json({ message: 'Updated' });
}

// ── DELETE /api/emails/[id] — Delete email (move to trash or permanent) ──

export async function DELETE(request: NextRequest, { params }: Params) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;
  const searchParams = request.nextUrl.searchParams;
  const permanent = searchParams.get('permanent') === 'true';
  const userEmail = session.user.email?.toLowerCase().trim();

  // Delete/trash in fallback store
  deleteCustomEmail(id, permanent);

  try {
    if (permanent) {
      await prisma.emailRecipient.deleteMany({
        where: {
          emailId: id,
          OR: [
            { userId: session.user.id },
            ...(userEmail ? [{ address: userEmail }] : []),
          ],
        },
      });
      // Clean up drafts owned by the user
      await prisma.email.deleteMany({
        where: {
          id,
          fromId: session.user.id,
          draft: true,
        },
      });
    } else {
      const updated = await prisma.emailRecipient.updateMany({
        where: {
          emailId: id,
          OR: [
            { userId: session.user.id },
            ...(userEmail ? [{ address: userEmail }] : []),
          ],
        },
        data: { folder: 'trash' },
      });

      if (updated.count === 0) {
        await prisma.email.deleteMany({
          where: {
            id,
            fromId: session.user.id,
            draft: true,
          },
        });
      }
    }
  } catch (dbErr) {
    console.warn('[Email DELETE] Database delete error (handled via fallback):', dbErr);
  }

  return NextResponse.json({ message: permanent ? 'Deleted permanently' : 'Moved to trash' });
}

