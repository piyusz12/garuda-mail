import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { resetAllLoginCredentials, deleteUserByEmail } from '@/lib/users';

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized: Session required' }, { status: 401 });
  }

  const role = (session.user as { role?: string }).role;
  if (role !== 'admin') {
    return NextResponse.json(
      { error: 'Forbidden: Resetting credentials requires Administrator privileges' },
      { status: 403 }
    );
  }

  try {
    const body = await request.json().catch(() => ({}));
    const { action, email, keepDefaultAdmins } = body;

    if (action === 'delete_user' && email) {
      const deleted = await deleteUserByEmail(email);
      return NextResponse.json({
        success: true,
        message: `Credentials for user ${email} deleted successfully.`,
        deleted,
        operator: session.user.email,
        timestamp: new Date().toISOString(),
      });
    }

    // Default: Reset all credentials
    const result = await resetAllLoginCredentials({
      keepDefaultAdmins: keepDefaultAdmins !== false,
    });

    return NextResponse.json({
      success: true,
      message: result.message,
      deletedCount: result.deletedCount,
      operator: session.user.email,
      timestamp: new Date().toISOString(),
    });
  } catch (error: unknown) {
    console.error('[ResetCredentials POST] Error:', error);
    const errMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Failed to reset credentials', details: errMessage },
      { status: 500 }
    );
  }
}
