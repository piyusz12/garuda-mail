import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { findUserByEmail, registerUser } from '@/lib/users';

export const runtime = 'nodejs';

const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100),
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validation = registerSchema.safeParse(body);

    if (!validation.success) {
      const errMsg =
        validation.error.issues?.[0]?.message ||
        (validation.error as any).errors?.[0]?.message ||
        'Invalid registration data';
      return NextResponse.json({ error: errMsg }, { status: 400 });
    }

    const { name, email, password } = validation.data;
    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists across DB, memory, or builtins
    const cookieHeader = request.headers.get('cookie');
    const existingUser = await findUserByEmail(normalizedEmail, cookieHeader);

    if (existingUser) {
      return NextResponse.json(
        { error: 'An account with this email already exists' },
        { status: 409 }
      );
    }

    // Register user across all stores (Prisma + Memory + /tmp + Signed fallback cookie)
    const { user, cookieToken } = await registerUser(name, normalizedEmail, password);

    const response = NextResponse.json(
      { message: 'Account created successfully', user },
      { status: 201 }
    );

    if (cookieToken) {
      response.cookies.set('garuda_usr_reg', cookieToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 30 * 24 * 60 * 60, // 30 days
      });
    }

    return response;
  } catch (error: any) {
    console.error('[Register] Error:', error);
    return NextResponse.json(
      { error: 'Failed to create account. Please try again.' },
      { status: 500 }
    );
  }
}
