import { NextResponse } from 'next/server';
import { runSIHDemo } from '@/lib/ops/autonomous-ops';

export async function POST() {
  try {
    const data = await runSIHDemo();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
