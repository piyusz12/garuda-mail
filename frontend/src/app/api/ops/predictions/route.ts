import { NextResponse } from 'next/server';
import { fetchOpsPredictions } from '@/lib/ops/autonomous-ops';

export async function GET() {
  try {
    const data = await fetchOpsPredictions();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
