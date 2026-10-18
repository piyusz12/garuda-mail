import { NextResponse } from 'next/server';
import { fetchOpsOverview } from '@/lib/ops/autonomous-ops';

export async function GET() {
  try {
    const data = await fetchOpsOverview();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
