import { NextRequest, NextResponse } from 'next/server';

export interface WarmupDayPlan {
  day: number;
  stageName: string;
  dailyLimit: number;
  hourlyRateLimit: number;
  riskTolerance: 'MINIMAL' | 'LOW' | 'BALANCED' | 'HIGH';
  focus: string;
}

const WARMUP_SCHEDULE: WarmupDayPlan[] = [
  { day: 1, stageName: 'Stage 1: Genesis Handshake', dailyLimit: 50, hourlyRateLimit: 10, riskTolerance: 'MINIMAL', focus: 'IP Warming & SPF Verification' },
  { day: 2, stageName: 'Stage 1: Genesis Handshake', dailyLimit: 75, hourlyRateLimit: 15, riskTolerance: 'MINIMAL', focus: 'SPF & DKIM Selector Discovery' },
  { day: 3, stageName: 'Stage 1: Genesis Handshake', dailyLimit: 100, hourlyRateLimit: 20, riskTolerance: 'MINIMAL', focus: 'DKIM Signature Confirmation' },
  { day: 4, stageName: 'Stage 2: Trust Building', dailyLimit: 150, hourlyRateLimit: 25, riskTolerance: 'LOW', focus: 'Inbox Engagement Calibration' },
  { day: 5, stageName: 'Stage 2: Trust Building', dailyLimit: 200, hourlyRateLimit: 30, riskTolerance: 'LOW', focus: 'DMARC rua Telemetry Evaluation' },
  { day: 6, stageName: 'Stage 2: Trust Building', dailyLimit: 300, hourlyRateLimit: 40, riskTolerance: 'LOW', focus: 'Bounce Rate Thresholding (<0.5%)' },
  { day: 7, stageName: 'Stage 2: Trust Building', dailyLimit: 400, hourlyRateLimit: 50, riskTolerance: 'LOW', focus: 'First-Week Reputation Score Check' },
  { day: 8, stageName: 'Stage 3: DMARC Scaling', dailyLimit: 600, hourlyRateLimit: 75, riskTolerance: 'BALANCED', focus: 'ISP Quota Expansion (Gmail/Yahoo)' },
  { day: 10, stageName: 'Stage 3: DMARC Scaling', dailyLimit: 1000, hourlyRateLimit: 125, riskTolerance: 'BALANCED', focus: 'Domain Reputation Hardening' },
  { day: 14, stageName: 'Stage 3: DMARC Scaling', dailyLimit: 1800, hourlyRateLimit: 200, riskTolerance: 'BALANCED', focus: 'Two-Week Milestone Audit' },
  { day: 18, stageName: 'Stage 4: High-Volume Ramp', dailyLimit: 3500, hourlyRateLimit: 350, riskTolerance: 'BALANCED', focus: 'High-Volume Relay Distribution' },
  { day: 21, stageName: 'Stage 4: High-Volume Ramp', dailyLimit: 5000, hourlyRateLimit: 500, riskTolerance: 'HIGH', focus: 'Commercial Sender Status Attainment' },
  { day: 25, stageName: 'Stage 5: Enterprise Fleet', dailyLimit: 10000, hourlyRateLimit: 1000, riskTolerance: 'HIGH', focus: 'Unthrottled Production Dispatch' },
  { day: 28, stageName: 'Stage 5: Enterprise Fleet', dailyLimit: 25000, hourlyRateLimit: 2500, riskTolerance: 'HIGH', focus: 'Full Autonomous Throughput' },
];

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const parsed = parseInt(searchParams.get('day') || '8', 10);
  const currentDay = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 1), 28) : 8;
  const currentPlan =
    [...WARMUP_SCHEDULE].reverse().find((p) => p.day <= currentDay) || WARMUP_SCHEDULE[0];

  return NextResponse.json({
    success: true,
    data: {
      currentDay,
      totalDays: 28,
      activeStage: currentPlan.stageName,
      currentDailyLimit: currentPlan.dailyLimit,
      currentHourlyRate: currentPlan.hourlyRateLimit,
      recommendedSchedule: WARMUP_SCHEDULE,
      deliverabilityScore: 94.8,
      status: 'WARMING_HEALTHY',
    },
  });
}

