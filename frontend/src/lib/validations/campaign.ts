import { z } from 'zod';

export const CampaignStep1Schema = z.object({
  title: z.string().min(3, 'Campaign title must be at least 3 characters').max(100, 'Title is too long'),
  fromName: z.string().min(2, 'Sender name is required').max(60),
  fromEmail: z.string().email('Valid sender email is required'),
  replyTo: z.string().email('Valid reply-to email is required').optional().or(z.literal('')),
  audienceSegment: z.string().min(1, 'Please select an audience segment or list'),
  trackOpens: z.boolean().default(true),
  trackClicks: z.boolean().default(true),
});

export const CampaignStep2Schema = z.object({
  subject: z.string().min(5, 'Subject line must be at least 5 characters').max(150, 'Subject line should stay concise'),
  previewText: z.string().max(140, 'Preheader preview text should be under 140 characters').optional().or(z.literal('')),
  contentHtml: z.string().min(20, 'Email HTML content must be provided'),
  contentPlainText: z.string().min(10, 'Plain text fallback is required for deliverability'),
  isAbTest: z.boolean().default(false),
  subjectVariantB: z.string().optional().or(z.literal('')),
  abSplitRatio: z.number().min(10).max(50).default(20),
  winningMetric: z.enum(['OPEN_RATE', 'CLICK_RATE']).default('OPEN_RATE'),
});

export const CampaignStep3Schema = z.object({
  sendScheduleType: z.enum(['IMMEDIATE', 'SCHEDULED']).default('IMMEDIATE'),
  scheduledDate: z.string().optional().or(z.literal('')),
  scheduledTime: z.string().optional().or(z.literal('')),
  warmupThrottling: z.boolean().default(true),
  maxPerHour: z.number().min(10).max(50000).default(500),
});

export const CampaignStep4Schema = z.object({
  preflightPassed: z.boolean().refine((val) => val === true, {
    message: 'Preflight deliverability checks must pass before sending',
  }),
  acknowledgedConsent: z.boolean().refine((val) => val === true, {
    message: 'You must confirm audience consent under CAN-SPAM and GDPR guidelines',
  }),
});

export const FullCampaignSchema = CampaignStep1Schema
  .and(CampaignStep2Schema)
  .and(CampaignStep3Schema)
  .and(CampaignStep4Schema);

export type CampaignStep1Input = z.infer<typeof CampaignStep1Schema>;
export type CampaignStep2Input = z.infer<typeof CampaignStep2Schema>;
export type CampaignStep3Input = z.infer<typeof CampaignStep3Schema>;
export type CampaignStep4Input = z.infer<typeof CampaignStep4Schema>;
export type FullCampaignInput = z.infer<typeof FullCampaignSchema>;

