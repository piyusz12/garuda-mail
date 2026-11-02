'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type WizardStep = 1 | 2 | 3 | 4;

export interface AltTextWarning {
  src: string;
  index: number;
}

export interface ContentAuditResult {
  textRatio: number;
  imageRatio: number;
  isRatioCompliant: boolean;
  missingAltImages: AltTextWarning[];
  hasAltTextIssues: boolean;
  spamWordsDetected: string[];
  mobileSubjectPreview: {
    iphoneTruncated: boolean;
    iphonePreview: string;
    androidTruncated: boolean;
    androidPreview: string;
  };
}

export interface CampaignState {
  // Wizard Navigation
  currentStep: WizardStep;
  completedSteps: number[];
  isDraftSaved: boolean;
  lastSavedAt: string | null;

  // Step 1: Setup & Audience
  title: string;
  fromName: string;
  fromEmail: string;
  replyTo: string;
  audienceSegment: string;
  recipientCount: number;
  trackOpens: boolean;
  trackClicks: boolean;

  // Step 2: Content & Design
  subject: string;
  previewText: string;
  contentHtml: string;
  contentPlainText: string;
  isAbTest: boolean;
  subjectVariantB: string;
  abSplitRatio: number;
  winningMetric: 'OPEN_RATE' | 'CLICK_RATE';

  // Step 3: Scheduling & Deliverability
  sendScheduleType: 'IMMEDIATE' | 'SCHEDULED';
  scheduledDate: string;
  scheduledTime: string;
  warmupThrottling: boolean;
  maxPerHour: number;

  // Step 4: Final Preflight & Review
  preflightPassed: boolean;
  acknowledgedConsent: boolean;

  // Actions
  setStep: (step: WizardStep) => void;
  nextStep: () => void;
  prevStep: () => void;
  updateField: <K extends keyof CampaignState>(key: K, value: CampaignState[K]) => void;
  resetDraft: () => void;
  runContentAudit: () => ContentAuditResult;
}

const SPAM_TRIGGER_WORDS = [
  'free', '100% free', 'guarantee', 'guaranteed', 'risk-free', 'risk free',
  '$$$', 'cash', 'prize', 'winner', 'won', 'earn money', 'make money',
  'act now', 'urgent', 'exclusive deal', 'no catch', 'no hidden fees',
  'buy direct', 'order now', 'claims', 'instant', 'unlimited', 'click here'
];

function checkSpamWord(text: string, word: string): boolean {
  if (word === '$$$') {
    return text.includes('$$$');
  }
  const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`\\b${escaped}\\b`, 'i');
  return regex.test(text);
}

export const useCampaignStore = create<CampaignState>()(
  persist(
    (set, get) => ({
      // Wizard Navigation
      currentStep: 1,
      completedSteps: [],
      isDraftSaved: true,
      lastSavedAt: null,

      // Step 1 Defaults
      title: 'Monthly Security & Deliverability Briefing',
      fromName: 'Garuda Mail Intelligence',
      fromEmail: 'dispatch@garudamail.org',
      replyTo: 'security@garudamail.org',
      audienceSegment: 'Enterprise Security Officers (4,850 contacts)',
      recipientCount: 4850,
      trackOpens: true,
      trackClicks: true,

      // Step 2 Defaults
      subject: 'Critical Q4 Cryptographic Intelligence & RFC 8058 Directives',
      previewText: 'Key findings on TLS 1.3 ciphers, DMARC enforcement, and automated DNS propagation.',
      contentHtml: `<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; line-height: 1.6; color: #1e293b;">
  <h1 style="color: #0369a1; font-size: 24px; margin-bottom: 16px;">Garuda Cryptographic Deliverability Report</h1>
  <p>Dear Security Officer,</p>
  <p>Mailbox providers have activated stringent enforcement for bulk senders. To guarantee unhindered deliverability, your domains must maintain cryptographic SPF/DKIM alignment and instant RFC 8058 one-click opt-outs.</p>
  <div style="background: #f1f5f9; padding: 16px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #0284c7;">
    <h3 style="margin-top: 0; color: #0f172a;">Executive Action Checklist</h3>
    <ul style="padding-left: 20px; margin-bottom: 0;">
      <li>Audit SPF records for single TXT string compliance</li>
      <li>Verify 2048-bit RSA or Ed25519 DKIM keys across active selectors</li>
      <li>Upgrade DMARC policy from p=none to p=quarantine</li>
    </ul>
  </div>
  <p>Review your live deliverability dashboard for automated trajectory curves and queue health metrics.</p>
  <p style="margin-top: 24px;">Sincerely,<br/><strong>Garuda Mail Protocol Team</strong></p>
</div>`,
      contentPlainText: `Garuda Cryptographic Deliverability Report\n\nDear Security Officer,\nMailbox providers have activated stringent enforcement for bulk senders. To guarantee unhindered deliverability, your domains must maintain cryptographic SPF/DKIM alignment and instant RFC 8058 one-click opt-outs.\n\nExecutive Action Checklist:\n1. Audit SPF records for single TXT string compliance\n2. Verify 2048-bit RSA or Ed25519 DKIM keys\n3. Upgrade DMARC policy to p=quarantine\n\nReview your live deliverability dashboard for automated trajectory curves.`,
      isAbTest: false,
      subjectVariantB: 'Action Required: Updated RFC 8058 and DMARC Directives for Your Organization',
      abSplitRatio: 20,
      winningMetric: 'OPEN_RATE',

      // Step 3 Defaults
      sendScheduleType: 'IMMEDIATE',
      scheduledDate: '',
      scheduledTime: '',
      warmupThrottling: true,
      maxPerHour: 500,

      // Step 4 Defaults
      preflightPassed: false,
      acknowledgedConsent: false,

      setStep: (step: WizardStep) => {
        set((state) => {
          const completed = new Set(state.completedSteps);
          if (step > state.currentStep) {
            completed.add(state.currentStep);
          }
          return {
            currentStep: step,
            completedSteps: Array.from(completed),
            isDraftSaved: true,
            lastSavedAt: new Date().toISOString()
          };
        });
      },

      nextStep: () => {
        const { currentStep, setStep } = get();
        if (currentStep < 4) {
          setStep((currentStep + 1) as WizardStep);
        }
      },

      prevStep: () => {
        const { currentStep, setStep } = get();
        if (currentStep > 1) {
          setStep((currentStep - 1) as WizardStep);
        }
      },

      updateField: (key, value) => {
        set({
          [key]: value,
          isDraftSaved: true,
          lastSavedAt: new Date().toISOString()
        });
      },

      resetDraft: () => {
        set({
          currentStep: 1,
          completedSteps: [],
          title: '',
          fromName: '',
          fromEmail: '',
          replyTo: '',
          audienceSegment: '',
          recipientCount: 0,
          subject: '',
          previewText: '',
          contentHtml: '',
          contentPlainText: '',
          isAbTest: false,
          subjectVariantB: '',
          preflightPassed: false,
          acknowledgedConsent: false,
          lastSavedAt: null
        });
      },

      runContentAudit: (): ContentAuditResult => {
        const state = get();
        const html = state.contentHtml || '';
        const subject = state.subject || '';

        // 1. Text vs Image Ratio Heuristic (WCAG / Spam Filter Deliverability)
        const strippedText = html.replace(/<[^>]*>/g, '').trim();
        const textCharCount = strippedText.length;
        const imgTags = html.match(/<img[^>]*>/gi) || [];
        const imgWeight = imgTags.length * 200; // rough visual weight proxy
        const totalWeight = Math.max(textCharCount + imgWeight, 1);
        const textRatio = Math.round((textCharCount / totalWeight) * 100);
        const imageRatio = 100 - textRatio;
        const isRatioCompliant = textRatio >= 80; // Standard 80/20 rule

        // 2. Missing Alt Text Check
        const missingAltImages: AltTextWarning[] = [];
        imgTags.forEach((tag, idx) => {
          const hasAlt = /\salt\s*=\s*["'][^"']*["']/i.test(tag);
          if (!hasAlt) {
            const srcMatch = tag.match(/\ssrc\s*=\s*["']([^"']+)["']/i);
            missingAltImages.push({
              src: srcMatch ? srcMatch[1] : `image_${idx + 1}`,
              index: idx + 1
            });
          }
        });

        // 3. Spam Keyword Detection
        const subjectLower = subject.toLowerCase();
        const contentLower = strippedText.toLowerCase();
        const spamWordsDetected = SPAM_TRIGGER_WORDS.filter((word) => {
          return checkSpamWord(subjectLower, word) || checkSpamWord(contentLower, word);
        });

        // 4. Mobile Viewport Truncation (iPhone 38 chars, Android 42 chars)
        const iphoneTruncated = subject.length > 38;
        const iphonePreview = iphoneTruncated ? `${subject.slice(0, 35)}...` : subject;
        const androidTruncated = subject.length > 42;
        const androidPreview = androidTruncated ? `${subject.slice(0, 39)}...` : subject;

        return {
          textRatio,
          imageRatio,
          isRatioCompliant,
          missingAltImages,
          hasAltTextIssues: missingAltImages.length > 0,
          spamWordsDetected,
          mobileSubjectPreview: {
            iphoneTruncated,
            iphonePreview,
            androidTruncated,
            androidPreview
          }
        };
      }
    }),
    {
      name: 'garuda-campaign-wizard-draft',
      partialize: (state) => ({
        currentStep: state.currentStep,
        completedSteps: state.completedSteps,
        title: state.title,
        fromName: state.fromName,
        fromEmail: state.fromEmail,
        replyTo: state.replyTo,
        audienceSegment: state.audienceSegment,
        recipientCount: state.recipientCount,
        trackOpens: state.trackOpens,
        trackClicks: state.trackClicks,
        subject: state.subject,
        previewText: state.previewText,
        contentHtml: state.contentHtml,
        contentPlainText: state.contentPlainText,
        isAbTest: state.isAbTest,
        subjectVariantB: state.subjectVariantB,
        abSplitRatio: state.abSplitRatio,
        winningMetric: state.winningMetric,
        sendScheduleType: state.sendScheduleType,
        scheduledDate: state.scheduledDate,
        scheduledTime: state.scheduledTime,
        warmupThrottling: state.warmupThrottling,
        maxPerHour: state.maxPerHour,
        preflightPassed: state.preflightPassed,
        lastSavedAt: state.lastSavedAt
      })
    }
  )
);
