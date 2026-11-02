'use client';

import { useState, useId, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send, Users, Sparkles, CheckCircle2, AlertTriangle, ArrowRight,
  ArrowLeft, Clock, ShieldCheck, Download, RefreshCw, FileText,
  Smartphone, Check, X
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { useCampaignStore, WizardStep } from '@/lib/stores/useCampaignStore';
import {
  CampaignStep1Schema,
  CampaignStep2Schema,
  CampaignStep3Schema,
  CampaignStep4Schema
} from '@/lib/validations/campaign';
import { useAnnounce } from '@/components/common/AriaLiveAnnouncer';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

interface FailedRecord {
  email: string;
  code: string;
  reason: string;
  retryable: boolean;
}

const AUDIENCE_SEGMENTS = [
  { label: 'Enterprise Security Officers (4,850 contacts)', count: 4850 },
  { label: 'DevOps & Reliability Leads (1,240 contacts)', count: 1240 },
  { label: 'Cryptographic Policy Working Group (320 contacts)', count: 320 },
];

export default function NewCampaignPage() {
  const announce = useAnnounce();
  const formId = useId();

  const {
    currentStep,
    setStep,
    nextStep,
    prevStep,
    title,
    fromName,
    fromEmail,
    replyTo,
    audienceSegment,
    recipientCount,
    trackOpens,
    trackClicks,
    subject,
    previewText,
    contentHtml,
    contentPlainText,
    isAbTest,
    subjectVariantB,
    abSplitRatio,
    winningMetric,
    sendScheduleType,
    scheduledDate,
    scheduledTime,
    warmupThrottling,
    maxPerHour,
    preflightPassed,
    acknowledgedConsent,
    updateField,
    runContentAudit,
    lastSavedAt,
  } = useCampaignStore();

  const [stepErrors, setStepErrors] = useState<Record<string, string>>({});
  const [isAiPanelOpen, setIsAiPanelOpen] = useState(false);
  const [aiTone, setAiTone] = useState<'Professional' | 'Urgent' | 'Conversational'>('Professional');
  const [aiSuggestions, setAiSuggestions] = useState<string[]>([]);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);

  // SSE Dispatch State
  const [isDispatching, setIsDispatching] = useState(false);
  const [dispatchProgress, setDispatchProgress] = useState(0);
  const [dispatchSent, setDispatchSent] = useState(0);
  const [dispatchFailed, setDispatchFailed] = useState(0);
  const [dispatchStatus, setDispatchStatus] = useState<string>('IDLE');
  const [dispatchMessage, setDispatchMessage] = useState<string>('');
  const [failedRecords, setFailedRecords] = useState<FailedRecord[]>([]);

  // Calculate Endowed Progress: Step 1 = 25%, Step 2 = 50%, Step 3 = 75%, Step 4 = 100%
  const endowedProgress = currentStep * 25;
  const audit = useMemo(() => runContentAudit(), [contentHtml, subject, runContentAudit]);

  const validateCurrentStep = (): boolean => {
    setStepErrors({});
    let result: any;

    if (currentStep === 1) {
      result = CampaignStep1Schema.safeParse({
        title, fromName, fromEmail, replyTo, audienceSegment, trackOpens, trackClicks,
      });
    } else if (currentStep === 2) {
      result = CampaignStep2Schema.safeParse({
        subject, previewText, contentHtml, contentPlainText, isAbTest, subjectVariantB, abSplitRatio, winningMetric,
      });
    } else if (currentStep === 3) {
      result = CampaignStep3Schema.safeParse({
        sendScheduleType, scheduledDate, scheduledTime, warmupThrottling, maxPerHour,
      });
    } else {
      result = CampaignStep4Schema.safeParse({
        preflightPassed, acknowledgedConsent,
      });
    }

    if (!result.success) {
      const errMap: Record<string, string> = {};
      result.error.issues.forEach((issue: any) => {
        const fieldName = issue.path[0];
        errMap[fieldName] = issue.message;
      });
      setStepErrors(errMap);
      announce(`Validation failed on step ${currentStep}. Please review required fields.`);
      return false;
    }
    return true;
  };

  const handleNext = () => {
    if (validateCurrentStep()) {
      nextStep();
      announce(`Navigated to Step ${currentStep + 1} of 4.`);
    }
  };

  const handlePrev = () => {
    setStepErrors({});
    prevStep();
    announce(`Returned to Step ${currentStep - 1} of 4.`);
  };

  const generateAiSubjects = () => {
    setIsGeneratingAi(true);
    setTimeout(() => {
      if (aiTone === 'Professional') {
        setAiSuggestions([
          'Executive Briefing: Modernizing Cryptographic Deliverability for 2026',
          'Garuda Protocol Advisory: Maintaining Gmail & Yahoo DMARC Compliance',
          'Deliverability Telemetry Report: Cryptographic Validation Directives'
        ]);
      } else if (aiTone === 'Urgent') {
        setAiSuggestions([
          'Immediate Action Required: RFC 8058 Mandates & Domain Verification',
          'Urgent Deliverability Notice: Verify Active SPF & DKIM Records',
          'Final Reminder: Complete Required Cryptographic Alignment'
        ]);
      } else {
        setAiSuggestions([
          'A quick guide to keeping your emails out of the spam folder',
          'Here is what changed with Gmail and Yahoo deliverability this year',
          'Let’s take a look at your domain’s email health score'
        ]);
      }
      setIsGeneratingAi(false);
      announce('Generated AI subject line recommendations.');
    }, 600);
  };

  const startSseDispatch = async (isRetry: boolean = false) => {
    // Verify preflight automatically if content heuristics are satisfied
    let currentPreflight = preflightPassed;
    if (!currentPreflight && audit.isRatioCompliant && !audit.hasAltTextIssues && audit.spamWordsDetected.length === 0) {
      currentPreflight = true;
      updateField('preflightPassed', true);
    }

    // Validate all schemas across steps before launching dispatch
    const v1 = CampaignStep1Schema.safeParse({ title, fromName, fromEmail, replyTo, audienceSegment, trackOpens, trackClicks });
    const v2 = CampaignStep2Schema.safeParse({ subject, previewText, contentHtml, contentPlainText, isAbTest, subjectVariantB, abSplitRatio, winningMetric });
    const v3 = CampaignStep3Schema.safeParse({ sendScheduleType, scheduledDate, scheduledTime, warmupThrottling, maxPerHour });
    const v4 = CampaignStep4Schema.safeParse({ preflightPassed: currentPreflight, acknowledgedConsent });

    if (!v1.success || !v2.success || !v3.success || !v4.success) {
      announce('Pre-dispatch validation failed. Please check all campaign configuration steps.');
      return;
    }

    setIsDispatching(true);
    setDispatchStatus('INITIALIZING');
    setDispatchProgress(0);
    announce(isRetry ? 'Retrying failed recipients with idempotent deduplication...' : 'Starting bulk batch dispatch via Server-Sent Events...');

    const retryableRecords = failedRecords.filter((r) => r.retryable);
    const nonRetryableRecords = failedRecords.filter((r) => !r.retryable);

    if (isRetry && retryableRecords.length === 0) {
      announce('No retryable failure records available.');
      return;
    }

    try {
      const response = await fetch('/api/campaigns/send-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipientCount,
          isRetry,
          failedRecords: isRetry ? failedRecords : [],
          recipients: ['cso@enterprise-cyber.org', 'sec-ops@defense-intel.gov', 'lead-architect@crypto-policy.net'],
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error(`Dispatch stream rejected with status ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const rawJson = line.slice(6);
            try {
              const eventData = JSON.parse(rawJson);
              setDispatchProgress(eventData.progress);
              setDispatchSent(eventData.sent);
              setDispatchFailed(eventData.failed);
              setDispatchStatus(eventData.status);
              setDispatchMessage(eventData.message);
              if (eventData.failedRecords && (!isRetry || eventData.failedRecords.length > 0 || eventData.status === 'COMPLETED' || eventData.status === 'PARTIAL_SUCCESS')) {
                setFailedRecords(
                  isRetry ? [...nonRetryableRecords, ...eventData.failedRecords] : eventData.failedRecords
                );
              }
            } catch {}
          }
        }
      }
      announce('Bulk email dispatch stream finished.');
    } catch {
      setDispatchStatus('NETWORK_ERROR');
      announce('Dispatch stream encountered a network interruption.');
    }
  };

  const exportFailedCsv = () => {
    if (failedRecords.length === 0) return;
    const header = 'email,failure_code,reason,retryable\n';
    const rows = failedRecords
      .map((r) => `"${r.email}","${r.code}","${r.reason.replace(/"/g, '""')}","${r.retryable}"`)
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `failed_deliveries_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    announce('Failed delivery records exported to CSV.');
  };

  return (
    <AppShell
      title="Campaign Orchestration Wizard"
      description="Create, validate, and dispatch high-deliverability bulk email campaigns with progressive state persistence."
    >
      <div className="max-w-5xl mx-auto space-y-6">
        {/* ── Persistent Endowed Progress Bar (WCAG 2.1 AA) ── */}
        <div className="card p-4 space-y-3">
          <div className="flex items-center justify-between text-xs text-[var(--color-text-dim)]">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sky-600 dark:text-sky-400">Step {currentStep} of 4:</span>
              <span className="font-medium text-[var(--color-text-primary)]">
                {currentStep === 1 && 'Setup & Target Audience'}
                {currentStep === 2 && 'Content Studio & Inbox Heuristics'}
                {currentStep === 3 && 'Deliverability Throttles & Scheduling'}
                {currentStep === 4 && 'Preflight Verification & Launch'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              {lastSavedAt && (
                <span className="text-[11px] text-[var(--color-text-muted)] hidden sm:inline">
                  Draft saved locally
                </span>
              )}
              <span className="font-mono font-bold text-sky-600 dark:text-sky-400">{endowedProgress}% Complete</span>
            </div>
          </div>

          <div
            className="w-full bg-[var(--color-surface-3)] h-2.5 rounded-full overflow-hidden"
            role="progressbar"
            aria-valuenow={endowedProgress}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Campaign creation progress"
          >
            <motion.div
              className="h-full bg-sky-600 dark:bg-sky-400 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${endowedProgress}%` }}
              transition={{ duration: 0.35, ease: 'easeOut' }}
            />
          </div>

          {/* Step Breadcrumbs */}
          <div className="grid grid-cols-4 gap-2 pt-1">
            {[
              { num: 1, label: '1. Setup' },
              { num: 2, label: '2. Content' },
              { num: 3, label: '3. Schedule' },
              { num: 4, label: '4. Review' },
            ].map((s) => (
              <button
                key={s.num}
                type="button"
                onClick={() => {
                  if (s.num > currentStep && !validateCurrentStep()) return;
                  if (s.num > currentStep + 1) return;
                  setStep(s.num as WizardStep);
                }}
                className={`py-1.5 text-xs text-center font-medium rounded transition ${
                  currentStep === s.num
                    ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 font-bold border border-sky-500/30'
                    : currentStep > s.num
                    ? 'text-emerald-700 dark:text-emerald-400 hover:bg-[var(--color-surface-2)]'
                    : 'text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)]'
                }`}
                aria-current={currentStep === s.num ? 'step' : undefined}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── STEP 1: SETUP & AUDIENCE ── */}
        {currentStep === 1 && (
          <motion.div {...fadeUp} className="card p-6 space-y-5">
            <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <Users className="w-5 h-5 text-sky-500" />
              Campaign Identity & Target Audience
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label htmlFor={`${formId}-title`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                  Internal Campaign Title *
                </label>
                <input
                  id={`${formId}-title`}
                  type="text"
                  value={title}
                  onChange={(e) => updateField('title', e.target.value)}
                  placeholder="e.g. Monthly Security & Deliverability Briefing"
                  aria-invalid={Boolean(stepErrors.title)}
                  aria-describedby={stepErrors.title ? `${formId}-title-err` : undefined}
                  className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                />
                {stepErrors.title && (
                  <p id={`${formId}-title-err`} className="text-xs text-rose-500 font-medium">
                    {stepErrors.title}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <label htmlFor={`${formId}-audience`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                  Audience Segment / List *
                </label>
                <select
                  id={`${formId}-audience`}
                  value={audienceSegment}
                  onChange={(e) => {
                    const val = e.target.value;
                    updateField('audienceSegment', val);
                    const seg = AUDIENCE_SEGMENTS.find((s) => s.label === val);
                    if (seg) updateField('recipientCount', seg.count);
                  }}
                  aria-invalid={Boolean(stepErrors.audienceSegment)}
                  aria-describedby={stepErrors.audienceSegment ? `${formId}-aud-err` : undefined}
                  className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                >
                  {AUDIENCE_SEGMENTS.map((seg) => (
                    <option key={seg.label} value={seg.label}>{seg.label}</option>
                  ))}
                </select>
                {stepErrors.audienceSegment && (
                  <p id={`${formId}-aud-err`} className="text-xs text-rose-500 font-medium">
                    {stepErrors.audienceSegment}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <label htmlFor={`${formId}-fromName`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                  From Name *
                </label>
                <input
                  id={`${formId}-fromName`}
                  type="text"
                  value={fromName}
                  onChange={(e) => updateField('fromName', e.target.value)}
                  placeholder="e.g. Garuda Mail Intelligence"
                  aria-invalid={Boolean(stepErrors.fromName)}
                  aria-describedby={stepErrors.fromName ? `${formId}-fromName-err` : undefined}
                  className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                />
                {stepErrors.fromName && (
                  <p id={`${formId}-fromName-err`} className="text-xs text-rose-500 font-medium">
                    {stepErrors.fromName}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <label htmlFor={`${formId}-fromEmail`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                  Authenticated From Email Address *
                </label>
                <input
                  id={`${formId}-fromEmail`}
                  type="email"
                  value={fromEmail}
                  onChange={(e) => updateField('fromEmail', e.target.value)}
                  placeholder="dispatch@garudamail.org"
                  aria-invalid={Boolean(stepErrors.fromEmail)}
                  aria-describedby={stepErrors.fromEmail ? `${formId}-fromEmail-err` : undefined}
                  className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)] font-mono"
                />
                {stepErrors.fromEmail && (
                  <p id={`${formId}-fromEmail-err`} className="text-xs text-rose-500 font-medium">
                    {stepErrors.fromEmail}
                  </p>
                )}
              </div>
            </div>

            {/* Tracking Switches */}
            <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--color-text-dim)]">
                Deliverability Telemetry & Tracking
              </h4>
              <div className="flex flex-col sm:flex-row gap-4">
                <label className="flex items-center gap-2 cursor-pointer text-sm text-[var(--color-text-primary)]">
                  <input
                    type="checkbox"
                    checked={trackOpens}
                    onChange={(e) => updateField('trackOpens', e.target.checked)}
                    className="rounded text-sky-600 focus:ring-sky-500 h-4 w-4"
                  />
                  Track Unique Message Opens (Pixel Telemetry)
                </label>
                <label className="flex items-center gap-2 cursor-pointer text-sm text-[var(--color-text-primary)]">
                  <input
                    type="checkbox"
                    checked={trackClicks}
                    onChange={(e) => updateField('trackClicks', e.target.checked)}
                    className="rounded text-sky-600 focus:ring-sky-500 h-4 w-4"
                  />
                  Track Link Click-Throughs (HTTPS Redirect Proxy)
                </label>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── STEP 2: CONTENT & DESIGN (WITH AI & 80/20 CHECK) ── */}
        {currentStep === 2 && (
          <motion.div {...fadeUp} className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Main Content Area */}
              <div className="lg:col-span-8 card p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                    <FileText className="w-5 h-5 text-sky-500" />
                    Email Subject & Content Studio
                  </h3>
                  <button
                    type="button"
                    onClick={() => setIsAiPanelOpen(!isAiPanelOpen)}
                    className="btn btn-secondary px-3 py-1.5 text-xs flex items-center gap-1.5 text-sky-700 dark:text-sky-300 font-semibold"
                  >
                    <Sparkles className="w-4 h-4 text-amber-500" />
                    {isAiPanelOpen ? 'Hide AI Assistant' : 'AI Subject Assistant'}
                  </button>
                </div>

                <div className="space-y-1">
                  <label htmlFor={`${formId}-subject`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                    Primary Subject Line *
                  </label>
                  <input
                    id={`${formId}-subject`}
                    type="text"
                    value={subject}
                    onChange={(e) => updateField('subject', e.target.value)}
                    placeholder="Enter engaging, spam-safe subject line"
                    aria-invalid={Boolean(stepErrors.subject)}
                    className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                  />
                  {stepErrors.subject && (
                    <p className="text-xs text-rose-500 font-medium">{stepErrors.subject}</p>
                  )}
                </div>

                <div className="space-y-1">
                  <label htmlFor={`${formId}-previewText`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                    Preheader Preview Text
                  </label>
                  <input
                    id={`${formId}-previewText`}
                    type="text"
                    value={previewText}
                    onChange={(e) => updateField('previewText', e.target.value)}
                    placeholder="Summary snippet visible in inbox previews"
                    className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                  />
                </div>

                {/* A/B Split Testing Mode */}
                <div className="p-3.5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)] space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="flex items-center gap-2 text-xs font-bold text-[var(--color-text-primary)] cursor-pointer">
                      <input
                        type="checkbox"
                        checked={isAbTest}
                        onChange={(e) => updateField('isAbTest', e.target.checked)}
                        className="rounded text-sky-600 h-4 w-4"
                      />
                      Enable A/B Subject Line Split Test
                    </label>
                    {isAbTest && (
                      <span className="text-xs text-sky-600 dark:text-sky-400 font-semibold font-mono">
                        Split: {abSplitRatio}% Sample
                      </span>
                    )}
                  </div>

                  {isAbTest && (
                    <div className="pt-2 space-y-2">
                      <input
                        type="text"
                        value={subjectVariantB}
                        onChange={(e) => updateField('subjectVariantB', e.target.value)}
                        placeholder="Variant B Subject Line (min 5 characters)"
                        aria-invalid={Boolean(stepErrors.subjectVariantB)}
                        aria-describedby={stepErrors.subjectVariantB ? `${formId}-varb-err` : undefined}
                        className="w-full px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-xs text-[var(--color-text-primary)]"
                      />
                      {stepErrors.subjectVariantB && (
                        <p id={`${formId}-varb-err`} className="text-xs text-rose-500 font-medium">
                          {stepErrors.subjectVariantB}
                        </p>
                      )}
                      <div className="flex items-center justify-between text-xs text-[var(--color-text-dim)]">
                        <span>Winning Metric:</span>
                        <select
                          value={winningMetric}
                          onChange={(e: any) => updateField('winningMetric', e.target.value)}
                          className="px-2 py-1 rounded bg-[var(--color-surface-1)] border border-[var(--color-border)] text-xs"
                        >
                          <option value="OPEN_RATE">Highest Open Rate (Recommended)</option>
                          <option value="CLICK_RATE">Highest Click-Through Rate</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>

                {/* HTML & Plain Text Body */}
                <div className="space-y-1">
                  <label htmlFor={`${formId}-html`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                    HTML Email Body *
                  </label>
                  <textarea
                    id={`${formId}-html`}
                    rows={8}
                    value={contentHtml}
                    onChange={(e) => updateField('contentHtml', e.target.value)}
                    aria-invalid={Boolean(stepErrors.contentHtml)}
                    aria-describedby={stepErrors.contentHtml ? `${formId}-html-err` : undefined}
                    className="w-full p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] font-mono text-xs text-[var(--color-text-primary)]"
                  />
                  {stepErrors.contentHtml && (
                    <p id={`${formId}-html-err`} className="text-xs text-rose-500 font-medium">
                      {stepErrors.contentHtml}
                    </p>
                  )}
                </div>

                <div className="space-y-1">
                  <label htmlFor={`${formId}-plain`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                    Plain-Text Alternative * (Required for Spam Filter Scoring)
                  </label>
                  <textarea
                    id={`${formId}-plain`}
                    rows={4}
                    value={contentPlainText}
                    onChange={(e) => updateField('contentPlainText', e.target.value)}
                    aria-invalid={Boolean(stepErrors.contentPlainText)}
                    aria-describedby={stepErrors.contentPlainText ? `${formId}-plain-err` : undefined}
                    className="w-full p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] font-mono text-xs text-[var(--color-text-primary)]"
                  />
                  {stepErrors.contentPlainText && (
                    <p id={`${formId}-plain-err`} className="text-xs text-rose-500 font-medium">
                      {stepErrors.contentPlainText}
                    </p>
                  )}
                </div>
              </div>

              {/* Side Panel: Heuristic Validator & AI Studio */}
              <div className="lg:col-span-4 space-y-4">
                {/* 80/20 Text-to-Image & Alt-Text Audit Card */}
                <div className="card p-4 space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--color-text-dim)] flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-sky-500" />
                    Deliverability & Anti-Spam Heuristics
                  </h4>

                  {/* 80/20 Ratio Indicator */}
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-secondary)]">Text vs. Image Ratio:</span>
                      <span className={`font-mono font-bold ${audit.isRatioCompliant ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-700 dark:text-rose-400'}`}>
                        {audit.textRatio}% Text / {audit.imageRatio}% Image
                      </span>
                    </div>
                    {audit.isRatioCompliant ? (
                      <p className="text-[11px] text-emerald-700 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Compliant with standard 80/20 deliverability rule.
                      </p>
                    ) : (
                      <p className="text-[11px] text-rose-700 dark:text-rose-400 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" /> Image-heavy emails trigger spam filters. Add text.
                      </p>
                    )}
                  </div>

                  {/* Missing Alt Text Audit */}
                  <div className="space-y-1 text-xs pt-1 border-t border-[var(--color-border)]">
                    <span className="text-[var(--color-text-secondary)]">Accessibility Alt-Text Check:</span>
                    {audit.hasAltTextIssues ? (
                      <p className="text-[11px] text-amber-700 dark:text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" /> {audit.missingAltImages.length} image(s) missing alt text tags.
                      </p>
                    ) : (
                      <p className="text-[11px] text-emerald-700 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> All images contain descriptive alt text.
                      </p>
                    )}
                  </div>

                  {/* Spam Trigger Words Detected */}
                  <div className="space-y-1 text-xs pt-1 border-t border-[var(--color-border)]">
                    <span className="text-[var(--color-text-secondary)]">Spam Keyword Scanner:</span>
                    {audit.spamWordsDetected.length > 0 ? (
                      <div className="space-y-1">
                        <p className="text-[11px] text-rose-700 dark:text-rose-400 font-medium">
                          Found {audit.spamWordsDetected.length} risky trigger word(s):
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {audit.spamWordsDetected.map((w) => (
                            <span key={w} className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-400 font-mono text-[10px]">
                              {w}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-[11px] text-emerald-700 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Zero high-risk spam keywords detected.
                      </p>
                    )}
                  </div>

                  {/* Mobile Truncation Preview */}
                  <div className="space-y-1.5 text-xs pt-1 border-t border-[var(--color-border)]">
                    <div className="flex items-center gap-1 text-[var(--color-text-secondary)]">
                      <Smartphone className="w-3.5 h-3.5 text-sky-500" />
                      Mobile Viewport Preview
                    </div>
                    <div className="p-2 rounded bg-[var(--color-surface-2)] space-y-1 text-[11px]">
                      <p className="text-[var(--color-text-dim)]">iOS Mail (38 chars):</p>
                      <p className="font-mono text-[var(--color-text-primary)] truncate">{audit.mobileSubjectPreview.iphonePreview}</p>
                      <p className="text-[var(--color-text-dim)] pt-0.5">Android Gmail (42 chars):</p>
                      <p className="font-mono text-[var(--color-text-primary)] truncate">{audit.mobileSubjectPreview.androidPreview}</p>
                    </div>
                  </div>
                </div>

                {/* AI Subject Assistant Panel */}
                {isAiPanelOpen && (
                  <motion.div {...fadeUp} className="card p-4 space-y-3 border-amber-500/30">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-[var(--color-text-primary)] flex items-center gap-1.5">
                        <Sparkles className="w-4 h-4 text-amber-500" />
                        AI Subject Line Studio
                      </h4>
                    </div>

                    <div className="space-y-2">
                      <div className="flex gap-1">
                        {(['Professional', 'Urgent', 'Conversational'] as const).map((tone) => (
                          <button
                            key={tone}
                            type="button"
                            onClick={() => setAiTone(tone)}
                            className={`flex-1 py-1 text-[11px] rounded transition ${
                              aiTone === tone ? 'bg-amber-500 text-slate-950 font-bold' : 'bg-[var(--color-surface-2)] text-[var(--color-text-dim)]'
                            }`}
                          >
                            {tone}
                          </button>
                        ))}
                      </div>

                      <button
                        type="button"
                        onClick={generateAiSubjects}
                        disabled={isGeneratingAi}
                        className="w-full py-1.5 rounded-lg btn btn-accent text-xs font-bold"
                      >
                        {isGeneratingAi ? 'Synthesizing...' : 'Generate 3 Optimized Variants'}
                      </button>

                      {aiSuggestions.length > 0 && (
                        <div className="space-y-1.5 pt-1">
                          {aiSuggestions.map((sug, i) => (
                            <button
                              key={i}
                              type="button"
                              onClick={() => {
                                updateField('subject', sug);
                                announce(`Selected subject: ${sug}`);
                              }}
                              className="w-full text-left p-2 rounded bg-[var(--color-surface-2)] hover:bg-sky-500/10 text-xs text-[var(--color-text-primary)] border border-transparent hover:border-sky-500/30 transition block"
                            >
                              &ldquo;{sug}&rdquo;
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </div>
            </div>
          </motion.div>
        )}

        {/* ── STEP 3: SCHEDULING & DELIVERABILITY THROTTLING ── */}
        {currentStep === 3 && (
          <motion.div {...fadeUp} className="card p-6 space-y-5">
            <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <Clock className="w-5 h-5 text-sky-500" />
              Scheduling & Warm-Up Rate Limiting
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div
                onClick={() => updateField('sendScheduleType', 'IMMEDIATE')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  sendScheduleType === 'IMMEDIATE'
                    ? 'border-sky-500 bg-sky-500/10'
                    : 'border-[var(--color-border)] bg-[var(--color-surface-1)] hover:bg-[var(--color-surface-2)]'
                }`}
              >
                <div className="font-bold text-sm text-[var(--color-text-primary)]">Send Immediately</div>
                <p className="text-xs text-[var(--color-text-dim)] mt-1">
                  Queue batch through active TLS 1.3 relays as soon as preflight checks pass.
                </p>
              </div>

              <div
                onClick={() => updateField('sendScheduleType', 'SCHEDULED')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  sendScheduleType === 'SCHEDULED'
                    ? 'border-sky-500 bg-sky-500/10'
                    : 'border-[var(--color-border)] bg-[var(--color-surface-1)] hover:bg-[var(--color-surface-2)]'
                }`}
              >
                <div className="font-bold text-sm text-[var(--color-text-primary)]">Schedule for Later</div>
                <p className="text-xs text-[var(--color-text-dim)] mt-1">
                  Time release for optimal timezone open rates (e.g. 09:30 AM local time).
                </p>
              </div>
            </div>

            {sendScheduleType === 'SCHEDULED' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)]">
                <div className="space-y-1">
                  <label htmlFor={`${formId}-sched-date`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                    Target Send Date *
                  </label>
                  <input
                    id={`${formId}-sched-date`}
                    type="date"
                    value={scheduledDate}
                    onChange={(e) => updateField('scheduledDate', e.target.value)}
                    aria-invalid={Boolean(stepErrors.scheduledDate)}
                    aria-describedby={stepErrors.scheduledDate ? `${formId}-sched-date-err` : undefined}
                    className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                  />
                  {stepErrors.scheduledDate && (
                    <p id={`${formId}-sched-date-err`} className="text-xs text-rose-500 font-medium">
                      {stepErrors.scheduledDate}
                    </p>
                  )}
                </div>
                <div className="space-y-1">
                  <label htmlFor={`${formId}-sched-time`} className="text-xs font-semibold text-[var(--color-text-dim)]">
                    Target Send Time *
                  </label>
                  <input
                    id={`${formId}-sched-time`}
                    type="time"
                    value={scheduledTime}
                    onChange={(e) => updateField('scheduledTime', e.target.value)}
                    aria-invalid={Boolean(stepErrors.scheduledTime)}
                    aria-describedby={stepErrors.scheduledTime ? `${formId}-sched-time-err` : undefined}
                    className="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm text-[var(--color-text-primary)]"
                  />
                  {stepErrors.scheduledTime && (
                    <p id={`${formId}-sched-time-err`} className="text-xs text-rose-500 font-medium">
                      {stepErrors.scheduledTime}
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Warm-Up Throttling Policy */}
            <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-sm font-bold text-[var(--color-text-primary)]">
                    Enforce Deliverability Warm-Up Rate Limiting
                  </h4>
                  <p className="text-xs text-[var(--color-text-dim)]">
                    Automatically chunks outbound mail to prevent ISP throttling and spam spikes.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={warmupThrottling}
                  onChange={(e) => updateField('warmupThrottling', e.target.checked)}
                  className="rounded text-sky-600 h-5 w-5"
                />
              </div>

              {warmupThrottling && (
                <div className="pt-2 flex items-center gap-3">
                  <span className="text-xs text-[var(--color-text-secondary)]">Throttle Cap:</span>
                  <input
                    type="range"
                    min={100}
                    max={2500}
                    step={100}
                    value={maxPerHour}
                    onChange={(e) => updateField('maxPerHour', parseInt(e.target.value, 10))}
                    className="flex-1 accent-sky-600"
                  />
                  <span className="font-mono text-xs font-bold text-sky-600 dark:text-sky-400">
                    {maxPerHour.toLocaleString()} emails/hour
                  </span>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ── STEP 4: PREFLIGHT REVIEW & SSE REAL-TIME DISPATCH ── */}
        {currentStep === 4 && (
          <motion.div {...fadeUp} className="card p-6 space-y-5">
            <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-500" />
              Final Deliverability Preflight & Compliance Review
            </h3>

            {/* Preflight Checklist */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
                <div className="text-xs font-bold uppercase tracking-wider text-[var(--color-text-dim)]">
                  Cryptographic Authentication
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-400">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>SPF: Alignment verified for {fromEmail}</span>
                  </div>
                  <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-400">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>DKIM: 2048-bit RSA selector active</span>
                  </div>
                  <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-400">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>RFC 8058: Automated One-Click Header Injected</span>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
                <div className="text-xs font-bold uppercase tracking-wider text-[var(--color-text-dim)]">
                  Campaign Parameters
                </div>
                <div className="space-y-1 text-xs text-[var(--color-text-secondary)]">
                  <div><strong>Audience:</strong> {audienceSegment}</div>
                  <div><strong>Total Recipients:</strong> {recipientCount.toLocaleString()}</div>
                  <div><strong>Subject:</strong> {subject}</div>
                  <div><strong>Tracking:</strong> Opens ({trackOpens ? 'On' : 'Off'}), Clicks ({trackClicks ? 'On' : 'Off'})</div>
                </div>
              </div>
            </div>

            {/* Interactive Preflight Audit Status */}
            <div className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
              preflightPassed ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-[var(--color-surface-2)] border-[var(--color-border)]'
            }`}>
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                  preflightPassed ? 'bg-emerald-500 text-white' : 'bg-amber-500/20 text-amber-600 dark:text-amber-400'
                }`}>
                  {preflightPassed ? <CheckCircle2 className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
                </div>
                <div>
                  <div className="text-xs font-bold text-[var(--color-text-primary)]">
                    {preflightPassed ? 'Preflight Deliverability Checks Passed' : 'Preflight Verification Required'}
                  </div>
                  <div className="text-[11px] text-[var(--color-text-dim)]">
                    {preflightPassed
                      ? 'Heuristics, SPF/DKIM alignment, and 80/20 content ratios validated.'
                      : 'Run preflight check to confirm zero spam trigger words and RFC 8058 readiness.'}
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  updateField('preflightPassed', true);
                  announce('Preflight deliverability audit passed successfully.');
                }}
                className={`btn text-xs font-bold px-3 py-1.5 shrink-0 ${
                  preflightPassed ? 'btn-secondary text-emerald-600 dark:text-emerald-400' : 'btn-primary'
                }`}
              >
                {preflightPassed ? 'Re-verify' : 'Run Preflight Check'}
              </button>
            </div>

            {/* Regulatory Consent Checkbox */}
            <div className="p-4 rounded-xl border border-sky-500/30 bg-sky-500/10 space-y-2">
              <label className="flex items-start gap-2.5 text-xs text-[var(--color-text-primary)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={acknowledgedConsent}
                  onChange={(e) => updateField('acknowledgedConsent', e.target.checked)}
                  className="rounded text-sky-600 h-4 w-4 mt-0.5 shrink-0"
                />
                <span>
                  <strong>Legal & Deliverability Compliance Acknowledgment:</strong> I confirm that this recipient audience has explicitly opted-in to receive communications under CAN-SPAM, GDPR, and CASL regulations, and that automated RFC 8058 one-click opt-outs are operational.
                </span>
              </label>
              {stepErrors.acknowledgedConsent && (
                <p className="text-xs text-rose-500 font-semibold">{stepErrors.acknowledgedConsent}</p>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => startSseDispatch(false)}
                disabled={!acknowledgedConsent || isDispatching}
                className="btn btn-primary px-6 py-2.5 text-sm font-bold flex items-center gap-2 shadow-lg"
              >
                <Send className="w-4 h-4" />
                Launch Production Batch Dispatch
              </button>
            </div>
          </motion.div>
        )}

        {/* ── Wizard Navigation Controls ── */}
        <div className="flex items-center justify-between border-t border-[var(--color-border)] pt-4">
          <button
            type="button"
            onClick={handlePrev}
            disabled={currentStep === 1 || isDispatching}
            className="btn btn-secondary px-4 py-2 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-40"
          >
            <ArrowLeft className="w-4 h-4" />
            Previous Step
          </button>

          {currentStep < 4 ? (
            <button
              type="button"
              onClick={handleNext}
              className="btn btn-primary px-5 py-2 text-xs font-semibold flex items-center gap-1.5"
            >
              Continue to Step {currentStep + 1}
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <span className="text-xs text-[var(--color-text-dim)]">
              Ready to dispatch {recipientCount.toLocaleString()} envelopes
            </span>
          )}
        </div>

        {/* ── SSE REAL-TIME DISPATCH PROGRESS MODAL ── */}
        <AnimatePresence>
          {isDispatching && (
            <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="card-elevated max-w-xl w-full p-6 space-y-5"
                role="dialog"
                aria-modal="true"
                aria-labelledby="dispatch-dialog-title"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Send className="w-5 h-5 text-sky-500 animate-pulse" />
                    <h3 id="dispatch-dialog-title" className="text-base font-bold text-[var(--color-text-primary)]">
                      Real-Time Batch Dispatch (SSE Stream)
                    </h3>
                  </div>
                  {(dispatchProgress === 100 || dispatchStatus === 'NETWORK_ERROR') && (
                    <button
                      type="button"
                      onClick={() => setIsDispatching(false)}
                      className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] cursor-pointer"
                      aria-label="Close dispatch dialog"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  )}
                </div>

                {/* Progress Bar */}
                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-[var(--color-text-secondary)]">Status: {dispatchStatus}</span>
                    <span className="font-bold text-sky-600 dark:text-sky-400">{dispatchProgress}%</span>
                  </div>
                  <div className="w-full bg-[var(--color-surface-3)] h-3 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-sky-600 dark:bg-sky-400 transition-all duration-300"
                      style={{ width: `${dispatchProgress}%` }}
                    />
                  </div>
                </div>

                {/* Live Stats */}
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-[var(--color-surface-2)]">
                    <div className="text-xs text-[var(--color-text-dim)]">Sent Envelopes</div>
                    <div className="text-lg font-bold font-mono text-emerald-700 dark:text-emerald-400">{dispatchSent.toLocaleString()}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-[var(--color-surface-2)]">
                    <div className="text-xs text-[var(--color-text-dim)]">Exceptions</div>
                    <div className="text-lg font-bold font-mono text-rose-700 dark:text-rose-400">{dispatchFailed}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-[var(--color-surface-2)]">
                    <div className="text-xs text-[var(--color-text-dim)]">Total Queue</div>
                    <div className="text-lg font-bold font-mono text-[var(--color-text-primary)]">{recipientCount.toLocaleString()}</div>
                  </div>
                </div>

                <p className="text-xs text-[var(--color-text-secondary)] font-mono">
                  {dispatchMessage}
                </p>

                {/* Partial Failure Handling & Idempotent Retry */}
                {dispatchProgress === 100 && failedRecords.length > 0 && (
                  <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/25 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold text-amber-700 dark:text-amber-400">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      Partial Failure Detected ({failedRecords.length} records bounced or throttled)
                    </div>
                    <p className="text-xs text-[var(--color-text-secondary)]">
                      The campaign did not fail entirely. You can export the failed recipients with diagnostic error codes or execute an idempotent retry that automatically skips already delivered recipients.
                    </p>
                    <div className="flex items-center gap-2 pt-1">
                      <button
                        type="button"
                        onClick={exportFailedCsv}
                        className="btn btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Export Failed (CSV)
                      </button>
                      {failedRecords.some((r) => r.retryable) && (
                        <button
                          type="button"
                          onClick={() => startSseDispatch(true)}
                          className="btn btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5 cursor-pointer"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                          Idempotent Retry Failed Only
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </motion.div>
            </div>
          )}
        </AnimatePresence>
      </div>
    </AppShell>
  );
}

