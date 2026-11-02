'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe, ShieldCheck, Key, AlertTriangle, CheckCircle2,
  Copy, Check, RefreshCw, Zap, Sliders, ExternalLink,
  Info, TrendingUp, Clock, HelpCircle, ArrowRight
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { useAnnounce } from '@/components/common/AriaLiveAnnouncer';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

interface DnsRecordView {
  protocol: 'SPF' | 'DKIM' | 'DMARC';
  friendlyName: string;
  conceptTranslation: string;
  recordType: 'TXT' | 'CNAME';
  host: string;
  expectedValue: string;
  foundValue: string | null;
  isVerified: boolean;
  statusText: string;
  ttlSeconds: number | null;
}

export default function DomainOnboardingPage() {
  const announce = useAnnounce();
  const [domain, setDomain] = useState('enterprise-cyber.org');
  const [selector, setSelector] = useState('garuda');
  const [setupMode, setSetupMode] = useState<'express' | 'advanced'>('advanced');
  const [isVerifying, setIsVerifying] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // DNS Verification State
  const [records, setRecords] = useState<{
    spf: DnsRecordView;
    dkim: DnsRecordView;
    dmarc: DnsRecordView;
  }>({
    spf: {
      protocol: 'SPF',
      friendlyName: 'Sender Policy Framework (SPF)',
      conceptTranslation: 'Authorize Garuda Mail to send on your behalf ("The Guest List"). Prevents spoofers from forging your domain.',
      recordType: 'TXT',
      host: '@',
      expectedValue: 'v=spf1 include:_spf.garudamail.com ~all',
      foundValue: 'v=spf1 include:_spf.garudamail.com ~all',
      isVerified: true,
      statusText: 'Authenticated (Active)',
      ttlSeconds: 300,
    },
    dkim: {
      protocol: 'DKIM',
      friendlyName: 'DomainKeys Identified Mail (DKIM)',
      conceptTranslation: 'Attaches a tamper-proof cryptographic signature to every outgoing payload using 2048-bit asymmetric keys.',
      recordType: 'TXT',
      host: `${selector}._domainkey`,
      expectedValue: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0tG...',
      foundValue: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0tG...',
      isVerified: true,
      statusText: '2048-bit Signature Valid',
      ttlSeconds: 300,
    },
    dmarc: {
      protocol: 'DMARC',
      friendlyName: 'Domain-based Message Authentication (DMARC)',
      conceptTranslation: 'Instructs major mailbox providers (Gmail, Yahoo, Outlook) how to handle suspicious emails claiming to be you.',
      recordType: 'TXT',
      host: '_dmarc',
      expectedValue: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@garudamail.com; pct=100; aspf=r; adkim=r',
      foundValue: null,
      isVerified: false,
      statusText: 'DMARC Policy Missing',
      ttlSeconds: 3600,
    },
  });

  const [warmupData, setWarmupData] = useState<any[]>([]);
  const [currentDay, setCurrentDay] = useState(8);

  const [verifiedTarget, setVerifiedTarget] = useState<{ domain: string; selector: string } | null>({
    domain: 'enterprise-cyber.org',
    selector: 'garuda'
  });

  const handleDomainChange = (val: string) => {
    setDomain(val);
    setVerifiedTarget(null);
  };

  const handleSelectorChange = (val: string) => {
    setSelector(val);
    setVerifiedTarget(null);
  };

  useEffect(() => {
    // Fetch warmup schedule trajectory
    fetch('/api/domains/warmup?day=8')
      .then((res) => res.json())
      .then((data) => {
        if (data.success && data.data?.recommendedSchedule) {
          setWarmupData(data.data.recommendedSchedule);
        }
      })
      .catch(() => {});
  }, []);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    announce(`Copied ${key} to clipboard`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    announce('Initiating real-time DNS propagation check...');
    try {
      const res = await fetch('/api/domains/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, selector }),
      });
      const data = await res.json();
      if (data.success && data.data?.records) {
        setRecords(data.data.records);
        setVerifiedTarget({ domain, selector });
        announce('DNS propagation check complete.');
      }
    } catch {
      announce('DNS verification request failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const isTargetVerified = verifiedTarget !== null && verifiedTarget.domain.toLowerCase().trim() === domain.toLowerCase().trim() && verifiedTarget.selector.toLowerCase().trim() === selector.toLowerCase().trim();
  const isFullyCompliant = isTargetVerified && Boolean(records.spf?.isVerified && records.dkim?.isVerified && records.dmarc?.isVerified);
  const verifiedCount = isTargetVerified ? [records.spf?.isVerified, records.dkim?.isVerified, records.dmarc?.isVerified].filter(Boolean).length : 0;
  const missingCount = 3 - verifiedCount;

  return (
    <AppShell
      title="Domain Authentication & Deliverability Onboarding"
      description="Configure SPF, DKIM, and DMARC alignment required by Google & Yahoo 2024–2026 bulk sender regulations."
    >
      <div className="max-w-6xl mx-auto space-y-6">
        {/* ── Top Status Banner ── */}
        <motion.div {...fadeUp} className="card-elevated p-6 border-l-4 border-l-sky-500 space-y-4">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Globe className="w-5 h-5 text-sky-500" />
                <h2 className="text-lg font-bold text-[var(--color-text-primary)]">
                  Active Domain: <span className="font-mono text-sky-600 dark:text-sky-400">{domain || 'custom-domain.com'}</span>
                </h2>
                {isFullyCompliant ? (
                  <span className="badge badge-healthy flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Fully Authenticated
                  </span>
                ) : (
                  <span className="badge badge-high flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Action Required ({missingCount} {missingCount === 1 ? 'Record' : 'Records'} Missing)
                  </span>
                )}
              </div>
              <p className="text-sm text-[var(--color-text-dim)]">
                Mailbox providers enforce SPF, DKIM, and DMARC for senders dispatching &gt;5,000 emails/day. Missing records result in spam routing or outright rejection.
              </p>
            </div>

            <button
              onClick={handleVerify}
              disabled={isVerifying || !domain.trim()}
              className="btn btn-primary flex items-center gap-2 px-4 py-2 shrink-0 text-sm font-semibold cursor-pointer disabled:opacity-50"
              aria-label="Verify DNS propagation"
            >
              <RefreshCw className={`w-4 h-4 ${isVerifying ? 'animate-spin' : ''}`} />
              {isVerifying ? 'Polling Resolvers...' : 'Check DNS Records'}
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-[var(--color-border)]">
            <div className="sm:col-span-2 space-y-1">
              <label htmlFor="domain-input" className="text-xs font-semibold text-[var(--color-text-dim)]">
                Target Sending Domain
              </label>
              <input
                id="domain-input"
                type="text"
                value={domain}
                onChange={(e) => handleDomainChange(e.target.value)}
                placeholder="e.g. enterprise-cyber.org"
                className="w-full px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm font-mono text-[var(--color-text-primary)]"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="selector-input" className="text-xs font-semibold text-[var(--color-text-dim)]">
                DKIM Selector
              </label>
              <input
                id="selector-input"
                type="text"
                value={selector}
                onChange={(e) => handleSelectorChange(e.target.value)}
                placeholder="e.g. garuda"
                className="w-full px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-sm font-mono text-[var(--color-text-primary)]"
              />
            </div>
          </div>
        </motion.div>

        {/* ── Path Switcher: Express vs Advanced ── */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setSetupMode('express')}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition ${
                setupMode === 'express'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-2)]'
              }`}
              aria-pressed={setupMode === 'express'}
            >
              <Zap className="w-4 h-4" />
              Express 1-Click Setup (API)
            </button>
            <button
              type="button"
              onClick={() => setSetupMode('advanced')}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition ${
                setupMode === 'advanced'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-2)]'
              }`}
              aria-pressed={setupMode === 'advanced'}
            >
              <Sliders className="w-4 h-4" />
              Advanced Manual DNS Records
            </button>
          </div>
          <span className="text-xs text-[var(--color-text-dim)] hidden sm:inline">
            TTL Polling Interval: <strong>30s</strong>
          </span>
        </div>

        {/* ── Express Route View ── */}
        {setupMode === 'express' ? (
          <motion.div {...fadeUp} className="card p-6 space-y-4">
            <h3 className="text-base font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
              <Zap className="w-5 h-5 text-amber-500" />
              Automated Registrar Integration
            </h3>
            <p className="text-sm text-[var(--color-text-secondary)]">
              Garuda Mail can securely provision your SPF, DKIM, and DMARC TXT records in seconds via authenticated DNS APIs.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
              {[
                { name: 'Cloudflare DNS', status: 'Connected', auto: true },
                { name: 'AWS Route 53', status: 'Available', auto: false },
                { name: 'Namecheap / GoDaddy', status: 'Available', auto: false },
              ].map((provider) => (
                <div key={provider.name} className="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] flex flex-col justify-between space-y-3">
                  <div className="font-semibold text-[var(--color-text-primary)] text-sm">{provider.name}</div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-sky-600 dark:text-sky-400 font-medium">{provider.status}</span>
                    <button
                      type="button"
                      className="text-xs btn btn-secondary px-2.5 py-1"
                      onClick={() => handleVerify()}
                    >
                      Provision
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        ) : (
          /* ── Advanced Manual Path (The 3 Pillars of Email Authentication) ── */
          <div className="space-y-4">
            {(['spf', 'dkim', 'dmarc'] as const).map((protoKey) => {
              const rec = records[protoKey];
              return (
                <motion.div
                  key={protoKey}
                  {...fadeUp}
                  className="card p-5 space-y-3 hover:border-sky-500/40 transition"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-base text-[var(--color-text-primary)]">{rec.friendlyName}</span>
                        <span className="text-xs px-2 py-0.5 rounded font-mono font-medium bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]">
                          {rec.recordType}
                        </span>
                      </div>
                      <p className="text-xs text-sky-700 dark:text-sky-300 italic">
                        {rec.conceptTranslation}
                      </p>
                    </div>

                    <div>
                      {rec.isVerified ? (
                        <span className="badge badge-healthy flex items-center gap-1 text-xs">
                          <CheckCircle2 className="w-3.5 h-3.5" /> {rec.statusText}
                        </span>
                      ) : (
                        <span className="badge badge-high flex items-center gap-1 text-xs">
                          <AlertTriangle className="w-3.5 h-3.5" /> {rec.statusText}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Copyable DNS Parameters */}
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-3 pt-2">
                    <div className="md:col-span-3 space-y-1">
                      <label className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-dim)]">Host / Name</label>
                      <div className="flex items-center justify-between bg-[var(--color-surface-2)] px-3 py-2 rounded-lg border border-[var(--color-border)]">
                        <code className="text-xs font-mono text-[var(--color-text-primary)] truncate">{rec.host}</code>
                        <button
                          type="button"
                          onClick={() => handleCopy(`${protoKey}-host`, rec.host)}
                          className="text-[var(--color-text-muted)] hover:text-sky-500 ml-2"
                          aria-label={`Copy ${rec.protocol} Host`}
                        >
                          {copiedKey === `${protoKey}-host` ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    <div className="md:col-span-9 space-y-1">
                      <label className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-dim)]">Value / Content</label>
                      <div className="flex items-center justify-between bg-[var(--color-surface-2)] px-3 py-2 rounded-lg border border-[var(--color-border)]">
                        <code className="text-xs font-mono text-[var(--color-text-primary)] truncate pr-2">{rec.expectedValue}</code>
                        <button
                          type="button"
                          onClick={() => handleCopy(`${protoKey}-val`, rec.expectedValue)}
                          className="text-[var(--color-text-muted)] hover:text-sky-500 shrink-0"
                          aria-label={`Copy ${rec.protocol} Value`}
                        >
                          {copiedKey === `${protoKey}-val` ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}

        {/* ── Deliverability Warm-Up Schedule Trajectory ── */}
        <motion.div {...fadeUp} className="card p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-sky-500" />
                Continuous Monitoring & Automated Deliverability Warm-Up Schedule
              </h3>
              <p className="text-xs text-[var(--color-text-dim)]">
                Mandatory 28-day volume ramping trajectory establishing sender reputation before launching unrestricted commercial sends.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-sky-500/10 text-sky-600 dark:text-sky-400 font-semibold border border-sky-500/20">
                Day {currentDay} of 28 (Stage 3)
              </span>
            </div>
          </div>

          <div className="h-64 w-full pt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={warmupData}>
                <defs>
                  <linearGradient id="warmupGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0284C7" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#0284C7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#64748B" fontSize={11} tickFormatter={(val) => `Day ${val}`} />
                <YAxis stroke="#64748B" fontSize={11} tickFormatter={(val) => val >= 1000 ? `${val / 1000}k` : val} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const d = payload[0].payload;
                      return (
                        <div className="bg-[var(--color-surface-1)] p-3 rounded-lg border border-[var(--color-border)] shadow-xl text-xs space-y-1">
                          <p className="font-bold text-[var(--color-text-primary)]">Day {d.day}: {d.stageName}</p>
                          <p className="text-sky-600 dark:text-sky-400 font-semibold">Daily Limit: {d.dailyLimit.toLocaleString()} emails</p>
                          <p className="text-[var(--color-text-dim)]">Hourly Throttle: {d.hourlyRateLimit}/hr</p>
                          <p className="text-xs italic text-[var(--color-text-secondary)]">{d.focus}</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Area type="monotone" dataKey="dailyLimit" stroke="#0284C7" strokeWidth={2.5} fillOpacity={1} fill="url(#warmupGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Accessible Table Fallback for Screen Readers (WCAG 1.3.1) */}
          <details className="text-xs text-[var(--color-text-dim)] cursor-pointer">
            <summary className="hover:text-[var(--color-text-primary)] py-1">View tabular warm-up schedule data (accessible fallback)</summary>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left border-collapse border border-[var(--color-border)]">
                <thead>
                  <tr className="bg-[var(--color-surface-2)]">
                    <th className="p-2 border border-[var(--color-border)]">Day</th>
                    <th className="p-2 border border-[var(--color-border)]">Stage</th>
                    <th className="p-2 border border-[var(--color-border)]">Daily Cap</th>
                    <th className="p-2 border border-[var(--color-border)]">Throttle</th>
                  </tr>
                </thead>
                <tbody>
                  {warmupData.map((row) => (
                    <tr key={row.day}>
                      <td className="p-2 border border-[var(--color-border)]">{row.day}</td>
                      <td className="p-2 border border-[var(--color-border)]">{row.stageName}</td>
                      <td className="p-2 border border-[var(--color-border)]">{row.dailyLimit}</td>
                      <td className="p-2 border border-[var(--color-border)]">{row.hourlyRateLimit}/hr</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        </motion.div>
      </div>
    </AppShell>
  );
}

