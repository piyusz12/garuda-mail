'use client';

import { motion } from 'framer-motion';
import { AlertTriangle, Shield, Network, ShieldAlert, Target, Cpu, ShieldCheck, Activity, FileSearch } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { RiskScore, PostureBar, SeverityDistribution, SeverityBadge, StatusBadge } from '@/components/ui/shared';
import { mockDashboard, mockSessions } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';

const fadeUp = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] },
};

const stagger = {
  animate: { transition: { staggerChildren: 0.06 } },
};

export default function DashboardPage() {
  const data = mockDashboard;

  return (
    <AppShell title="Command Center" description="Garuda Mail — Cryptographic Forensics Overview">
      <motion.div initial="initial" animate="animate" variants={stagger} className="space-y-6 max-w-[1400px] mx-auto pb-12">

        {/* ── Row 1: KPIs ── */}
        <motion.div variants={stagger} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div variants={fadeUp}>
            <DashboardMetricCard
              label="Sessions Analyzed"
              value={data.sessionsAnalyzed}
              sub="From 3 captures"
              accent="accent"
              icon={Network}
            />
          </motion.div>
          <motion.div variants={fadeUp}>
            <DashboardMetricCard
              label="Total Findings"
              value={data.findingsSummary.total}
              sub={`${data.findingsSummary.critical} critical, ${data.findingsSummary.high} high`}
              accent="critical"
              icon={ShieldAlert}
            />
          </motion.div>
          <motion.div variants={fadeUp}>
            <DashboardMetricCard
              label="Affected Assets"
              value={data.affectedAssets}
              sub="Unique hosts with findings"
              accent="high"
              icon={Target}
            />
          </motion.div>
          <motion.div variants={fadeUp}>
            <DashboardMetricCard
              label="AI Anomalies"
              value="9"
              sub="Across 248 sessions"
              accent="accent"
              icon={Cpu}
            />
          </motion.div>
        </motion.div>

        {/* ── Row 2: Risk + Severity + Posture ── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">

          {/* Risk Score */}
          <motion.div variants={fadeUp} className="lg:col-span-3 card p-6 flex flex-col items-center justify-center relative overflow-hidden border border-[var(--color-severity-high)]/20 shadow-md">
            <div className="absolute inset-0 bg-[var(--color-severity-high)]/5 pointer-events-none" />
            <div className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-6 z-10 text-center">
              Current Security Posture<br/>
              <span className="text-[var(--color-severity-high)]">Overall Assessment</span>
            </div>
            <div className="z-10 scale-110 mb-5 drop-shadow-md">
              <RiskScore score={data.risk.overallScore} size="lg" />
            </div>
            <div className="mt-4 w-full grid grid-cols-2 gap-x-3 gap-y-3 text-center z-10">
              <div className="bg-[var(--color-surface-1)] rounded-lg p-2.5 border border-[var(--color-border-subtle)] shadow-sm">
                <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-0.5">Rule Base</div>
                <div className="text-[14px] font-bold text-[var(--color-text-primary)] tabular-nums">{data.risk.ruleContribution}%</div>
              </div>
              <div className="bg-[var(--color-surface-1)] rounded-lg p-2.5 border border-[var(--color-border-subtle)] shadow-sm">
                <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-0.5">Anomaly</div>
                <div className="text-[14px] font-bold text-[var(--color-text-primary)] tabular-nums">{data.risk.aiAnomalyContribution}%</div>
              </div>
              <div className="bg-[var(--color-surface-1)] rounded-lg p-2.5 border border-[var(--color-border-subtle)] shadow-sm">
                <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-0.5">Context</div>
                <div className="text-[14px] font-bold text-[var(--color-text-primary)] tabular-nums">{data.risk.contextContribution}%</div>
              </div>
              <div className="bg-[var(--color-surface-1)] rounded-lg p-2.5 border border-[var(--color-border-subtle)] shadow-sm">
                <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-0.5">Confidence</div>
                <div className="text-[14px] font-bold text-[var(--color-text-primary)] tabular-nums">{data.risk.confidenceContribution}%</div>
              </div>
            </div>
          </motion.div>

          {/* Finding Severity Distribution */}
          <motion.div variants={fadeUp} className="lg:col-span-4 card p-6 flex flex-col shadow-sm border border-[var(--color-border)]">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-2">
                <Activity size={16} className="text-[var(--color-text-dim)]" />
                <span className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">
                  Severity Distribution
                </span>
              </div>
              <Link href="/findings" className="text-[11px] font-bold text-[var(--color-accent)] hover:text-[var(--color-text-primary)] transition-colors">View all →</Link>
            </div>

            <div className="mb-10 mt-2">
              <SeverityDistribution
                critical={data.findingsSummary.critical}
                high={data.findingsSummary.high}
                medium={data.findingsSummary.medium}
                low={data.findingsSummary.low}
                informational={data.findingsSummary.informational}
              />
            </div>

            <div className="grid grid-cols-5 gap-2 mt-auto">
              {[
                { label: 'Critical', count: data.findingsSummary.critical, color: 'text-[var(--color-severity-critical)]', bg: 'bg-[var(--color-severity-critical-bg)]', border: 'border-[var(--color-severity-critical)]/30' },
                { label: 'High', count: data.findingsSummary.high, color: 'text-[var(--color-severity-high)]', bg: 'bg-[var(--color-severity-high)]/10', border: 'border-[var(--color-severity-high)]/30' },
                { label: 'Medium', count: data.findingsSummary.medium, color: 'text-[var(--color-severity-medium)]', bg: 'bg-[var(--color-severity-medium)]/10', border: 'border-[var(--color-severity-medium)]/30' },
                { label: 'Low', count: data.findingsSummary.low, color: 'text-[var(--color-severity-low)]', bg: 'bg-[var(--color-severity-low)]/10', border: 'border-[var(--color-severity-low)]/30' },
                { label: 'Info', count: data.findingsSummary.informational, color: 'text-[var(--color-text-secondary)]', bg: 'bg-[var(--color-surface-2)]', border: 'border-[var(--color-border-subtle)]' },
              ].map(item => (
                <div key={item.label} className={clsx("flex flex-col items-center justify-center p-2 rounded-lg border", item.bg, item.border)}>
                  <div className={clsx('text-[16px] sm:text-xl font-bold tabular-nums leading-none mb-1', item.color)}>{item.count}</div>
                  <div className="text-[8px] sm:text-[9px] font-bold text-[var(--color-text-dim)] uppercase tracking-wider">{item.label}</div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Security Posture */}
          <motion.div variants={fadeUp} className="lg:col-span-5 card p-6 flex flex-col justify-between shadow-sm border border-[var(--color-border)]">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-2">
                <ShieldCheck size={16} className="text-[var(--color-text-dim)]" />
                <span className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">
                  Cryptographic Posture
                </span>
              </div>
              <Link href="/crypto" className="text-[11px] font-bold text-[var(--color-accent)] hover:text-[var(--color-text-primary)] transition-colors">Details →</Link>
            </div>
            <div className="space-y-5">
              <PostureBar {...data.posture.tlsPosture} />
              <PostureBar {...data.posture.certificateHealth} />
              <PostureBar {...data.posture.forwardSecrecy} />
              <PostureBar {...data.posture.starttlsAdoption} />
              <PostureBar {...data.posture.cryptoCompliance} />
              <PostureBar {...data.posture.aiAnomalyActivity} />
            </div>
          </motion.div>
        </div>

        {/* ── Row 3: Recent Findings + Recent Sessions ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Recent Findings */}
          <motion.div variants={fadeUp} className="card p-6 flex flex-col shadow-sm border border-[var(--color-border)]">
            <div className="flex items-center justify-between mb-6 border-b border-[var(--color-border-subtle)] pb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle size={16} className="text-[var(--color-severity-critical)]" />
                <span className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">
                  Recent Findings
                </span>
              </div>
              <Link href="/findings" className="text-[11px] font-bold text-[var(--color-accent)] hover:text-[var(--color-text-primary)] transition-colors">View all →</Link>
            </div>
            <div className="space-y-3 flex-1 overflow-y-auto pr-1 hide-scrollbar">
              {data.recentFindings.map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="flex items-center gap-4 p-3.5 rounded-xl border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] hover:bg-[var(--color-surface-2)] transition-all group"
                >
                  <div className="shrink-0">
                    <SeverityBadge severity={finding.severity} size="sm" />
                  </div>
                  <div className="flex-1 min-w-0 flex flex-col justify-center">
                    <div className="text-[13px] font-bold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] truncate transition-colors mb-1">
                      {finding.title}
                    </div>
                    <div className="text-[11px] text-[var(--color-text-dim)] font-medium truncate flex items-center gap-2">
                      <span className="px-1.5 py-0.5 bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] rounded-sm font-mono text-[9px] border border-[var(--color-border-subtle)]">{finding.id}</span>
                      <span>•</span>
                      <span className="truncate">{finding.affectedAssets.join(', ')}</span>
                      <span>•</span>
                      <span className="truncate">{finding.category}</span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </motion.div>

          {/* Recent Sessions */}
          <motion.div variants={fadeUp} className="card p-6 flex flex-col shadow-sm border border-[var(--color-border)]">
            <div className="flex items-center justify-between mb-6 border-b border-[var(--color-border-subtle)] pb-4">
              <div className="flex items-center gap-2">
                <Network size={16} className="text-[var(--color-accent)]" />
                <span className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">
                  Recent Sessions
                </span>
              </div>
              <Link href="/sessions" className="text-[11px] font-bold text-[var(--color-accent)] hover:text-[var(--color-text-primary)] transition-colors">View all →</Link>
            </div>
            <div className="overflow-x-auto flex-1 hide-scrollbar">
              <table className="w-full min-w-[420px]">
                <thead>
                  <tr className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] border-b border-[var(--color-border-subtle)]">
                    <th className="text-left pb-3 font-bold px-1">ID</th>
                    <th className="text-left pb-3 font-bold px-1">Protocol</th>
                    <th className="text-left pb-3 font-bold px-1">Destination</th>
                    <th className="text-left pb-3 font-bold px-1">TLS</th>
                    <th className="text-center pb-3 font-bold px-1">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-subtle)]">
                  {mockSessions.slice(0, 6).map((session) => (
                    <tr key={session.id} className="hover:bg-[var(--color-surface-2)] transition-colors group">
                      <td className="py-3 px-1">
                        <Link href={`/sessions/${session.id}`} className="text-[12px] font-mono font-bold text-[var(--color-text-secondary)] group-hover:text-[var(--color-accent)] transition-colors">
                          {session.id}
                        </Link>
                      </td>
                      <td className="py-3 px-1">
                        <span className="text-[11px] font-bold px-2 py-0.5 rounded-sm bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] border border-[var(--color-border-subtle)]">
                          {session.protocol}
                        </span>
                      </td>
                      <td className="py-3 px-1">
                        <span className="text-[12px] text-mono font-medium text-[var(--color-text-primary)]">{session.destHostname || session.destIp}</span>
                      </td>
                      <td className="py-3 px-1">
                        {session.tlsVersion ? (
                          <span className="text-[11px] font-mono font-bold text-[var(--color-severity-healthy)] border border-[var(--color-severity-healthy)]/30 bg-[var(--color-severity-healthy)]/10 px-1.5 py-0.5 rounded-sm">
                            {session.tlsVersion}
                          </span>
                        ) : (
                          <span className="text-[11px] font-mono font-bold text-[var(--color-severity-critical)] border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical-bg)] px-1.5 py-0.5 rounded-sm">
                            NONE
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-1 text-center">
                        <SeverityBadge severity={session.risk} size="xs" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        </div>

        {/* ── Row 4: Recent Analyses ── */}
        <motion.div variants={fadeUp} className="card p-6 shadow-sm border border-[var(--color-border)]">
          <div className="flex items-center justify-between mb-6 border-b border-[var(--color-border-subtle)] pb-4">
            <div className="flex items-center gap-2">
              <FileSearch size={16} className="text-[var(--color-accent)]" />
              <span className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">
                Recent Analyses
              </span>
            </div>
            <Link href="/analysis" className="text-[11px] font-bold text-[var(--color-accent)] hover:text-[var(--color-text-primary)] transition-colors">New analysis →</Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {data.recentAnalyses.map((analysis) => (
              <div key={analysis.id} className="card p-5 border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] hover:bg-[var(--color-surface-2)] transition-all group flex flex-col relative overflow-hidden shadow-sm">

                <div className="flex items-start justify-between mb-4">
                  <div className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded-sm bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] border border-[var(--color-border-subtle)] z-10">
                    {analysis.id}
                  </div>
                  <div className="z-10">
                    <StatusBadge status={analysis.status} />
                  </div>
                </div>

                <div className="text-[14px] font-bold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors truncate mb-1.5 z-10">
                  {analysis.filename}
                </div>

                <div className="text-[11px] font-medium text-[var(--color-text-muted)] flex items-center gap-1.5 mb-5 z-10">
                  <span className="font-bold">{analysis.sessionsCount} Sessions</span>
                  <span className="text-[var(--color-border-subtle)]">|</span>
                  <span className={clsx("font-bold", analysis.findingsCount > 0 && "text-[var(--color-severity-critical)]")}>{analysis.findingsCount} Findings</span>
                </div>

                <div className="flex items-end justify-between mt-auto pt-4 border-t border-[var(--color-border-subtle)] z-10">
                  <div>
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-1.5">Risk Score</div>
                    <RiskScore score={analysis.overallRisk} size="sm" />
                  </div>
                  <div className="text-right flex flex-col justify-end">
                    <div className="text-[11px] font-mono font-bold text-[var(--color-text-secondary)] mb-0.5">{formatBytes(analysis.fileSize)}</div>
                    <div className="text-[10px] font-medium text-[var(--color-text-dim)]">{formatDate(analysis.startedAt)}</div>
                  </div>
                </div>

                {/* Subtle Hover Glow */}
                <div className="absolute -bottom-8 -right-8 w-24 h-24 rounded-full blur-3xl opacity-0 group-hover:opacity-10 transition-opacity duration-500 bg-[var(--color-text-secondary)] pointer-events-none" />
              </div>
            ))}
          </div>
        </motion.div>

      </motion.div>
    </AppShell>
  );
}

function DashboardMetricCard({ label, value, sub, accent, icon: Icon }: any) {
  const accentColors: any = {
    critical: 'text-[var(--color-severity-critical)]',
    high: 'text-[var(--color-severity-high)]',
    accent: 'text-[var(--color-accent)]',
    healthy: 'text-[var(--color-severity-healthy)]',
  };
  const bgColors: any = {
    critical: 'group-hover:bg-[var(--color-severity-critical-bg)] hover:border-[var(--color-severity-critical)]/30 border-[var(--color-border-subtle)]',
    high: 'group-hover:bg-[var(--color-severity-high)]/5 hover:border-[var(--color-severity-high)]/30 border-[var(--color-border-subtle)]',
    accent: 'group-hover:bg-[var(--color-accent-dim)] hover:border-[var(--color-accent)]/30 border-[var(--color-border-subtle)]',
    healthy: 'group-hover:bg-[var(--color-severity-healthy)]/5 hover:border-[var(--color-severity-healthy)]/30 border-[var(--color-border-subtle)]',
  };

  const selectedAccent = accentColors[accent] || accentColors.accent;
  const selectedBg = bgColors[accent] || bgColors.accent;

  return (
    <div className={clsx("card p-5 relative overflow-hidden transition-all duration-300 group border bg-[var(--color-surface-1)] shadow-sm h-full flex flex-col", selectedBg)}>
      <div className="flex items-start justify-between mb-3 z-10 relative">
        <div className="text-[10px] sm:text-[11px] font-bold uppercase tracking-widest text-[var(--color-text-dim)]">{label}</div>
        <Icon size={16} className={clsx("opacity-40 group-hover:opacity-100 transition-opacity", selectedAccent)} />
      </div>
      <div className={clsx("text-2xl sm:text-3xl font-bold tracking-tight z-10 relative mt-auto", selectedAccent)}>
        {value}
      </div>
      {sub && (
        <div className="text-[11px] font-medium text-[var(--color-text-muted)] mt-1.5 z-10 relative truncate">{sub}</div>
      )}

      {/* Background ambient glow on hover */}
      <div className={clsx("absolute -bottom-10 -right-10 w-28 h-28 rounded-full blur-2xl opacity-0 group-hover:opacity-20 transition-opacity duration-500 pointer-events-none",
        accent === 'critical' ? 'bg-[var(--color-severity-critical)]' :
        accent === 'high' ? 'bg-[var(--color-severity-high)]' :
        accent === 'healthy' ? 'bg-[var(--color-severity-healthy)]' :
        'bg-[var(--color-accent)]'
      )} />
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(1)} GB`;
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
