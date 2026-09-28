'use client';

import { motion } from 'framer-motion';
import { AlertTriangle, Shield, Network, Clock, TrendingUp, FileSearch, Activity } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { MetricCard, RiskScore, PostureBar, SeverityBadge, SeverityDistribution, StatusBadge } from '@/components/ui/shared';
import { mockDashboard, mockSessions, mockFindings } from '@/lib/mock/data';
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
      <motion.div initial="initial" animate="animate" variants={stagger} className="space-y-6">

        {/* ── Row 1: KPIs ── */}
        <motion.div variants={stagger} className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div variants={fadeUp}>
            <MetricCard label="Sessions Analyzed" value={data.sessionsAnalyzed} sub="From 3 captures" accent="accent" />
          </motion.div>
          <motion.div variants={fadeUp}>
            <MetricCard label="Total Findings" value={data.findingsSummary.total} sub={`${data.findingsSummary.critical} critical, ${data.findingsSummary.high} high`} accent="critical" />
          </motion.div>
          <motion.div variants={fadeUp}>
            <MetricCard label="Affected Assets" value={data.affectedAssets} sub="Unique hosts with findings" accent="high" />
          </motion.div>
          <motion.div variants={fadeUp}>
            <MetricCard label="AI Anomalies" value="9" sub="Across 248 sessions" accent="accent" />
          </motion.div>
        </motion.div>

        {/* ── Row 2: Risk + Severity + Posture ── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Risk Score */}
          <motion.div variants={fadeUp} className="lg:col-span-3 card p-6 flex flex-col items-center justify-center">
            <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium mb-4">
              Overall Risk Score
            </div>
            <RiskScore score={data.risk.overallScore} size="lg" />
            <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-1 text-center">
              <div>
                <div className="text-[10px] text-[var(--color-text-dim)]">Rule-based</div>
                <div className="text-[13px] font-semibold text-[var(--color-text-secondary)] tabular-nums">{data.risk.ruleContribution}%</div>
              </div>
              <div>
                <div className="text-[10px] text-[var(--color-text-dim)]">AI Anomaly</div>
                <div className="text-[13px] font-semibold text-[var(--color-text-secondary)] tabular-nums">{data.risk.aiAnomalyContribution}%</div>
              </div>
              <div>
                <div className="text-[10px] text-[var(--color-text-dim)]">Context</div>
                <div className="text-[13px] font-semibold text-[var(--color-text-secondary)] tabular-nums">{data.risk.contextContribution}%</div>
              </div>
              <div>
                <div className="text-[10px] text-[var(--color-text-dim)]">Confidence</div>
                <div className="text-[13px] font-semibold text-[var(--color-text-secondary)] tabular-nums">{data.risk.confidenceContribution}%</div>
              </div>
            </div>
          </motion.div>

          {/* Finding Severity Distribution */}
          <motion.div variants={fadeUp} className="lg:col-span-4 card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">
                Finding Severity Distribution
              </div>
              <Link href="/findings" className="text-[11px] text-[var(--color-accent)] hover:underline">View all →</Link>
            </div>
            <SeverityDistribution
              critical={data.findingsSummary.critical}
              high={data.findingsSummary.high}
              medium={data.findingsSummary.medium}
              low={data.findingsSummary.low}
              informational={data.findingsSummary.informational}
            />
            <div className="mt-5 grid grid-cols-5 gap-2 text-center">
              {[
                { label: 'Critical', count: data.findingsSummary.critical, color: 'text-[var(--color-severity-critical)]' },
                { label: 'High', count: data.findingsSummary.high, color: 'text-[var(--color-severity-high)]' },
                { label: 'Medium', count: data.findingsSummary.medium, color: 'text-[var(--color-severity-medium)]' },
                { label: 'Low', count: data.findingsSummary.low, color: 'text-[var(--color-severity-low)]' },
                { label: 'Info', count: data.findingsSummary.informational, color: 'text-[var(--color-severity-info)]' },
              ].map(item => (
                <div key={item.label} className="card p-2.5">
                  <div className={clsx('text-xl font-bold tabular-nums', item.color)}>{item.count}</div>
                  <div className="text-[9px] text-[var(--color-text-dim)] uppercase tracking-wider">{item.label}</div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Security Posture */}
          <motion.div variants={fadeUp} className="lg:col-span-5 card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">
                Security Posture
              </div>
              <Link href="/crypto" className="text-[11px] text-[var(--color-accent)] hover:underline">Details →</Link>
            </div>
            <div className="space-y-4">
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
          <motion.div variants={fadeUp} className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle size={14} className="text-[var(--color-severity-critical)]" />
                <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">
                  Recent Findings
                </span>
              </div>
              <Link href="/findings" className="text-[11px] text-[var(--color-accent)] hover:underline">View all →</Link>
            </div>
            <div className="space-y-2">
              {data.recentFindings.map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="flex items-start gap-3 p-3 rounded-md hover:bg-[var(--color-surface-2)] transition-colors group"
                >
                  <SeverityBadge severity={finding.severity} size="xs" />
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] font-medium text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] truncate transition-colors">
                      {finding.title}
                    </div>
                    <div className="text-[11px] text-[var(--color-text-muted)] mt-0.5 truncate">
                      {finding.affectedAssets.join(', ')} • {finding.category}
                    </div>
                  </div>
                  <span className="text-[10px] text-[var(--color-text-dim)] text-mono shrink-0">{finding.id}</span>
                </Link>
              ))}
            </div>
          </motion.div>

          {/* Recent Sessions */}
          <motion.div variants={fadeUp} className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Network size={14} className="text-[var(--color-accent)]" />
                <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">
                  Recent Sessions
                </span>
              </div>
              <Link href="/sessions" className="text-[11px] text-[var(--color-accent)] hover:underline">View all →</Link>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] border-b border-default">
                    <th className="text-left pb-2 font-medium">ID</th>
                    <th className="text-left pb-2 font-medium">Protocol</th>
                    <th className="text-left pb-2 font-medium">Destination</th>
                    <th className="text-left pb-2 font-medium">TLS</th>
                    <th className="text-center pb-2 font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {mockSessions.slice(0, 6).map((session) => (
                    <tr key={session.id} className="border-b border-[var(--color-border-subtle)] hover:bg-[var(--color-surface-2)] transition-colors">
                      <td className="py-2.5">
                        <Link href={`/sessions/${session.id}`} className="text-[12px] text-mono text-[var(--color-accent)] hover:underline">
                          {session.id}
                        </Link>
                      </td>
                      <td className="py-2.5 text-[12px] text-[var(--color-text-secondary)]">{session.protocol}</td>
                      <td className="py-2.5">
                        <span className="text-[12px] text-mono text-[var(--color-text-secondary)]">{session.destHostname || session.destIp}</span>
                      </td>
                      <td className="py-2.5">
                        <span className={clsx('text-[11px] text-mono', session.tlsVersion ? 'text-[var(--color-text-secondary)]' : 'text-[var(--color-severity-critical)]')}>
                          {session.tlsVersion || 'None'}
                        </span>
                      </td>
                      <td className="py-2.5 text-center">
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
        <motion.div variants={fadeUp} className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <FileSearch size={14} className="text-[var(--color-accent)]" />
              <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">
                Recent Analyses
              </span>
            </div>
            <Link href="/analysis" className="text-[11px] text-[var(--color-accent)] hover:underline">New analysis →</Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {data.recentAnalyses.map((analysis) => (
              <div key={analysis.id} className="card p-4 card-hover">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] text-mono text-[var(--color-accent)]">{analysis.id}</span>
                  <StatusBadge status={analysis.status} />
                </div>
                <div className="text-[13px] font-medium text-[var(--color-text-primary)] truncate mb-1">
                  {analysis.filename}
                </div>
                <div className="text-[11px] text-[var(--color-text-muted)]">
                  {analysis.sessionsCount} sessions • {analysis.findingsCount} findings
                </div>
                <div className="flex items-center justify-between mt-3 pt-2 border-t border-[var(--color-border-subtle)]">
                  <RiskScore score={analysis.overallRisk} size="sm" />
                  <div className="text-right">
                    <div className="text-[10px] text-[var(--color-text-dim)]">{formatBytes(analysis.fileSize)}</div>
                    <div className="text-[10px] text-[var(--color-text-dim)]">{formatDate(analysis.startedAt)}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

      </motion.div>
    </AppShell>
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
