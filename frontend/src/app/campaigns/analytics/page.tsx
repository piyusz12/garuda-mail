'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  BarChart3, CheckCircle2, AlertTriangle, Users, Mail,
  MousePointerClick, Eye, ShieldAlert, Download, Filter,
  ArrowUpDown, Search, RefreshCw, Layers
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis,
  Tooltip, Legend, CartesianGrid
} from 'recharts';
import { useAnnounce } from '@/components/common/AriaLiveAnnouncer';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

interface CampaignMetricRow {
  id: string;
  name: string;
  audience: string;
  sentDate: string;
  totalSent: number;
  deliveryRate: number;
  openRate: number;
  ctr: number;
  hardBounces: number;
  spamComplaints: number;
  status: 'DELIVERED' | 'SENDING' | 'ATTENTION';
}

const SAMPLE_CAMPAIGNS: CampaignMetricRow[] = [
  {
    id: 'camp-01',
    name: 'Q4 Cryptographic Intelligence & RFC 8058 Directives',
    audience: 'Enterprise Security Officers',
    sentDate: '2026-11-02 14:30',
    totalSent: 4850,
    deliveryRate: 99.4,
    openRate: 46.8,
    ctr: 18.2,
    hardBounces: 24,
    spamComplaints: 1,
    status: 'DELIVERED',
  },
  {
    id: 'camp-02',
    name: 'Weekly Warm-Up Trajectory Check-In (Stage 3)',
    audience: 'DevOps & Reliability Leads',
    sentDate: '2026-10-28 09:15',
    totalSent: 1240,
    deliveryRate: 98.9,
    openRate: 52.1,
    ctr: 24.6,
    hardBounces: 12,
    spamComplaints: 0,
    status: 'DELIVERED',
  },
  {
    id: 'camp-03',
    name: 'Post-Quantum TLS Key Exchange Migration Guidelines',
    audience: 'Cryptographic Policy Working Group',
    sentDate: '2026-10-21 16:00',
    totalSent: 320,
    deliveryRate: 100.0,
    openRate: 68.4,
    ctr: 39.1,
    hardBounces: 0,
    spamComplaints: 0,
    status: 'DELIVERED',
  },
  {
    id: 'camp-04',
    name: 'Emergency DMARC Alignment Verification Notice',
    audience: 'Enterprise Security Officers',
    sentDate: '2026-10-15 11:20',
    totalSent: 4800,
    deliveryRate: 97.6,
    openRate: 41.5,
    ctr: 14.8,
    hardBounces: 110,
    spamComplaints: 4,
    status: 'ATTENTION',
  },
];

const TIME_SERIES_PERFORMANCE = [
  { time: '0h', delivered: 0, opens: 0, clicks: 0 },
  { time: '2h', delivered: 1800, opens: 640, clicks: 180 },
  { time: '4h', delivered: 3400, opens: 1420, clicks: 420 },
  { time: '8h', delivered: 4600, opens: 2100, clicks: 760 },
  { time: '12h', delivered: 4820, opens: 2280, clicks: 880 },
  { time: '24h', delivered: 4826, opens: 2340, clicks: 920 },
];

export default function CampaignAnalyticsPage() {
  const announce = useAnnounce();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'DELIVERED' | 'ATTENTION'>('ALL');
  const [sortField, setSortField] = useState<keyof CampaignMetricRow>('deliveryRate');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const handleSort = (field: keyof CampaignMetricRow) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
    announce(`Sorted table by ${String(field)}.`);
  };

  const filtered = SAMPLE_CAMPAIGNS.filter((c) => {
    const matchesSearch = c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.audience.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  }).sort((a, b) => {
    const valA = a[sortField];
    const valB = b[sortField];
    if (typeof valA === 'number' && typeof valB === 'number') {
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    }
    if (typeof valA === 'string' && typeof valB === 'string') {
      return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
    return 0;
  });

  const exportTableCsv = () => {
    const header = 'id,name,audience,sentDate,totalSent,deliveryRate,openRate,ctr,hardBounces,spamComplaints,status\n';
    const rows = filtered
      .map((c) => `"${c.id}","${c.name}","${c.audience}","${c.sentDate}",${c.totalSent},${c.deliveryRate},${c.openRate},${c.ctr},${c.hardBounces},${c.spamComplaints},"${c.status}"`)
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `garuda_campaign_analytics_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    announce('Exported analytics table to CSV');
  };

  return (
    <AppShell
      title="Deliverability & Campaign Intelligence Analytics"
      description="Translate raw SMTP dispatch logs and webhook telemetries into high-level deliverability metrics and ROI insights."
    >
      <div className="max-w-6xl mx-auto space-y-6">
        {/* ── KPI Metric Summary Cards ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <motion.div {...fadeUp} className="card p-4 space-y-1">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-dim)] font-medium">
              <span>Delivery Rate</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            </div>
            <div className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">99.1%</div>
            <p className="text-[11px] text-emerald-700 dark:text-emerald-400 font-medium">
              +0.4% above industry baseline
            </p>
          </motion.div>

          <motion.div {...fadeUp} className="card p-4 space-y-1">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-dim)] font-medium">
              <span>Avg. Open Rate</span>
              <Eye className="w-4 h-4 text-sky-500" />
            </div>
            <div className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">48.2%</div>
            <p className="text-[11px] text-sky-700 dark:text-sky-300 font-medium">
              Measured via pixel telemetry
            </p>
          </motion.div>

          <motion.div {...fadeUp} className="card p-4 space-y-1">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-dim)] font-medium">
              <span>Click-Through Rate (CTR)</span>
              <MousePointerClick className="w-4 h-4 text-indigo-500" />
            </div>
            <div className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">21.4%</div>
            <p className="text-[11px] text-indigo-700 dark:text-indigo-300 font-medium">
              Encrypted redirect tracking
            </p>
          </motion.div>

          <motion.div {...fadeUp} className="card p-4 space-y-1">
            <div className="flex items-center justify-between text-xs text-[var(--color-text-dim)] font-medium">
              <span>Spam Complaint Rate</span>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-700 dark:text-emerald-400">0.03%</div>
            <p className="text-[11px] text-[var(--color-text-dim)]">
              Well below the 0.10% Gmail limit
            </p>
          </motion.div>
        </div>

        {/* ── Time-Series Performance Chart ── */}
        <motion.div {...fadeUp} className="card p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-sky-500" />
                24-Hour Velocity & Engagement Timeline
              </h3>
              <p className="text-xs text-[var(--color-text-dim)]">
                Real-time tracking of outbound envelope delivery vs. verified recipient interactions.
              </p>
            </div>
          </div>

          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={TIME_SERIES_PERFORMANCE}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.15} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} />
                <YAxis stroke="#64748B" fontSize={11} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="bg-[var(--color-surface-1)] p-3 rounded-lg border border-[var(--color-border)] shadow-xl text-xs space-y-1">
                          <p className="font-bold text-[var(--color-text-primary)]">Hour {payload[0].payload.time}</p>
                          <p className="text-sky-600 dark:text-sky-400 font-semibold">Delivered: {payload[0].payload.delivered.toLocaleString()}</p>
                          <p className="text-indigo-600 dark:text-indigo-400 font-semibold">Opens: {payload[0].payload.opens.toLocaleString()}</p>
                          <p className="text-emerald-600 dark:text-emerald-400 font-semibold">Clicks: {payload[0].payload.clicks.toLocaleString()}</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend />
                <Line type="monotone" dataKey="delivered" name="Delivered Envelopes" stroke="#0284C7" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="opens" name="Unique Opens" stroke="#6366F1" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="clicks" name="Link Clicks" stroke="#10B981" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Accessible Table Fallback for Screen Readers (WCAG 1.3.1) */}
          <details className="text-xs text-[var(--color-text-dim)] cursor-pointer">
            <summary className="hover:text-[var(--color-text-primary)] py-1">View tabular chart data (accessible fallback)</summary>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left border border-[var(--color-border)]">
                <thead>
                  <tr className="bg-[var(--color-surface-2)]">
                    <th className="p-2 border">Timeline</th>
                    <th className="p-2 border">Delivered</th>
                    <th className="p-2 border">Opens</th>
                    <th className="p-2 border">Clicks</th>
                  </tr>
                </thead>
                <tbody>
                  {TIME_SERIES_PERFORMANCE.map((row) => (
                    <tr key={row.time}>
                      <td className="p-2 border">{row.time}</td>
                      <td className="p-2 border">{row.delivered}</td>
                      <td className="p-2 border">{row.opens}</td>
                      <td className="p-2 border">{row.clicks}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        </motion.div>

        {/* ── Granular Campaign Log Table with Filtering & CSV Export ── */}
        <motion.div {...fadeUp} className="card p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <div className="relative w-full">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-[var(--color-text-muted)]" />
                <input
                  type="text"
                  placeholder="Filter campaigns by title or audience..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-xs text-[var(--color-text-primary)]"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <select
                value={statusFilter}
                onChange={(e: any) => setStatusFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-xs text-[var(--color-text-primary)]"
              >
                <option value="ALL">All Statuses</option>
                <option value="DELIVERED">Delivered</option>
                <option value="ATTENTION">Needs Attention</option>
              </select>

              <button
                type="button"
                onClick={exportTableCsv}
                className="btn btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5 shrink-0"
              >
                <Download className="w-3.5 h-3.5" />
                Export CSV
              </button>
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-[var(--color-border)] max-h-96 overflow-y-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="sticky top-0 bg-[var(--color-surface-2)] z-10 border-b border-[var(--color-border)]">
                <tr>
                  <th className="p-3 font-semibold text-[var(--color-text-primary)]">Campaign Title</th>
                  <th className="p-3 font-semibold text-[var(--color-text-primary)]">Audience</th>
                  <th className="p-3 font-semibold text-[var(--color-text-primary)] text-right">Sent</th>
                  <th
                    className="p-3 font-semibold text-[var(--color-text-primary)] text-right"
                    aria-sort={sortField === 'deliveryRate' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}
                  >
                    <button
                      type="button"
                      onClick={() => handleSort('deliveryRate')}
                      className="inline-flex items-center gap-1 cursor-pointer hover:text-sky-500 font-semibold"
                    >
                      Delivery <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th
                    className="p-3 font-semibold text-[var(--color-text-primary)] text-right"
                    aria-sort={sortField === 'openRate' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}
                  >
                    <button
                      type="button"
                      onClick={() => handleSort('openRate')}
                      className="inline-flex items-center gap-1 cursor-pointer hover:text-sky-500 font-semibold"
                    >
                      Open Rate <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th className="p-3 font-semibold text-[var(--color-text-primary)] text-right">Bounces</th>
                  <th className="p-3 font-semibold text-[var(--color-text-primary)] text-center">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)] bg-[var(--color-surface-1)]">
                {filtered.map((camp) => (
                  <tr key={camp.id} className="hover:bg-[var(--color-surface-2)] transition">
                    <td className="p-3 font-medium text-[var(--color-text-primary)] max-w-xs truncate">
                      {camp.name}
                    </td>
                    <td className="p-3 text-[var(--color-text-secondary)]">{camp.audience}</td>
                    <td className="p-3 text-right font-mono text-[var(--color-text-primary)]">
                      {camp.totalSent.toLocaleString()}
                    </td>
                    <td className="p-3 text-right font-mono font-bold text-emerald-700 dark:text-emerald-400">
                      {camp.deliveryRate}%
                    </td>
                    <td className="p-3 text-right font-mono text-sky-700 dark:text-sky-300">
                      {camp.openRate}%
                    </td>
                    <td className="p-3 text-right font-mono text-rose-700 dark:text-rose-400">
                      {camp.hardBounces}
                    </td>
                    <td className="p-3 text-center">
                      {camp.status === 'DELIVERED' ? (
                        <span className="badge badge-healthy text-[10px]">Delivered</span>
                      ) : (
                        <span className="badge badge-high text-[10px]">Review</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
    </AppShell>
  );
}

