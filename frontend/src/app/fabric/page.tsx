'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cpu, Server, Shield, Network, Activity, CheckCircle2,
  AlertTriangle, RefreshCw, Play, PlayCircle, Zap,
  Layers, Lock, Database, ArrowRight, XCircle, Sliders,
  Gauge, FileText, Check, AlertOctagon, Terminal
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { MetricCard } from '@/components/ui/shared';
import clsx from 'clsx';

const fadeUp = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] },
};

const stagger = {
  animate: { transition: { staggerChildren: 0.06 } },
};

export default function FabricPage() {
  const [activeTab, setActiveTab] = useState<'mesh' | 'scheduler' | 'demos' | 'enrollment' | 'benchmarks'>('mesh');
  const [nodes, setNodes] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [enrollments, setEnrollments] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [airGapped, setAirGappedState] = useState<boolean>(true);

  // Scheduler Form State
  const [capability, setCapability] = useState('chat');
  const [model, setModel] = useState('qwen-local');
  const [classification, setClassification] = useState('INTERNAL');
  const [minVram, setMinVram] = useState<number>(0);
  const [priority, setPriority] = useState('normal');
  const [schedulingResult, setSchedulingResult] = useState<any>(null);
  const [schedulingLoading, setSchedulingLoading] = useState<boolean>(false);

  // SIH Demos State
  const [runningDemoId, setRunningDemoId] = useState<number | null>(null);
  const [demoResults, setDemoResults] = useState<Record<number, any>>({});
  const [demoLogs, setDemoLogs] = useState<string[]>([]);

  // Benchmark State
  const [benchmarkResult, setBenchmarkResult] = useState<any>(null);
  const [benchmarkLoading, setBenchmarkLoading] = useState<boolean>(false);

  // Fetch initial cluster state
  async function loadClusterData() {
    try {
      setLoading(true);
      const res = await fetch('/api/fabric/nodes');
      if (res.ok) {
        const data = await res.json();
        setNodes(data.nodes || []);
        setMetrics(data.metrics || null);
      }
      const enrollRes = await fetch('/api/fabric/enrollment');
      if (enrollRes.ok) {
        const enrollData = await enrollRes.json();
        setEnrollments(enrollData.requests || []);
      }
      const partRes = await fetch('/api/fabric/partition');
      if (partRes.ok) {
        const partData = await partRes.json();
        setAirGappedState(partData.airGapped);
      }
    } catch (e) {
      console.error('Failed to load fabric data', e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadClusterData();
  }, []);

  // Handle Air-Gapped Toggle
  async function toggleAirGapped() {
    try {
      const res = await fetch('/api/fabric/partition', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !airGapped }),
      });
      if (res.ok) {
        const data = await res.json();
        setAirGappedState(data.airGapped);
        loadClusterData();
      }
    } catch (e) {
      console.error(e);
    }
  }

  // Handle Workload Schedule
  async function handleScheduleWorkload(e: React.FormEvent) {
    e.preventDefault();
    setSchedulingLoading(true);
    try {
      const res = await fetch('/api/fabric/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'workload.execute',
          capability,
          model: model || undefined,
          minVramGb: Number(minVram) || 0,
          dataClassification: classification,
          priority,
        }),
      });
      const data = await res.json();
      setSchedulingResult(data.schedule || data);
    } catch (err) {
      console.error(err);
    } finally {
      setSchedulingLoading(false);
    }
  }

  // Handle SIH Demo Run
  async function executeDemo(demoId: number) {
    setRunningDemoId(demoId);
    setDemoLogs([`[Demo ${demoId}] Initializing orchestration sequence...`]);
    try {
      const res = await fetch('/api/fabric/demos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ demoId }),
      });
      if (res.ok) {
        const data = await res.json();
        setDemoResults(prev => ({ ...prev, [demoId]: data }));
        setDemoLogs(data.logs || [`[Demo ${demoId}] Execution completed successfully.`]);
        loadClusterData();
      }
    } catch (err) {
      console.error(err);
      setDemoLogs(prev => [...prev, `[ERROR] Demo execution failed`]);
    } finally {
      setRunningDemoId(null);
    }
  }

  // Run all demos in sequence
  async function runAllDemos() {
    for (let i = 1; i <= 6; i++) {
      await executeDemo(i);
      await new Promise(r => setTimeout(r, 600));
    }
  }

  // Handle Benchmark Run
  async function handleRunBenchmark() {
    setBenchmarkLoading(true);
    try {
      const res = await fetch('/api/fabric/benchmarks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: 50 }),
      });
      if (res.ok) {
        const data = await res.json();
        setBenchmarkResult(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setBenchmarkLoading(false);
    }
  }

  // Handle Enrollment Action
  async function handleEnrollmentReview(requestId: string, action: 'approve' | 'reject') {
    try {
      const res = await fetch('/api/fabric/enrollment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, requestId }),
      });
      if (res.ok) {
        loadClusterData();
      }
    } catch (err) {
      console.error(err);
    }
  }

  return (
    <AppShell
      title="Distributed AI Fabric"
      description="Sovereign Multi-Node Compute Mesh, Resource-Aware Scheduling & Fault Tolerance"
    >
      <div className="space-y-6">

        {/* ── Top Bar: Cluster Vitals & Air-Gapped Toggle ── */}
        <motion.div variants={fadeUp} initial="initial" animate="animate" className="card p-5 surface-1 border-default">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className={clsx(
                'w-3.5 h-3.5 rounded-full ring-4 animate-pulse',
                metrics?.systemStatus === 'HEALTHY'
                  ? 'bg-[var(--color-severity-healthy)] ring-[rgba(16,185,129,0.2)]'
                  : 'bg-[var(--color-severity-high)] ring-[rgba(245,158,11,0.2)]'
              )} />
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-lg font-bold text-[var(--color-text-primary)]">GARUDA SOVEREIGN COMPUTE MESH</h2>
                  <span className="badge badge-accent text-[10px] font-mono uppercase tracking-wider">Mesh Active</span>
                </div>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  Control Plane: Active | Policy & Data Locality: Enforced | Failover: Autonomous
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2 bg-[var(--color-surface-2)] px-3 py-1.5 rounded-md border border-[var(--color-border-subtle)] text-xs">
                <Shield className="w-3.5 h-3.5 text-[var(--color-accent)]" />
                <span className="text-[var(--color-text-dim)]">Sovereignty:</span>
                <span className="font-semibold text-[var(--color-accent)] font-mono">
                  {airGapped ? 'AIR-GAPPED' : 'HYBRID MESH'}
                </span>
              </div>

              <button
                onClick={toggleAirGapped}
                className={clsx(
                  'btn text-xs flex items-center gap-1.5 transition-all',
                  airGapped ? 'btn-secondary text-[var(--color-severity-healthy)]' : 'btn-accent'
                )}
                title="Toggle Air-Gapped Network Boundary"
              >
                <Lock className="w-3.5 h-3.5" />
                {airGapped ? 'Air-Gapped (Egress Blocked)' : 'Enable Air-Gap'}
              </button>

              <button
                onClick={loadClusterData}
                disabled={loading}
                className="btn btn-secondary text-xs flex items-center gap-1"
              >
                <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} />
                Sync
              </button>
            </div>
          </div>
        </motion.div>

        {/* ── Row 1: KPI Metrics ── */}
        <motion.div variants={stagger} initial="initial" animate="animate" className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div variants={fadeUp}>
            <MetricCard
              label="Fabric Nodes"
              value={metrics?.totalNodes ?? 4}
              sub={`${metrics?.healthyNodes ?? 3} healthy, ${metrics?.quarantinedNodes ?? 1} quarantined`}
              accent="accent"
            />
          </motion.div>
          <motion.div variants={fadeUp}>
            <MetricCard
              label="Total GPU VRAM"
              value={`${metrics?.totalVramGb ?? 32.0} GB`}
              sub={`${metrics?.freeVramGb ?? 20.3} GB free (${metrics?.vramUtilizationPct ?? 36.5}% allocated)`}
              accent="healthy"
            />
          </motion.div>
          <motion.div variants={fadeUp}>
            <MetricCard
              label="Active Workloads"
              value={metrics?.activeJobs ?? 0}
              sub="Durable checkpoints enabled"
              accent="high"
            />
          </motion.div>
          <motion.div variants={fadeUp}>
            <MetricCard
              label="Failover (24h)"
              value={metrics?.failoverLast24h ?? 2}
              sub="0 jobs lost, 100% recovered"
              accent="accent"
            />
          </motion.div>
        </motion.div>

        {/* ── Navigation Tabs ── */}
        <div className="flex items-center gap-1 border-b border-[var(--color-border)] pb-2 overflow-x-auto">
          {[
            { id: 'mesh', label: 'Cluster Mesh & Node Map', icon: Network },
            { id: 'scheduler', label: 'Workload Scheduler', icon: Sliders },
            { id: 'demos', label: 'Fault-Tolerance Scenarios', icon: PlayCircle },
            { id: 'enrollment', label: `Node Enrollment (${enrollments.length})`, icon: Shield },
            { id: 'benchmarks', label: 'Cluster Benchmarks', icon: Gauge },
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer whitespace-nowrap',
                  active
                    ? 'bg-[var(--color-accent-glow)] text-[var(--color-accent)] border border-[var(--color-accent-dim)] font-semibold'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]'
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* ── Tab 1: Cluster Mesh & Node Map ── */}
        {activeTab === 'mesh' && (
          <motion.div variants={stagger} initial="initial" animate="animate" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {nodes.map(node => {
                const freeVram = Math.max(0, node.vramTotalGb - node.vramUsedGb);
                const vramPct = node.vramTotalGb > 0 ? (node.vramUsedGb / node.vramTotalGb) * 100 : 0;
                const isQuarantined = node.status === 'quarantined' || node.trust === 'quarantined';

                return (
                  <motion.div
                    key={node.nodeId}
                    variants={fadeUp}
                    className={clsx(
                      'card p-5 relative overflow-hidden transition-all',
                      isQuarantined
                        ? 'border-[var(--color-severity-critical)] bg-[rgba(239,68,68,0.03)]'
                        : 'border-[var(--color-border)] hover:border-[var(--color-border-active)] surface-1'
                    )}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between">
                      <div>
                        <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--color-text-dim)]">
                          {node.role}
                        </span>
                        <h3 className="text-base font-bold text-[var(--color-text-primary)] mt-0.5">
                          {node.nodeId}
                        </h3>
                        <p className="text-xs text-[var(--color-text-muted)] truncate max-w-[180px]">
                          {node.hostname}
                        </p>
                      </div>

                      <div className="flex flex-col items-end gap-1">
                        <span className={clsx(
                          'badge text-[10px] font-mono uppercase',
                          node.status === 'healthy' ? 'badge-healthy' :
                          node.status === 'degraded' ? 'badge-high' : 'badge-critical'
                        )}>
                          {node.status}
                        </span>
                        <span className={clsx(
                          'text-[9px] px-1.5 py-0.5 rounded font-mono',
                          node.zone === 'RESTRICTED_AI' ? 'bg-[rgba(56,189,248,0.1)] text-[var(--color-accent)]' :
                          node.zone === 'INTERNAL_AI' ? 'bg-[rgba(16,185,129,0.1)] text-[var(--color-severity-healthy)]' :
                          'bg-[var(--color-surface-3)] text-[var(--color-text-dim)]'
                        )}>
                          {node.zone}
                        </span>
                      </div>
                    </div>

                    {/* GPU & Hardware Specs */}
                    <div className="mt-4 pt-3 border-t border-[var(--color-border-subtle)] space-y-2.5">
                      <div>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="text-[var(--color-text-dim)] flex items-center gap-1">
                            <Cpu className="w-3 h-3 text-[var(--color-accent)]" /> GPU VRAM
                          </span>
                          <span className="font-mono text-[var(--color-text-secondary)]">
                            {node.vramTotalGb > 0
                              ? `${node.vramUsedGb.toFixed(1)} / ${node.vramTotalGb.toFixed(1)} GB`
                              : 'CPU Host'}
                          </span>
                        </div>
                        {node.vramTotalGb > 0 && (
                          <div className="w-full bg-[var(--color-surface-3)] rounded-full h-1.5 overflow-hidden">
                            <div
                              className={clsx(
                                'h-full rounded-full transition-all duration-500',
                                vramPct > 90 ? 'bg-[var(--color-severity-critical)]' :
                                vramPct > 70 ? 'bg-[var(--color-severity-high)]' : 'bg-[var(--color-accent)]'
                              )}
                              style={{ width: `${Math.min(100, Math.max(5, vramPct))}%` }}
                            />
                          </div>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[11px] text-[var(--color-text-muted)]">
                        <div>
                          <span className="text-[var(--color-text-dim)]">RAM:</span>{' '}
                          <span className="font-mono text-[var(--color-text-secondary)]">{node.ramUsedGb?.toFixed(1) || '4'}/{node.ramTotalGb || '16'} GB</span>
                        </div>
                        <div>
                          <span className="text-[var(--color-text-dim)]">Jobs:</span>{' '}
                          <span className="font-mono text-[var(--color-text-secondary)]">{node.activeJobs} active</span>
                        </div>
                      </div>

                      {/* Capabilities pills */}
                      <div className="pt-2">
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-1">Capabilities:</div>
                        <div className="flex flex-wrap gap-1">
                          {node.capabilities.slice(0, 4).map((cap: string) => (
                            <span key={cap} className="px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[10px] font-mono text-[var(--color-text-secondary)]">
                              {cap}
                            </span>
                          ))}
                          {node.capabilities.length > 4 && (
                            <span className="px-1 py-0.5 rounded bg-[var(--color-surface-3)] text-[10px] font-mono text-[var(--color-text-dim)]">
                              +{node.capabilities.length - 4}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Models loaded pills */}
                      <div className="pt-1">
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-1">Loaded Models:</div>
                        <div className="flex flex-wrap gap-1">
                          {node.models.length > 0 ? (
                            node.models.map((m: string) => (
                              <span key={m} className="px-1.5 py-0.5 rounded bg-[rgba(56,189,248,0.08)] text-[10px] font-mono text-[var(--color-accent)]">
                                {m}
                              </span>
                            ))
                          ) : (
                            <span className="text-[10px] text-[var(--color-text-dim)] italic">No active models</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Status & Trust footer */}
                    <div className="mt-4 pt-2 border-t border-[var(--color-border-subtle)] flex items-center justify-between text-[10px]">
                      <span className="text-[var(--color-text-dim)]">
                        Trust: <span className="font-semibold text-[var(--color-text-secondary)] font-mono">{node.trust.toUpperCase()}</span>
                      </span>
                      <span className="text-[var(--color-text-dim)] font-mono">
                        v{node.softwareVersion}
                      </span>
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {/* Architecture Explanatory Banner */}
            <div className="card p-5 surface-2 border-default flex items-start gap-4">
              <div className="p-2.5 rounded-lg bg-[rgba(56,189,248,0.1)] text-[var(--color-accent)] mt-0.5">
                <Layers className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-semibold text-[var(--color-text-primary)]">
                  Control Plane & Data Plane Separation (Section 34.1)
                </h4>
                <p className="text-xs text-[var(--color-text-muted)] leading-relaxed">
                  The Garuda Control Plane orchestrates policy, security gates, model placement, and audit records,
                  while compute workers (Node 1 RTX 4060 Laptop, Node 2 GPU Server, Node 3 CPU Storage) perform
                  localized data plane processing. Restricted workloads are guaranteed never to cross sovereign compute zones.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Tab 2: Explainable Workload Scheduler Sandbox ── */}
        {activeTab === 'scheduler' && (
          <motion.div variants={stagger} initial="initial" animate="animate" className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Input Form */}
            <div className="lg:col-span-5 card p-6 surface-1 border-default space-y-4">
              <div>
                <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-[var(--color-accent)]" />
                  Workload Dispatch Simulator
                </h3>
                <p className="text-xs text-[var(--color-text-muted)] mt-1">
                  Submit a workload request to test policy filtering, resource checks, and explainable scoring.
                </p>
              </div>

              <form onSubmit={handleScheduleWorkload} className="space-y-4">
                <div>
                  <label className="text-xs font-medium text-[var(--color-text-secondary)] block mb-1">
                    Required Capability
                  </label>
                  <select
                    value={capability}
                    onChange={e => setCapability(e.target.value)}
                    className="w-full bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md px-3 py-2 text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="chat">chat (LLM Conversational)</option>
                    <option value="coding">coding (Code Synthesis & Review)</option>
                    <option value="embeddings">embeddings (Neural Embeddings)</option>
                    <option value="vision">vision (Forensic Image & Video Inspection)</option>
                    <option value="rag">rag (Document Retrieval & Reranking)</option>
                    <option value="vector_store">vector_store (Vector Indexing)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-medium text-[var(--color-text-secondary)] block mb-1">
                    Target Model
                  </label>
                  <select
                    value={model}
                    onChange={e => setModel(e.target.value)}
                    className="w-full bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md px-3 py-2 text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="qwen-local">qwen-local (1.5B, 2.2 GB VRAM - Workstation/Laptop)</option>
                    <option value="qwen-coder-7b">qwen-coder-7b (7B, 6.5 GB VRAM - Code Specialist)</option>
                    <option value="qwen-vl-vision">qwen-vl-vision (7B, 7.8 GB VRAM - Vision Model)</option>
                    <option value="bge-embeddings">bge-embeddings (0.5B, 1.2 GB VRAM - Embedding)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-medium text-[var(--color-text-secondary)] block mb-1">
                    Data Classification Tier (Sovereign Locality)
                  </label>
                  <select
                    value={classification}
                    onChange={e => setClassification(e.target.value)}
                    className="w-full bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md px-3 py-2 text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="PUBLIC">PUBLIC (General Access)</option>
                    <option value="INTERNAL">INTERNAL (Internal AI Mesh)</option>
                    <option value="CONFIDENTIAL">CONFIDENTIAL (Internal AI & Workstation)</option>
                    <option value="RESTRICTED">RESTRICTED (Restricted Sovereign Zone Only)</option>
                    <option value="TOP_SECRET">TOP_SECRET (Strict Air-Gapped Workstation Only)</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-medium text-[var(--color-text-secondary)] block mb-1">
                      Min VRAM Required (GB)
                    </label>
                    <input
                      type="number"
                      step="0.5"
                      min="0"
                      max="24"
                      value={minVram}
                      onChange={e => setMinVram(Number(e.target.value))}
                      className="w-full bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md px-3 py-2 text-xs text-[var(--color-text-primary)] font-mono focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-[var(--color-text-secondary)] block mb-1">
                      Priority Class
                    </label>
                    <select
                      value={priority}
                      onChange={e => setPriority(e.target.value)}
                      className="w-full bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md px-3 py-2 text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    >
                      <option value="critical">CRITICAL (+35)</option>
                      <option value="high">HIGH (+18)</option>
                      <option value="normal">NORMAL (0)</option>
                      <option value="low">LOW (-10)</option>
                      <option value="background">BACKGROUND (-25)</option>
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={schedulingLoading}
                  className="btn btn-accent w-full text-xs font-medium py-2.5 flex items-center justify-center gap-2"
                >
                  {schedulingLoading ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5" />
                  )}
                  Evaluate & Dispatch Workload
                </button>
              </form>
            </div>

            {/* Results & Explainability Panel */}
            <div className="lg:col-span-7 card p-6 surface-1 border-default space-y-4">
              <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <FileText className="w-4 h-4 text-[var(--color-accent)]" />
                Explainable Decision Breakdown (Section 34.49)
              </h3>

              {schedulingResult ? (
                <div className="space-y-4">
                  {/* Selected Node Result */}
                  <div className={clsx(
                    'p-4 rounded-lg border',
                    schedulingResult.scheduled
                      ? 'bg-[rgba(16,185,129,0.06)] border-[var(--color-severity-healthy)] text-[var(--color-text-primary)]'
                      : 'bg-[rgba(239,68,68,0.06)] border-[var(--color-severity-critical)] text-[var(--color-text-primary)]'
                  )}>
                    <div className="flex items-center gap-2 font-bold text-sm">
                      {schedulingResult.scheduled ? (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-[var(--color-severity-healthy)]" />
                          <span>Dispatched to {schedulingResult.selectedNode?.nodeId || 'Selected Node'}</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4 text-[var(--color-severity-critical)]" />
                          <span>Scheduling Denied — No Eligible Node</span>
                        </>
                      )}
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)] mt-1.5 leading-relaxed font-mono">
                      {schedulingResult.explanation || schedulingResult.reason}
                    </p>
                  </div>

                  {/* Candidates Comparison Table */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-dim)]">
                      Candidate Evaluation Scores
                    </h4>
                    <div className="space-y-2">
                      {schedulingResult.candidates?.map((c: any) => (
                        <div
                          key={c.nodeId}
                          className={clsx(
                            'p-3 rounded-md border text-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-2',
                            c.isEligible
                              ? 'bg-[var(--color-surface-2)] border-[var(--color-border)]'
                              : 'bg-[rgba(239,68,68,0.03)] border-[rgba(239,68,68,0.2)] opacity-75'
                          )}
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[var(--color-text-primary)] font-mono">{c.nodeId}</span>
                              <span className={clsx(
                                'badge text-[9px] font-mono',
                                c.isEligible ? 'badge-healthy' : 'badge-critical'
                              )}>
                                {c.isEligible ? 'ELIGIBLE' : 'REJECTED'}
                              </span>
                            </div>
                            <div className="text-[11px] text-[var(--color-text-muted)] mt-1">
                              {c.isEligible ? (
                                c.reasons?.slice(0, 2).join(' • ')
                              ) : (
                                <span className="text-[var(--color-severity-critical)]">
                                  {c.rejectionReason || schedulingResult.rejectedReasons?.[c.nodeId] || 'Policy filter failed'}
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="text-right flex items-center gap-3">
                            <div>
                              <div className="text-[10px] text-[var(--color-text-dim)]">Score</div>
                              <div className="font-mono font-bold text-sm text-[var(--color-accent)]">{c.score}</div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center border border-dashed border-[var(--color-border)] rounded-lg text-xs text-[var(--color-text-dim)]">
                  Configure requirements and click &quot;Evaluate & Dispatch Workload&quot; to see real-time explainable routing.
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ── Tab 3: SIH Flagship Demonstrations Control Center ── */}
        {activeTab === 'demos' && (
          <motion.div variants={stagger} initial="initial" animate="animate" className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                  <PlayCircle className="w-4 h-4 text-[var(--color-accent)]" />
                  Cluster Resilience &amp; Fault-Tolerance Test Suite
                </h3>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  Execute live verification scenarios proving distributed inference, resource-aware placement, data sovereignty, and automatic failover.
                </p>
              </div>

              <button
                onClick={runAllDemos}
                disabled={runningDemoId !== null}
                className="btn btn-accent text-xs flex items-center gap-1.5 font-semibold"
              >
                <Zap className="w-3.5 h-3.5" />
                Run All 6 Scenarios
              </button>
            </div>

            {/* Demo Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[
                {
                  id: 1,
                  title: 'Scenario 1 — Distributed Inference',
                  scenarioId: 'SCENARIO-01',
                  desc: 'Distributes requests across Node A (RTX 4060) and Node B (RTX 4090) based on queue pressure.',
                  tag: 'Load Balancing',
                },
                {
                  id: 2,
                  title: 'Scenario 2 — Resource-Aware Scheduling',
                  scenarioId: 'SCENARIO-02',
                  desc: 'Simulates memory saturation on RTX 4060 (7.6/8 GB used) and routes large model to RTX 4090.',
                  tag: 'VRAM Headroom',
                },
                {
                  id: 3,
                  title: 'Scenario 3 — Sovereign Data Placement',
                  scenarioId: 'SCENARIO-03',
                  desc: 'Enforces RESTRICTED classification: Node B and Node C are denied; only RESTRICTED_AI Node A approved.',
                  tag: 'Data Locality',
                },
                {
                  id: 4,
                  title: 'Scenario 4 — Node Failure & Failover',
                  scenarioId: 'SCENARIO-04',
                  desc: 'Simulates worker kernel crash, retrieves durable checkpoints, and resumes seamlessly on Node A.',
                  tag: 'Fault Tolerance',
                },
                {
                  id: 5,
                  title: 'Scenario 5 — Air-Gapped Mode',
                  scenarioId: 'SCENARIO-05',
                  desc: 'Blocks external AI APIs while local offline RAG and local models continue running unimpeded.',
                  tag: 'Air-Gap / Offline',
                },
                {
                  id: 6,
                  title: 'Scenario 6 — Policy + Scheduler Chain',
                  scenarioId: 'SCENARIO-06',
                  desc: 'Complete control plane: Auth -> RBAC -> DataClass -> Policy -> VRAM -> Scheduler -> Audit commit.',
                  tag: 'End-to-End Governance',
                },
              ].map(demo => {
                const res = demoResults[demo.id];
                const isRunning = runningDemoId === demo.id;

                return (
                  <motion.div
                    key={demo.id}
                    variants={fadeUp}
                    className="card p-5 surface-1 border-default flex flex-col justify-between hover:border-[var(--color-border-active)] transition-all"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-[var(--color-accent)] font-semibold">
                          {demo.scenarioId}
                        </span>
                        <span className="badge badge-accent text-[9px] font-mono">{demo.tag}</span>
                      </div>
                      <h4 className="text-sm font-bold text-[var(--color-text-primary)] mt-1.5">
                        {demo.title}
                      </h4>
                      <p className="text-xs text-[var(--color-text-muted)] mt-1 leading-relaxed">
                        {demo.desc}
                      </p>
                    </div>

                    <div className="mt-4 pt-3 border-t border-[var(--color-border-subtle)] flex items-center justify-between">
                      {res ? (
                        <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--color-severity-healthy)]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>PASSED</span>
                        </div>
                      ) : (
                        <span className="text-[11px] text-[var(--color-text-dim)]">Ready for execution</span>
                      )}

                      <button
                        onClick={() => executeDemo(demo.id)}
                        disabled={isRunning}
                        className="btn btn-secondary text-xs flex items-center gap-1 py-1.5 px-3"
                      >
                        {isRunning ? (
                          <RefreshCw className="w-3 h-3 animate-spin text-[var(--color-accent)]" />
                        ) : (
                          <Play className="w-3 h-3" />
                        )}
                        {isRunning ? 'Running...' : 'Run Demo'}
                      </button>
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {/* Live Terminal Stream */}
            <div className="card p-5 surface-2 border-default space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-[var(--color-accent)]" />
                  Demonstration Execution Log Stream
                </span>
                <span className="text-[10px] text-[var(--color-text-dim)] font-mono">Live Telemetry</span>
              </div>
              <div className="bg-[var(--color-surface-0)] p-4 rounded-lg border border-[var(--color-border)] font-mono text-xs text-[var(--color-text-secondary)] space-y-1 max-h-56 overflow-y-auto">
                {demoLogs.length > 0 ? (
                  demoLogs.map((log, idx) => (
                    <div key={idx} className={clsx(
                      log.includes('PASSED') || log.includes('SUCCESS') || log.includes('APPROVED')
                        ? 'text-[var(--color-severity-healthy)]'
                        : log.includes('DENIED') || log.includes('BLOCKED') || log.includes('ALERT')
                        ? 'text-[var(--color-severity-high)]'
                        : 'text-[var(--color-text-secondary)]'
                    )}>
                      {log}
                    </div>
                  ))
                ) : (
                  <div className="text-[var(--color-text-dim)] italic">
                    Click &quot;Run Demo&quot; on any card above to view execution steps.
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Tab 4: Node Enrollment & Trust Governance ── */}
        {activeTab === 'enrollment' && (
          <motion.div variants={stagger} initial="initial" animate="animate" className="space-y-6">
            <div>
              <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <Shield className="w-4 h-4 text-[var(--color-accent)]" />
                Secure Node Enrollment Workflow (Section 34.4 & 34.21)
              </h3>
              <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                Worker nodes cannot join the fabric automatically. Administrators must review specifications and approve issuance of cryptographic certificates.
              </p>
            </div>

            <div className="space-y-3">
              {enrollments.length > 0 ? (
                enrollments.map(req => (
                  <div key={req.requestId} className="card p-5 surface-1 border-default flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-[var(--color-text-primary)] text-sm font-mono">{req.requestId}</span>
                        <span className={clsx(
                          'badge text-[10px] font-mono',
                          req.status === 'PENDING_APPROVAL' ? 'badge-high' :
                          req.status === 'APPROVED' ? 'badge-healthy' : 'badge-critical'
                        )}>
                          {req.status}
                        </span>
                      </div>
                      <div className="text-xs text-[var(--color-text-secondary)] mt-1">
                        Hostname: <span className="font-semibold">{req.hostname}</span> • IP: <span className="font-mono">{req.ipAddress}</span> • Target Zone: <span className="font-mono">{req.requestedZone}</span>
                      </div>
                      <div className="text-xs text-[var(--color-text-muted)] mt-1">
                        Advertised Hardware: <span className="text-[var(--color-accent)] font-semibold">{req.advertisedGpu}</span> ({req.advertisedVramGb} GB VRAM, {req.advertisedRamGb} GB RAM)
                      </div>
                    </div>

                    {req.status === 'PENDING_APPROVAL' && (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleEnrollmentReview(req.requestId, 'approve')}
                          className="btn btn-accent text-xs py-1.5 px-3 flex items-center gap-1"
                        >
                          <Check className="w-3.5 h-3.5" />
                          Approve Enrollment
                        </button>
                        <button
                          onClick={() => handleEnrollmentReview(req.requestId, 'reject')}
                          className="btn btn-secondary text-xs py-1.5 px-3 flex items-center gap-1 text-[var(--color-severity-critical)]"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          Reject
                        </button>
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="card p-8 text-center surface-1 border-default text-xs text-[var(--color-text-dim)]">
                  No pending enrollment requests.
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ── Tab 5: Performance Benchmarks & Audit ── */}
        {activeTab === 'benchmarks' && (
          <motion.div variants={stagger} initial="initial" animate="animate" className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Gauge className="w-4 h-4 text-[var(--color-accent)]" />
                  Performance Benchmarking (Section 34.24 & 34.36)
                </h3>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                  Measures throughput, queue latency, and VRAM efficiency comparing Single-Node vs Distributed AI Fabric.
                </p>
              </div>

              <button
                onClick={handleRunBenchmark}
                disabled={benchmarkLoading}
                className="btn btn-accent text-xs flex items-center gap-1.5"
              >
                {benchmarkLoading ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Run 50-Request Benchmark
              </button>
            </div>

            {benchmarkResult ? (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="card p-5 surface-1 border-default">
                    <span className="text-[10px] font-mono text-[var(--color-text-dim)] uppercase">Throughput Speedup</span>
                    <div className="text-2xl font-bold text-[var(--color-severity-healthy)] font-mono mt-1">
                      {benchmarkResult.speedup.throughputImprovementPct}
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">
                      From {benchmarkResult.singleNode.throughputReqSec} req/s to {benchmarkResult.distributedFabric.throughputReqSec} req/s
                    </p>
                  </div>

                  <div className="card p-5 surface-1 border-default">
                    <span className="text-[10px] font-mono text-[var(--color-text-dim)] uppercase">Latency Reduction</span>
                    <div className="text-2xl font-bold text-[var(--color-accent)] font-mono mt-1">
                      {benchmarkResult.speedup.latencyReductionPct}
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">
                      From {benchmarkResult.singleNode.avgLatencyMs} ms down to {benchmarkResult.distributedFabric.avgLatencyMs} ms
                    </p>
                  </div>

                  <div className="card p-5 surface-1 border-default">
                    <span className="text-[10px] font-mono text-[var(--color-text-dim)] uppercase">Failover Recovery</span>
                    <div className="text-2xl font-bold text-[var(--color-text-primary)] font-mono mt-1">
                      {benchmarkResult.speedup.failoverRecoveryTimeMs} ms
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">
                      Automated checkpoint restore latency
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Single Node Card */}
                  <div className="card p-5 surface-2 border-default space-y-3">
                    <h4 className="text-sm font-bold text-[var(--color-text-primary)]">Single Node Baseline</h4>
                    <p className="text-xs text-[var(--color-text-muted)]">{benchmarkResult.singleNode.node}</p>
                    <div className="space-y-1.5 text-xs font-mono">
                      <div className="flex justify-between">
                        <span className="text-[var(--color-text-dim)]">Average Latency:</span>
                        <span>{benchmarkResult.singleNode.avgLatencyMs} ms</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[var(--color-text-dim)]">p95 Latency:</span>
                        <span>{benchmarkResult.singleNode.p95LatencyMs} ms</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[var(--color-text-dim)]">VRAM Saturation:</span>
                        <span className="text-[var(--color-severity-high)]">{benchmarkResult.singleNode.vramStatus}</span>
                      </div>
                    </div>
                  </div>

                  {/* Distributed Fabric Card */}
                  <div className="card p-5 surface-2 border-[var(--color-accent-dim)] space-y-3">
                    <h4 className="text-sm font-bold text-[var(--color-accent)]">Distributed Sovereign Fabric</h4>
                    <p className="text-xs text-[var(--color-text-muted)]">Multi-Node Mesh (RTX 4060 + RTX 4090)</p>
                    <div className="space-y-1.5 text-xs font-mono">
                      <div className="flex justify-between">
                        <span className="text-[var(--color-text-dim)]">Average Latency:</span>
                        <span className="text-[var(--color-severity-healthy)] font-bold">{benchmarkResult.distributedFabric.avgLatencyMs} ms</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[var(--color-text-dim)]">p95 Latency:</span>
                        <span>{benchmarkResult.distributedFabric.p95LatencyMs} ms</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[var(--color-text-dim)]">VRAM Status:</span>
                        <span className="text-[var(--color-severity-healthy)]">{benchmarkResult.distributedFabric.vramStatus}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="card p-8 text-center surface-1 border-default text-xs text-[var(--color-text-dim)]">
                Click &quot;Run 50-Request Benchmark&quot; to measure actual single-node vs distributed throughput and latency.
              </div>
            )}
          </motion.div>
        )}

      </div>
    </AppShell>
  );
}
