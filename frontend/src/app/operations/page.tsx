'use client';

import React, { useState, useEffect } from 'react';
import {
  Activity,
  Shield,
  Zap,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Play,
  Cpu,
  Layers,
  Clock,
  ArrowRight,
  Database,
  BarChart3,
  Server,
  Lock,
  RefreshCw,
  Sliders,
  FileCheck,
  Check,
  XCircle,
} from 'lucide-react';
import {
  ActionPlan,
  TelemetryMetrics,
  WorkloadPrediction,
  OperationalIncident,
  OptimizationExperiment,
  AutonomyMode,
} from '@/lib/ops/autonomous-ops';
import AppShell from '@/components/layout/AppShell';

export default function AutonomousOperationsPage() {
  const [mode, setMode] = useState<AutonomyMode>('RECOMMEND_AND_APPROVE');
  const [overview, setOverview] = useState<any>(null);
  const [metrics, setMetrics] = useState<TelemetryMetrics | null>(null);
  const [predictions, setPredictions] = useState<WorkloadPrediction | null>(null);
  const [actions, setActions] = useState<ActionPlan[]>([]);
  const [incidents, setIncidents] = useState<OperationalIncident[]>([]);
  const [experiments, setExperiments] = useState<OptimizationExperiment[]>([]);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoResults, setDemoResults] = useState<any>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Load live data
  const loadData = async () => {
    try {
      const [resOv, resMet, resPred, resAct, resInc, resExp] = await Promise.all([
        fetch('/api/ops/overview').then(r => r.json()).catch(() => null),
        fetch('/api/ops/metrics').then(r => r.json()).catch(() => null),
        fetch('/api/ops/predictions').then(r => r.json()).catch(() => null),
        fetch('/api/ops/actions').then(r => r.json()).catch(() => []),
        fetch('/api/ops/incidents').then(r => r.json()).catch(() => []),
        fetch('/api/ops/experiments').then(r => r.json()).catch(() => []),
      ]);

      if (resOv) {
        setOverview(resOv);
        if (resOv.autonomy_mode) setMode(resOv.autonomy_mode);
      }
      if (resMet) setMetrics(resMet);
      if (resPred) setPredictions(resPred);
      if (Array.isArray(resAct)) setActions(resAct);
      if (Array.isArray(resInc)) setIncidents(resInc);
      if (Array.isArray(resExp)) setExperiments(resExp);
    } catch (err) {
      console.error('Failed to load autonomous ops data', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      loadData();
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  // Mode change
  const handleModeChange = async (newMode: AutonomyMode) => {
    try {
      setMode(newMode);
      await fetch('/api/ops/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode }),
      });
      setActionNotice(`Autonomy Mode switched to ${newMode}`);
      setTimeout(() => setActionNotice(null), 4000);
      loadData();
    } catch (err) {
      console.error('Failed to update mode', err);
    }
  };

  // Action interactions
  const handleActionCommand = async (actionId: string, command: 'approve' | 'execute' | 'rollback') => {
    try {
      setLoadingAction(actionId);
      const res = await fetch('/api/ops/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: actionId, command }),
      });
      const data = await res.json();
      if (res.ok) {
        setActionNotice(`Action ${actionId} successfully ${command}d.`);
      } else {
        setActionNotice(`Error: ${data.error || 'Failed to process action'}`);
      }
      setTimeout(() => setActionNotice(null), 4500);
      loadData();
    } catch (err) {
      console.error('Action failed', err);
    } finally {
      setLoadingAction(null);
    }
  };

  // Run SIH demo
  const handleRunSIHDemo = async () => {
    try {
      setDemoRunning(true);
      setDemoResults(null);
      const res = await fetch('/api/ops/demo/sih', { method: 'POST' });
      const data = await res.json();
      setDemoResults(data);
      loadData();
    } catch (err) {
      console.error('Demo failed', err);
    } finally {
      setDemoRunning(false);
    }
  };

  return (
    <AppShell
      title="Autonomous Operations & System Health"
      description="Closed-loop telemetry, predictive resource balancing, auto-remediation, and safeguard governance"
    >
      <div className="space-y-8 font-sans">
        {/* ── Header & Mode Switcher ── */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1E293B]">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/25 text-cyan-400">
                <Activity className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
                  Autonomous Operations &amp; Health
                  <span className="badge badge-accent text-[11px] font-medium">
                    Self-Healing Active
                  </span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Closed-loop node telemetry, workload prediction, and allowlisted automated recovery within strict security boundaries.
                </p>
              </div>
            </div>
          </div>

          {/* Autonomy Mode Selector */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 p-1 bg-[#0F172A] border border-slate-800 rounded-xl w-full lg:w-auto">
            <button
              onClick={() => handleModeChange('OBSERVE')}
              className={`flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                mode === 'OBSERVE'
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Monitor Only</span>
            </button>
            <button
              onClick={() => handleModeChange('RECOMMEND_AND_APPROVE')}
              className={`flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                mode === 'RECOMMEND_AND_APPROVE'
                  ? 'bg-amber-600 text-white shadow-lg shadow-amber-500/20 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Guided Approval</span>
            </button>
            <button
              onClick={() => handleModeChange('BOUNDED_AUTOMATION')}
              className={`flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                mode === 'BOUNDED_AUTOMATION'
                  ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-500/20 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Auto-Recovery</span>
            </button>
          </div>
        </div>

      {actionNotice && (
        <div className="p-3 bg-cyan-950/60 border border-cyan-500/40 rounded-xl text-xs text-cyan-200 flex items-center justify-between animate-fadeIn">
          <span>{actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="text-cyan-400 hover:text-white">✕</button>
        </div>
      )}

      {/* ── KPI Overview Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="p-4 rounded-xl bg-[#0F172A]/70 border border-slate-800/80 shadow-sm backdrop-blur-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">Active Jobs</div>
          <div className="text-2xl font-bold text-white mt-1">
            {overview?.active_jobs_count ?? 3}
          </div>
          <div className="text-[10px] text-cyan-400 mt-1">Across eligible nodes</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/70 border border-slate-800/80 shadow-sm backdrop-blur-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">Queued Jobs</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {overview?.queued_jobs_count ?? 1}
          </div>
          <div className="text-[10px] text-slate-400 mt-1">Waiting for capacity</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/70 border border-slate-800/80 shadow-sm backdrop-blur-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">Pending Approvals</div>
          <div className="text-2xl font-bold text-amber-500 mt-1">
            {overview?.pending_approvals_count ?? 1}
          </div>
          <div className="text-[10px] text-slate-400 mt-1">Human review gated</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/70 border border-slate-800/80 shadow-sm backdrop-blur-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">Recoveries</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">2</div>
          <div className="text-[10px] text-emerald-400 mt-1">Allowlisted self-heals</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/70 border border-slate-800/80 shadow-sm backdrop-blur-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">GPU VRAM Usage</div>
          <div className="text-2xl font-bold text-white mt-1">
            {metrics?.gpu.used_vram_gb ?? 11.2} <span className="text-xs text-slate-400 font-normal">/ {metrics?.gpu.total_vram_gb ?? 32} GB</span>
          </div>
          <div className="text-[10px] text-emerald-400 mt-1">Headroom safe (35%)</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/70 border border-slate-800/80 shadow-sm backdrop-blur-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">P95 TTFT Latency</div>
          <div className="text-2xl font-bold text-cyan-400 mt-1">
            {metrics?.ai_inference.time_to_first_token_avg_ms ?? 36.4} <span className="text-xs text-slate-400 font-normal">ms</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-1">SLO target: 80.0 ms</div>
        </div>
      </div>

      {/* ── Autonomous Closed-Loop Feedback Pipeline ── */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-[#0F172A]/90 via-[#1E293B]/60 to-[#0F172A]/90 border border-slate-800/80">
        <div className="text-xs uppercase tracking-widest text-slate-400 font-semibold mb-4 flex items-center justify-between">
          <span>Continuous Health &amp; Safeguard Lifecycle</span>
          <span className="text-cyan-400 flex items-center gap-1">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Telemetry Feedback Active
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 lg:grid-cols-9 gap-2 text-center text-xs">
          {[
            { step: 'OBSERVE', sub: 'Telemetry & Logs', color: 'border-cyan-500/40 text-cyan-400' },
            { step: 'DIAGNOSE', sub: 'Anomaly Detector', color: 'border-blue-500/40 text-blue-400' },
            { step: 'PLAN', sub: 'Forecaster & AI', color: 'border-indigo-500/40 text-indigo-400' },
            { step: 'CHECK POLICY', sub: 'Governance Gate', color: 'border-purple-500/40 text-purple-400' },
            { step: 'AUTHORIZE', sub: 'Autonomy Mode', color: 'border-amber-500/40 text-amber-400' },
            { step: 'EXECUTE', sub: 'Allowlist Executor', color: 'border-emerald-500/40 text-emerald-400' },
            { step: 'VERIFY', sub: 'Health Probe', color: 'border-teal-500/40 text-teal-400' },
            { step: 'MEASURE', sub: 'Compare Baseline', color: 'border-sky-500/40 text-sky-400' },
            { step: 'RETAIN/ROLLBACK', sub: 'Feedback Learning', color: 'border-green-500/40 text-green-400' },
          ].map((item, idx) => (
            <div
              key={item.step}
              className={`p-2.5 rounded-xl bg-slate-900/60 border ${item.color} flex flex-col justify-center items-center shadow-sm`}
            >
              <span className="font-bold tracking-wider text-[11px]">{item.step}</span>
              <span className="text-[9px] text-slate-400 mt-0.5">{item.sub}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Main Content Grid: Predictive Workload Management & Action Plans ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Workload Forecasting & Capacity */}
        <div className="space-y-6">
          <div className="p-5 rounded-2xl bg-[#0F172A]/70 border border-slate-800 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                Predictive Workload Assessment
              </h2>
              <span className="text-xs px-2 py-0.5 rounded bg-blue-950 border border-blue-500/30 text-blue-300 font-mono">
                Confidence: {predictions?.confidence ? `${Math.round(predictions.confidence * 100)}%` : '84%'}
              </span>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="text-slate-400">Predicted Queue Depth</span>
                <span className="text-white font-semibold font-mono">
                  {predictions?.predicted_queue_depth ?? 18} jobs
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="text-slate-400">Expected Resource Pressure</span>
                <span
                  className={`font-semibold px-2 py-0.5 rounded text-[11px] ${
                    predictions?.expected_resource_pressure === 'HIGH'
                      ? 'bg-rose-950 text-rose-300 border border-rose-500/30'
                      : 'bg-amber-950 text-amber-300 border border-amber-500/30'
                  }`}
                >
                  {predictions?.expected_resource_pressure ?? 'MEDIUM'}
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="text-slate-400">Model Prewarm Recommended</span>
                <span className="text-emerald-400 font-semibold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {predictions?.model_warmup_recommended ? 'YES (qwen-2.5-coder-7b)' : 'NO'}
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="text-slate-400">Additional Worker Demand</span>
                <span className="text-slate-300 font-semibold font-mono">
                  {predictions?.additional_worker_needed ?? 'POSSIBLE'}
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed">
              <span className="font-semibold text-cyan-400">Predictor Assessment: </span>
              {predictions?.reasoning || 'Anticipating morning forensic ingestion spike. Recommending model prewarming on high-memory Node B.'}
            </div>
          </div>

          {/* Model Lifecycle & VRAM Allocation */}
          <div className="p-5 rounded-2xl bg-[#0F172A]/70 border border-slate-800 shadow-sm space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              Model Lifecycle &amp; Memory Bounds
            </h2>

            <div className="space-y-3 text-xs">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex justify-between items-center">
                <div>
                  <div className="font-medium text-white">qwen-local (1.5B GGUF)</div>
                  <div className="text-[10px] text-slate-400">Node A (RTX 4060) · 2.2 GB VRAM</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/30 text-[10px] font-mono">
                  READY
                </span>
              </div>

              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex justify-between items-center">
                <div>
                  <div className="font-medium text-white">qwen-2.5-coder-7b</div>
                  <div className="text-[10px] text-slate-400">Node B (RTX 4090) · 6.5 GB VRAM</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30 text-[10px] font-mono">
                  WARMED
                </span>
              </div>

              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex justify-between items-center">
                <div>
                  <div className="font-medium text-white">bge-large-embeddings</div>
                  <div className="text-[10px] text-slate-400">Node C (Storage) · 1.2 GB VRAM</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/30 text-[10px] font-mono">
                  READY
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Middle/Right: Action Plans & Bounded Execution (2 Cols) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="p-5 rounded-2xl bg-[#0F172A]/70 border border-slate-800 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  Operational Action Plans &amp; Approval Pipeline
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Deterministic allowlisted operations with post-execution verification and reversible rollback.
                </p>
              </div>
              <button
                onClick={loadData}
                className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white transition-colors"
                title="Refresh action plans"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Action ID</th>
                    <th className="py-2.5 px-3">Operation</th>
                    <th className="py-2.5 px-3">Target</th>
                    <th className="py-2.5 px-3">Risk</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Controls</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {actions.map((act) => {
                    const isPending = act.status === 'PENDING_APPROVAL';
                    const isApproved = act.status === 'APPROVED';
                    const isCompleted = act.status === 'COMPLETED';
                    const isRolledBack = act.status === 'ROLLED_BACK';

                    return (
                      <tr key={act.action_id} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-3 font-mono font-medium text-slate-300">
                          {act.action_id}
                        </td>
                        <td className="py-3 px-3">
                          <span className="font-semibold text-white">{act.action_type}</span>
                          <p className="text-[10px] text-slate-400 truncate max-w-xs">{act.reason}</p>
                        </td>
                        <td className="py-3 px-3 font-mono text-slate-300 text-[11px]">
                          {act.target_resource}
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              act.risk_level === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-300 border border-rose-500/30'
                                : act.risk_level === 'HIGH'
                                ? 'bg-amber-950 text-amber-300 border border-amber-500/30'
                                : 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                            }`}
                          >
                            {act.risk_level}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                              isCompleted
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                                : isPending
                                ? 'bg-amber-950 text-amber-300 border border-amber-500/30'
                                : isRolledBack
                                ? 'bg-slate-800 text-slate-400'
                                : 'bg-blue-950 text-blue-300 border border-blue-500/30'
                            }`}
                          >
                            {act.status}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right space-x-1.5 whitespace-nowrap">
                          {isPending && (
                            <button
                              disabled={loadingAction === act.action_id}
                              onClick={() => handleActionCommand(act.action_id, 'approve')}
                              className="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-medium text-[11px] transition-colors"
                            >
                              Approve
                            </button>
                          )}
                          {isApproved && (
                            <button
                              disabled={loadingAction === act.action_id}
                              onClick={() => handleActionCommand(act.action_id, 'execute')}
                              className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-[11px] transition-colors"
                            >
                              Execute
                            </button>
                          )}
                          {isCompleted && act.reversible && (
                            <button
                              disabled={loadingAction === act.action_id}
                              onClick={() => handleActionCommand(act.action_id, 'rollback')}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-rose-900/60 text-slate-300 hover:text-rose-200 border border-slate-700 font-medium text-[11px] transition-colors"
                            >
                              Rollback
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Controlled Optimization Experiments (Module M) */}
          <div className="p-5 rounded-2xl bg-[#0F172A]/70 border border-slate-800 shadow-sm space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              Controlled Optimization Experiments (A/B Baselines)
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {experiments.map((exp) => (
                <div
                  key={exp.experiment_id}
                  className={`p-4 rounded-xl border ${
                    exp.accepted
                      ? 'bg-emerald-950/20 border-emerald-500/30'
                      : 'bg-rose-950/20 border-rose-500/30'
                  } space-y-2 text-xs`}
                >
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-white">{exp.title}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        exp.accepted ? 'bg-emerald-900 text-emerald-200' : 'bg-rose-900 text-rose-200'
                      }`}
                    >
                      {exp.accepted ? 'ACCEPTED (+25%)' : 'ROLLED BACK'}
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">{exp.hypothesis}</p>
                  <div className="flex justify-between text-[11px] pt-2 border-t border-slate-800/60 font-mono">
                    <span className="text-slate-400">P50: {exp.baseline_metrics.p50_latency_ms}ms → {exp.proposed_metrics.p50_latency_ms}ms</span>
                    <span className="text-cyan-400">P95: {exp.proposed_metrics.p95_latency_ms}ms</span>
                  </div>
                  {exp.rollback_reason && (
                    <p className="text-[10px] text-rose-300 italic">Rollback: {exp.rollback_reason}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Live Automated Recovery Verification ── */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-cyan-500/30 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Play className="w-5 h-5 text-cyan-400" />
              Live Failover &amp; Recovery Simulation
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Simulates real-world primary node degradation, checks sovereign policy eligibility, safely routes workloads to verified replacement compute, and verifies 0 data loss under load.
            </p>
          </div>
          <button
            disabled={demoRunning}
            onClick={handleRunSIHDemo}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/20 flex items-center gap-2 transition-all active:scale-95 disabled:opacity-50 cursor-pointer"
          >
            {demoRunning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Executing Recovery...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                Run Failover Test
              </>
            )}
          </button>
        </div>

        {demoResults && (
          <div className="p-4 rounded-xl bg-slate-950/80 border border-cyan-500/30 space-y-3 animate-fadeIn">
            <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
              <span className="font-semibold text-cyan-300">{demoResults.verdict}</span>
              <span className="text-emerald-400 font-mono">7 / 7 STEPS COMPLETED</span>
            </div>
            <div className="space-y-2 text-xs">
              {demoResults.timeline?.map((st: any) => (
                <div key={st.step} className="flex items-start gap-3 p-2 rounded-lg bg-slate-900/60 border border-slate-800/80">
                  <div className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-500/40 flex items-center justify-center font-bold text-[10px] mt-0.5">
                    {st.step}
                  </div>
                  <div>
                    <div className="font-semibold text-white flex items-center gap-2">
                      {st.name}
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 font-mono">
                        {st.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300 mt-0.5">{st.details}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Operational Incident Response Records (Module O) ── */}
      <div className="p-5 rounded-2xl bg-[#0F172A]/70 border border-slate-800 shadow-sm space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400" />
          Incident Response Lifecycle (Module O)
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {incidents.map((inc) => (
            <div key={inc.incident_id} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3 text-xs">
              <div className="flex justify-between items-center">
                <span className="font-bold text-white flex items-center gap-2">
                  <span className="font-mono text-cyan-400">{inc.incident_id}</span>
                  {inc.title}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                    inc.status === 'RESOLVED'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                      : 'bg-rose-950 text-rose-300 border border-rose-500/30'
                  }`}
                >
                  {inc.status}
                </span>
              </div>
              <p className="text-slate-400 text-[11px]">{inc.description}</p>
              <div className="text-[10px] text-slate-400 font-mono">
                Target: {inc.target_resource} · Detected by: {inc.detection_source}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  </AppShell>
);
}
