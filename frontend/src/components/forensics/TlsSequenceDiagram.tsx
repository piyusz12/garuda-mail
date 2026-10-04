'use client';

import { useEffect, useRef, useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Edge,
  Node,
  Position,
  Handle,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { motion } from 'framer-motion';
import {
  Play, Pause, SkipBack, SkipForward, RotateCcw,
  ShieldCheck, AlertTriangle, Cpu, Terminal, ArrowRight,
  Layers, Lock, Sparkles, Database, Info, Copy, Check
} from 'lucide-react';
import { usePcapStore, TlsStepNode } from '@/lib/store/usePcapStore';
import clsx from 'clsx';

// Custom Node for TLS Handshake Messages
function TlsMessageNode({ data }: { data: TlsStepNode & { isCurrent: boolean } }) {
  const isClientToServer = data.direction === 'client-to-server';
  const isCurrent = data.isCurrent;

  return (
    <div
      className={clsx(
        'w-64 p-3 rounded-lg border shadow-lg transition-all duration-300 relative font-sans cursor-pointer',
        isCurrent
          ? 'bg-[var(--color-surface-3)] border-[var(--color-accent)] ring-2 ring-[var(--color-accent)]/40 shadow-[0_0_20px_rgba(56,189,248,0.25)] scale-105 z-20'
          : 'bg-[var(--color-surface-2)] border-[var(--color-border)] hover:border-[var(--color-border-subtle)] text-[var(--color-text-secondary)] opacity-85 hover:opacity-100'
      )}
    >
      <Handle type="target" position={isClientToServer ? Position.Left : Position.Right} className="!bg-[var(--color-accent)] !w-2 !h-2" />
      <Handle type="source" position={isClientToServer ? Position.Right : Position.Left} className="!bg-[var(--color-accent)] !w-2 !h-2" />

      {/* Header */}
      <div className="flex items-center justify-between gap-1 mb-1.5">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{
            backgroundColor: data.status === 'valid' ? '#10b981' : data.status === 'warning' ? '#f59e0b' : '#ef4444'
          }} />
          <span className="text-[12px] font-bold text-[var(--color-text-primary)] tracking-tight">
            {data.name}
          </span>
        </div>
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-1)] text-[var(--color-text-muted)] border border-[var(--color-border)]">
          +{data.timestampMs}ms
        </span>
      </div>

      {/* Direction & Version */}
      <div className="flex items-center justify-between text-[10px] text-[var(--color-text-dim)] border-t border-[var(--color-border-subtle)] pt-1.5">
        <span className="font-mono text-[var(--color-accent)] font-semibold">{data.version}</span>
        <span className="flex items-center gap-1 font-mono">
          {isClientToServer ? 'Client ➔ Server' : 'Server ➔ Client'}
        </span>
      </div>

      {/* Summary Snippet */}
      {data.cipher && (
        <div className="mt-1.5 text-[10px] text-[var(--color-text-muted)] line-clamp-1 font-mono bg-[var(--color-surface-1)] p-1 rounded">
          {data.cipher}
        </div>
      )}
    </div>
  );
}

const nodeTypes = {
  tlsMessage: TlsMessageNode,
};

export default function TlsSequenceDiagram() {
  const {
    tlsSteps,
    activeStepIndex,
    setActiveStepIndex,
    nextStep,
    prevStep,
    isPlaying,
    setIsPlaying,
    playbackSpeed,
    setPlaybackSpeed,
    reset,
  } = usePcapStore();

  const activeStep = tlsSteps[activeStepIndex] || tlsSteps[0];

  // Playback timer loop
  useEffect(() => {
    let timer: any;
    if (isPlaying) {
      timer = setInterval(() => {
        nextStep();
      }, playbackSpeed);
    }
    return () => clearInterval(timer);
  }, [isPlaying, playbackSpeed, nextStep]);

  // Construct React Flow Nodes and Edges based on vertical Client and Server axes
  const { nodes, edges } = useMemo(() => {
    const generatedNodes: Node[] = [];
    const generatedEdges: Edge[] = [];

    // Dual axis positions: Client X = 80, Server X = 480
    const clientX = 80;
    const serverX = 480;
    const startY = 40;
    const gapY = 110;

    tlsSteps.forEach((step, idx) => {
      const isClientToServer = step.direction === 'client-to-server';
      const xPos = isClientToServer ? clientX : serverX;
      const yPos = startY + idx * gapY;
      const isCurrent = idx === activeStepIndex;

      generatedNodes.push({
        id: step.id,
        type: 'tlsMessage',
        position: { x: xPos, y: yPos },
        data: { ...step, isCurrent },
      });

      // Connect sequence flow
      if (idx > 0) {
        const prev = tlsSteps[idx - 1];
        generatedEdges.push({
          id: `edge-${prev.id}-${step.id}`,
          source: prev.id,
          target: step.id,
          animated: isCurrent,
          style: {
            stroke: isCurrent ? 'var(--color-accent)' : 'rgba(255,255,255,0.15)',
            strokeWidth: isCurrent ? 2.5 : 1.5,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isCurrent ? 'var(--color-accent)' : 'rgba(255,255,255,0.3)',
          },
        });
      }
    });

    return { nodes: generatedNodes, edges: generatedEdges };
  }, [tlsSteps, activeStepIndex]);

  return (
    <div className="space-y-4">
      {/* ── Playback Controls Bar ── */}
      <div className="card p-3 bg-[var(--color-surface-1)] border border-[var(--color-border)] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-[var(--color-surface-2)] p-1 rounded-md border border-[var(--color-border)]">
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className={clsx(
                'flex items-center gap-1.5 px-3 py-1.5 rounded text-[12px] font-semibold transition-colors',
                isPlaying
                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  : 'bg-[var(--color-accent)] text-[#0B0D10] hover:bg-[#5ccbfc]'
              )}
            >
              {isPlaying ? <Pause size={14} /> : <Play size={14} />}
              <span>{isPlaying ? 'Pause' : 'Play Sequence'}</span>
            </button>

            <button
              onClick={prevStep}
              disabled={activeStepIndex === 0}
              className="p-1.5 rounded text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors disabled:opacity-30"
              title="Previous Message"
            >
              <SkipBack size={14} />
            </button>

            <button
              onClick={nextStep}
              disabled={activeStepIndex === tlsSteps.length - 1}
              className="p-1.5 rounded text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors disabled:opacity-30"
              title="Next Message"
            >
              <SkipForward size={14} />
            </button>

            <button
              onClick={reset}
              className="p-1.5 rounded text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors"
              title="Reset to ClientHello"
            >
              <RotateCcw size={14} />
            </button>
          </div>

          {/* Speed Selector */}
          <div className="flex items-center gap-1 text-[11px] text-[var(--color-text-muted)] ml-2">
            <span>Speed:</span>
            {[500, 1000, 2000].map(s => (
              <button
                key={s}
                onClick={() => setPlaybackSpeed(s)}
                className={clsx(
                  'px-2 py-0.5 rounded font-mono text-[10px] transition-colors',
                  playbackSpeed === s
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] font-bold border border-[var(--color-accent)]/30'
                    : 'bg-[var(--color-surface-2)] text-[var(--color-text-dim)] hover:text-[var(--color-text-primary)]'
                )}
              >
                {s === 500 ? '2x' : s === 1000 ? '1x' : '0.5x'}
              </button>
            ))}
          </div>
        </div>

        {/* Axis Labels */}
        <div className="flex items-center gap-6 font-mono text-[11px]">
          <div className="flex items-center gap-1.5 text-sky-400">
            <span className="w-2 h-2 rounded-full bg-sky-400" />
            <span>Client (192.168.1.100:54320)</span>
          </div>
          <ArrowRight size={13} className="text-[var(--color-text-dim)]" />
          <div className="flex items-center gap-1.5 text-indigo-400">
            <span className="w-2 h-2 rounded-full bg-indigo-400" />
            <span>Server (192.168.1.3:587 SMTP)</span>
          </div>
          <div className="px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-[10px] font-mono text-[var(--color-accent)]">
            Step {activeStepIndex + 1} of {tlsSteps.length}
          </div>
        </div>
      </div>

      {/* ── Main Sequence & Inspector Split ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 h-[680px]">
        {/* React Flow Sequence Diagram (7 cols) */}
        <div className="lg:col-span-7 card p-0 overflow-hidden relative border border-[var(--color-border)] bg-[#070b14]">
          <div className="absolute top-3 left-4 z-10 font-mono text-[11px] text-[var(--color-text-muted)] bg-[var(--color-surface-1)]/80 backdrop-blur-sm px-2.5 py-1 rounded border border-[var(--color-border)]">
            Interactive Handshake Flow (Drag / Zoom / Click Steps)
          </div>

          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => {
              const clickedIdx = tlsSteps.findIndex(s => s.id === node.id);
              if (clickedIdx !== -1) setActiveStepIndex(clickedIdx);
            }}
            fitView
            minZoom={0.5}
            maxZoom={1.5}
          >
            <Background color="rgba(255,255,255,0.06)" gap={20} size={1} />
            <Controls className="!bg-[var(--color-surface-2)] !border-[var(--color-border)] !fill-[var(--color-text-secondary)]" />
          </ReactFlow>
        </div>

        {/* Deep Forensic Inspector Panel (5 cols) */}
        <div className="lg:col-span-5 card p-4 overflow-y-auto space-y-4 bg-[var(--color-surface-1)] border border-[var(--color-border)]">
          {/* Active Step Header */}
          <div className="flex items-start justify-between gap-2 pb-3 border-b border-[var(--color-border)]">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[14px] font-bold text-[var(--color-text-primary)]">
                  {activeStep.name}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[var(--color-accent)]/30">
                  {activeStep.version}
                </span>
              </div>
              <p className="text-[11px] text-[var(--color-text-muted)] mt-0.5">
                Observed packet delta: <span className="font-mono text-[var(--color-text-primary)]">+{activeStep.timestampMs} ms</span>
              </p>
            </div>
            <div className="text-[11px] font-mono px-2 py-1 rounded bg-[var(--color-surface-2)] text-[var(--color-text-secondary)]">
              {activeStep.direction === 'client-to-server' ? 'EGRESS ➔' : 'INGRESS ➔'}
            </div>
          </div>

          {/* Negotiated Cryptographic Parameters */}
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
              <Lock size={12} className="text-[var(--color-accent)]" />
              <span>Parsed Protocol Parameters</span>
            </div>

            <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1.5 font-mono text-[11px]">
              {Object.entries(activeStep.parsedSummary).map(([k, v]) => (
                <div key={k} className="flex items-start justify-between gap-2">
                  <span className="text-[var(--color-text-dim)] flex-shrink-0">{k}:</span>
                  <span className="text-[var(--color-text-primary)] text-right font-medium break-all">
                    {Array.isArray(v) ? v.join(', ') : String(v)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Raw Hex-Dump Dissection */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
              <div className="flex items-center gap-1.5">
                <Terminal size={12} className="text-emerald-400" />
                <span>Raw Packet Hex-Dump (Wire Format)</span>
              </div>
              <span className="text-[10px] font-mono text-[var(--color-text-dim)]">Offset 0x0000</span>
            </div>

            <div className="p-3 rounded-lg bg-[#050811] border border-[var(--color-border-subtle)] font-mono text-[11px] leading-relaxed overflow-x-auto text-emerald-400/90 shadow-inner">
              <div className="flex gap-4">
                <div className="text-slate-500 select-none">
                  0000<br />0010<br />0020<br />0030
                </div>
                <div className="space-y-0.5 tracking-wider">
                  {activeStep.hexDump}
                </div>
              </div>
            </div>
          </div>

          {/* AI Security Recommendation for this step */}
          <div className="p-3 rounded-lg bg-sky-950/20 border border-sky-800/30 text-[11px] space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-sky-400">
              <Sparkles size={13} />
              <span>Cryptographic Posture Assessment</span>
            </div>
            <p className="text-[var(--color-text-secondary)] leading-relaxed">
              {activeStep.status === 'valid'
                ? 'Handshake parameter conforms to TLS 1.3 NIST PQC standards with zero downgrade vectors.'
                : activeStep.status === 'warning'
                ? 'Certificate expires in under 30 days. Recommend automated renewal via ACME / enterprise CA.'
                : 'Cryptographically deprecated parameter detected. High risk of downgrade exploitation.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
