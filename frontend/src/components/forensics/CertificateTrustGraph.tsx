'use client';

import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { usePcapStore, CertNode } from '@/lib/store/usePcapStore';
import {
  Award, ShieldAlert, CheckCircle2, XCircle, AlertTriangle,
  Key, Calendar, Copy, Check, FileCheck, Layers, ExternalLink
} from 'lucide-react';
import clsx from 'clsx';

export default function CertificateTrustGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const { certificates, selectedCertId, setSelectedCertId } = usePcapStore();
  const [copied, setCopied] = useState(false);

  const selectedCert = certificates.find(c => c.id === selectedCertId) || certificates[0];

  useEffect(() => {
    if (!containerRef.current) return;

    // Convert certs to Cytoscape elements (Nodes & Hierarchy Edges)
    const elements: cytoscape.ElementDefinition[] = [];

    certificates.forEach(c => {
      // Determine node color based on status
      let bgColor = '#10b981'; // trusted green
      let borderColor = '#34d399';
      if (c.status === 'expiring') {
        bgColor = '#f59e0b'; // amber
        borderColor = '#fbbf24';
      } else if (c.status === 'expired' || c.status === 'self-signed' || c.status === 'weak') {
        bgColor = '#ef4444'; // critical red
        borderColor = '#f87171';
      }

      elements.push({
        data: {
          id: c.id,
          label: c.subject.split(',')[0].replace('CN=', ''),
          status: c.status,
          keySize: c.keySize,
          keyType: c.keyType,
          bgColor,
          borderColor,
        },
      });

      if (c.parentId) {
        elements.push({
          data: {
            id: `edge-${c.parentId}-${c.id}`,
            source: c.parentId,
            target: c.id,
            label: 'Signs',
          },
        });
      }
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(bgColor)',
            'label': 'data(label)',
            'color': '#f8fafc',
            'font-family': 'Inter, sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'width': 44,
            'height': 44,
            'border-width': 3,
            'border-color': 'data(borderColor)',
            'overlay-opacity': 0,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 6,
            'border-color': '#38bdf8',
            'shadow-blur': 25,
            'shadow-color': 'rgba(56,189,248,0.7)',
            'shadow-opacity': 0.8,
          } as any,
        },
        {
          selector: 'edge',
          style: {
            'width': 2.5,
            'line-color': 'rgba(255, 255, 255, 0.25)',
            'target-arrow-color': 'rgba(255, 255, 255, 0.4)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.2,
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.4,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    cy.on('tap', 'node', evt => {
      const node = evt.target;
      setSelectedCertId(node.id());
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [certificates, setSelectedCertId]);

  // Synchronize selection highlight
  useEffect(() => {
    if (cyRef.current && selectedCertId) {
      cyRef.current.nodes().unselect();
      const target = cyRef.current.getElementById(selectedCertId);
      if (target) target.select();
    }
  }, [selectedCertId]);

  const copyFingerprint = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      {/* ── Cytoscape WebGL Graph (7 cols) ── */}
      <div className="lg:col-span-7 card p-0 overflow-hidden relative border border-[var(--color-border)] bg-[#070b14] h-[540px]">
        {/* Graph Legend Overlay */}
        <div className="absolute top-3 left-4 z-10 flex items-center gap-3 bg-[var(--color-surface-1)]/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-[var(--color-border)] text-[11px] font-mono">
          <div className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span>Trusted Root</span>
          </div>
          <div className="flex items-center gap-1.5 text-amber-400">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span>Expiring (&lt;30d)</span>
          </div>
          <div className="flex items-center gap-1.5 text-rose-400">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span>Expired / Weak</span>
          </div>
        </div>

        {/* Cytoscape Container */}
        <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
      </div>

      {/* ── Certificate Inspector Details (5 cols) ── */}
      <div className="lg:col-span-5 card p-4 overflow-y-auto space-y-4 bg-[var(--color-surface-1)] border border-[var(--color-border)] h-[540px]">
        <div className="flex items-start justify-between gap-2 pb-3 border-b border-[var(--color-border)]">
          <div>
            <div className="flex items-center gap-2">
              <Award size={16} className="text-[var(--color-accent)]" />
              <h3 className="text-[14px] font-bold text-[var(--color-text-primary)]">
                {selectedCert.subject.split(',')[0]}
              </h3>
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)] mt-0.5 font-mono">
              Serial: {selectedCert.serialNumber}
            </p>
          </div>

          <span
            className={clsx(
              'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider',
              selectedCert.status === 'trusted'
                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                : selectedCert.status === 'expiring'
                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
            )}
          >
            {selectedCert.status}
          </span>
        </div>

        {/* Cryptographic Specifications */}
        <div className="space-y-2 font-mono text-[11px]">
          <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-dim)]">Public Key:</span>
              <span className="text-[var(--color-text-primary)] font-bold">
                {selectedCert.keyType} {selectedCert.keySize}-bit
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-dim)]">Signature Hash:</span>
              <span className={clsx(selectedCert.signatureAlgorithm.includes('SHA1') ? 'text-rose-400 font-bold' : 'text-[var(--color-text-primary)]')}>
                {selectedCert.signatureAlgorithm}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-dim)]">Valid Window:</span>
              <span className="text-[var(--color-text-primary)]">
                {selectedCert.validFrom} ➔ {selectedCert.validTo}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-text-dim)]">Days Remaining:</span>
              <span className={clsx('font-bold', selectedCert.daysRemaining < 0 ? 'text-rose-400' : selectedCert.daysRemaining < 30 ? 'text-amber-400' : 'text-emerald-400')}>
                {selectedCert.daysRemaining < 0 ? `EXPIRED (${Math.abs(selectedCert.daysRemaining)}d ago)` : `${selectedCert.daysRemaining} days`}
              </span>
            </div>
          </div>
        </div>

        {/* Issuer and Trust Chain */}
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] block">Certificate Authority Issuer</label>
          <div className="p-2.5 rounded bg-[var(--color-surface-2)] text-[11px] font-mono text-[var(--color-text-secondary)] border border-[var(--color-border-subtle)]">
            {selectedCert.issuer}
          </div>
        </div>

        {/* Subject Alternative Names (SANs) */}
        {selectedCert.sanList.length > 0 && (
          <div className="space-y-1.5">
            <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] block">Subject Alternative Names (SANs)</label>
            <div className="flex flex-wrap gap-1">
              {selectedCert.sanList.map((san, idx) => (
                <span key={idx} className="px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-[10px] font-mono text-[var(--color-accent)] border border-[var(--color-border)]">
                  {san}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* SHA-256 Fingerprint */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)]">SHA-256 Fingerprint</label>
            <button
              onClick={() => copyFingerprint(selectedCert.fingerprintSha256)}
              className="text-[10px] text-[var(--color-accent)] hover:underline flex items-center gap-1"
            >
              {copied ? <Check size={11} /> : <Copy size={11} />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-2 rounded bg-[#050811] text-[10px] font-mono text-slate-300 break-all border border-[var(--color-border-subtle)]">
            {selectedCert.fingerprintSha256}
          </div>
        </div>
      </div>
    </div>
  );
}
