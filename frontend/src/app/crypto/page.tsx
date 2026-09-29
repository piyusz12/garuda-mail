'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Lock, Key, AlertTriangle, CheckCircle, XCircle,
  HelpCircle, ExternalLink, Cpu, Sparkles, Filter, ChevronRight
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore, PostureBar } from '@/components/ui/shared';
import { mockPosture, mockSessions, mockFindings } from '@/lib/mock/data';
import { getPolicyStatusLabel, getPolicyStatusColor } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

// Detailed observed cipher suites across enterprise capture
const OBSERVED_CIPHERS = [
  {
    name: 'TLS_AES_256_GCM_SHA384',
    protocol: 'TLS 1.3',
    kex: 'ECDHE (X25519)',
    auth: 'ECDSA',
    encryption: 'AES-256-GCM',
    hash: 'SHA-384',
    pfs: true,
    policy: 'compliant',
    sessionsCount: 78,
    standard: 'NIST SP 800-52r2 Recommended',
  },
  {
    name: 'TLS_CHACHA20_POLY1305_SHA256',
    protocol: 'TLS 1.3',
    kex: 'ECDHE (X25519)',
    auth: 'ECDSA',
    encryption: 'ChaCha20-Poly1305',
    hash: 'SHA-256',
    pfs: true,
    policy: 'compliant',
    sessionsCount: 34,
    standard: 'NIST SP 800-52r2 Recommended',
  },
  {
    name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    protocol: 'TLS 1.2',
    kex: 'ECDHE (P-256)',
    auth: 'RSA',
    encryption: 'AES-256-GCM',
    hash: 'SHA-384',
    pfs: true,
    policy: 'acceptable',
    sessionsCount: 112,
    standard: 'PCI DSS 4.0 Approved',
  },
  {
    name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    protocol: 'TLS 1.2',
    kex: 'ECDHE (P-256)',
    auth: 'RSA',
    encryption: 'AES-128-GCM',
    hash: 'SHA-256',
    pfs: true,
    policy: 'acceptable',
    sessionsCount: 19,
    standard: 'PCI DSS 4.0 Approved',
  },
  {
    name: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    protocol: 'TLS 1.0',
    kex: 'RSA (Static)',
    auth: 'RSA',
    encryption: 'AES-128-CBC',
    hash: 'SHA-1',
    pfs: false,
    policy: 'insecure',
    sessionsCount: 3,
    standard: 'NIST SP 800-52r2 Non-Compliant',
  },
  {
    name: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    protocol: 'TLS 1.1',
    kex: 'RSA (Static)',
    auth: 'RSA',
    encryption: '3DES (Sweet32)',
    hash: 'SHA-1',
    pfs: false,
    policy: 'deprecated',
    sessionsCount: 2,
    standard: 'NIST SP 800-131A Disallowed',
  },
];

export default function CryptoPosturePage() {
  const [filterPolicy, setFilterPolicy] = useState<string>('all');

  const filteredCiphers = OBSERVED_CIPHERS.filter(c => {
    if (filterPolicy === 'all') return true;
    return c.policy === filterPolicy;
  });

  return (
    <AppShell
      title="Cryptographic Posture"
      description="In-depth audit of enterprise email TLS handshakes, cipher suites, forward secrecy, and Post-Quantum readiness"
    >
      <div className="space-y-6">

        {/* ── Top Metric Cards ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="card p-5 space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Overall Crypto Health</span>
              <Shield size={16} className="text-[var(--color-accent)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-accent)] tabular-nums">
              74<span className="text-base text-[var(--color-text-muted)] font-normal">/100</span>
            </div>
            <p className="text-[11px] text-[var(--color-severity-high)] font-medium">
              3 non-compliant protocol versions detected
            </p>
          </div>

          <div className="card p-5 space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Forward Secrecy (PFS)</span>
              <Lock size={16} className="text-[var(--color-severity-healthy)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-healthy)] tabular-nums">
              91.4%
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">
              227 of 248 sessions protected with ECDHE/DHE
            </p>
          </div>

          <div className="card p-5 space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>TLS 1.2+ Adoption</span>
              <CheckCircle size={16} className="text-[var(--color-severity-healthy)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-healthy)] tabular-nums">
              97.2%
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">
              241 modern sessions (112 TLS 1.3, 129 TLS 1.2)
            </p>
          </div>

          <div className="card p-5 space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>PQC Migration Status</span>
              <Sparkles size={16} className="text-[var(--color-severity-high)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-high)] tabular-nums">
              0% <span className="text-sm font-normal text-[var(--color-text-dim)]">PQC Hybrid</span>
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">
              Store-now-decrypt-later vulnerability on all classical RSA/ECC
            </p>
          </div>
        </div>

        {/* ── Protocol Distribution & Compliance Checklist ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* TLS Version Breakdown (2 cols) */}
          <div className="lg:col-span-2 card p-6 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
                  TLS Protocol Version Distribution
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Telemetry distribution across all 248 captured email sessions
                </p>
              </div>
            </div>

            <div className="space-y-4">
              {/* TLS 1.3 */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[var(--color-severity-healthy)]" />
                    TLS 1.3 (RFC 8446)
                  </span>
                  <span className="text-[var(--color-text-secondary)] text-mono font-medium">
                    112 sessions (45.2%) — <span className="text-[var(--color-severity-healthy)] font-bold">COMPLIANT</span>
                  </span>
                </div>
                <div className="h-2 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                  <div className="h-full bg-[var(--color-severity-healthy)] rounded-full" style={{ width: '45.2%' }} />
                </div>
              </div>

              {/* TLS 1.2 */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[var(--color-accent)]" />
                    TLS 1.2 (RFC 5246)
                  </span>
                  <span className="text-[var(--color-text-secondary)] text-mono font-medium">
                    129 sessions (52.0%) — <span className="text-[var(--color-accent)] font-bold">ACCEPTABLE</span>
                  </span>
                </div>
                <div className="h-2 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                  <div className="h-full bg-[var(--color-accent)] rounded-full" style={{ width: '52.0%' }} />
                </div>
              </div>

              {/* TLS 1.1 */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[var(--color-severity-high)]" />
                    TLS 1.1 (RFC 4346)
                  </span>
                  <span className="text-[var(--color-text-secondary)] text-mono font-medium">
                    2 sessions (0.8%) — <span className="text-[var(--color-severity-high)] font-bold">DEPRECATED</span>
                  </span>
                </div>
                <div className="h-2 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                  <div className="h-full bg-[var(--color-severity-high)] rounded-full" style={{ width: '0.8%' }} />
                </div>
              </div>

              {/* TLS 1.0 */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[var(--color-severity-critical)]" />
                    TLS 1.0 (RFC 2246)
                  </span>
                  <span className="text-[var(--color-text-secondary)] text-mono font-medium">
                    3 sessions (1.2%) — <span className="text-[var(--color-severity-critical)] font-bold">INSECURE</span>
                  </span>
                </div>
                <div className="h-2 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                  <div className="h-full bg-[var(--color-severity-critical)] rounded-full" style={{ width: '1.2%' }} />
                </div>
              </div>

              {/* Plaintext */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[var(--color-severity-critical)]" />
                    Plaintext (Cleartext Port 143/25)
                  </span>
                  <span className="text-[var(--color-text-secondary)] text-mono font-medium">
                    2 sessions (0.8%) — <span className="text-[var(--color-severity-critical)] font-bold">UNENCRYPTED</span>
                  </span>
                </div>
                <div className="h-2 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                  <div className="h-full bg-[var(--color-severity-critical)] rounded-full" style={{ width: '0.8%' }} />
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[var(--color-border-subtle)] text-[11px] text-[var(--color-text-muted)] flex items-center gap-2">
              <AlertTriangle size={14} className="text-[var(--color-severity-high)] flex-shrink-0" />
              <span>NIST SP 800-52r2 Section 3.1 mandates deprecation of TLS 1.0/1.1 across all federal and regulated enterprise email gateways.</span>
            </div>
          </div>

          {/* Compliance & Standards Guard (1 col) */}
          <div className="card p-6 space-y-4">
            <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
              Compliance Mandates
            </h3>

            <div className="space-y-3">
              <div className="p-3 rounded-lg border border-[rgba(239,68,68,0.3)] bg-[rgba(239,68,68,0.03)] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">PCI DSS 4.0 (Req 4.2)</span>
                  <span className="badge-critical text-[9px] px-1.5 py-0.5 rounded font-bold">FAIL</span>
                </div>
                <p className="text-[11px] text-[var(--color-text-muted)]">
                  TLS 1.0 negotiation violates modern secure transmission mandate.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[rgba(239,68,68,0.3)] bg-[rgba(239,68,68,0.03)] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">NIST SP 800-52 Rev 2</span>
                  <span className="badge-critical text-[9px] px-1.5 py-0.5 rounded font-bold">FAIL</span>
                </div>
                <p className="text-[11px] text-[var(--color-text-muted)]">
                  Static RSA key exchange and SHA-1 in CBC cipher suites disallowed.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[rgba(34,197,94,0.3)] bg-[rgba(34,197,94,0.03)] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">RFC 8314 (Email TLS)</span>
                  <span className="badge-healthy text-[9px] px-1.5 py-0.5 rounded font-bold">PASS 96%</span>
                </div>
                <p className="text-[11px] text-[var(--color-text-muted)]">
                  Submission and retrieval protocols successfully enforce TLS on dedicated ports.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[rgba(234,179,8,0.3)] bg-[rgba(234,179,8,0.03)] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">CNSA 2.0 (PQC)</span>
                  <span className="badge-high text-[9px] px-1.5 py-0.5 rounded font-bold">LEGACY</span>
                </div>
                <p className="text-[11px] text-[var(--color-text-muted)]">
                  No post-quantum key encapsulation (ML-KEM/Kyber) deployed on gateways.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* ── Cipher Suite Audit Matrix ── */}
        <div className="card p-6 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
                Observed Cipher Suite Inventory
              </h3>
              <p className="text-[12px] text-[var(--color-text-muted)]">
                Breakdown of key exchange, encryption algorithms, hashing, and policy statuses
              </p>
            </div>

            {/* Filter buttons */}
            <div className="flex items-center gap-1.5 bg-[var(--color-surface-2)] p-1 rounded-lg border border-[var(--color-border)]">
              {['all', 'compliant', 'acceptable', 'deprecated', 'insecure'].map((policy) => (
                <button
                  key={policy}
                  onClick={() => setFilterPolicy(policy)}
                  className={clsx(
                    'px-2.5 py-1 text-[11px] font-medium rounded-md capitalize transition-colors',
                    filterPolicy === policy
                      ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                  )}
                >
                  {policy}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                  <th className="py-2.5 px-3">Cipher Suite Name</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">Key Exchange</th>
                  <th className="py-2.5 px-3">Encryption</th>
                  <th className="py-2.5 px-3">Hash</th>
                  <th className="py-2.5 px-3">PFS</th>
                  <th className="py-2.5 px-3">Policy Status</th>
                  <th className="py-2.5 px-3">Sessions</th>
                  <th className="py-2.5 px-3">Compliance Standard</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {filteredCiphers.map((c, i) => (
                  <tr key={i} className="hover:bg-[var(--color-surface-2)] transition-colors">
                    <td className="py-3 px-3 text-mono font-medium text-[var(--color-text-primary)]">
                      {c.name}
                    </td>
                    <td className="py-3 px-3 text-mono text-[var(--color-text-secondary)]">
                      {c.protocol}
                    </td>
                    <td className="py-3 px-3 text-[var(--color-text-secondary)]">
                      {c.kex}
                    </td>
                    <td className="py-3 px-3 text-[var(--color-text-secondary)]">
                      {c.encryption}
                    </td>
                    <td className="py-3 px-3 text-mono text-[var(--color-text-dim)]">
                      {c.hash}
                    </td>
                    <td className="py-3 px-3">
                      {c.pfs ? (
                        <span className="badge-healthy text-[10px] px-1.5 py-0.5 rounded font-semibold">YES</span>
                      ) : (
                        <span className="badge-critical text-[10px] px-1.5 py-0.5 rounded font-semibold">NO</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className="text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider"
                        style={{
                          backgroundColor: `${getPolicyStatusColor(c.policy)}18`,
                          color: getPolicyStatusColor(c.policy),
                          border: `1px solid ${getPolicyStatusColor(c.policy)}30`,
                        }}
                      >
                        {getPolicyStatusLabel(c.policy)}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-mono font-medium">
                      {c.sessionsCount}
                    </td>
                    <td className="py-3 px-3 text-[11px] text-[var(--color-text-dim)]">
                      {c.standard}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </AppShell>
  );
}
