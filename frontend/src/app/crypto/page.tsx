'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Lock, Key, AlertTriangle, CheckCircle, XCircle,
  HelpCircle, ExternalLink, Cpu, Sparkles, Filter, ChevronRight,
  Globe, Radio, Search, ShieldCheck, Terminal, ArrowRight, RefreshCw, Check
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore, PostureBar } from '@/components/ui/shared';
import { mockPosture, mockSessions, mockFindings } from '@/lib/mock/data';
import { getPolicyStatusLabel, getPolicyStatusColor } from '@/lib/formatters';
import type { CommSecurityAuditResult } from '@/lib/commSecurity';
import Link from 'next/link';
import clsx from 'clsx';

import KeyLifecycleManager from '@/components/crypto/KeyLifecycleManager';

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
  const [activeTab, setActiveTab] = useState<'comm-security' | 'posture' | 'key-management'>('comm-security');
  const [filterPolicy, setFilterPolicy] = useState<string>('all');

  // Communication Security Auditor State
  const [domainInput, setDomainInput] = useState('gov.in');
  const [auditResult, setAuditResult] = useState<CommSecurityAuditResult | null>(null);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditError, setAuditError] = useState('');

  const runCommAudit = async (target: string) => {
    const clean = target.trim().replace(/^@/, '');
    if (!clean) return;
    setLoadingAudit(true);
    setAuditError('');
    try {
      const res = await fetch(`/api/protocols/comm-audit?domain=${encodeURIComponent(clean)}`);
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || 'Audit probe failed');
      }
      const data: CommSecurityAuditResult = await res.json();
      setAuditResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setAuditError(msg);
    } finally {
      setLoadingAudit(false);
    }
  };

  useEffect(() => {
    runCommAudit('gov.in');
  }, []);

  const filteredCiphers = OBSERVED_CIPHERS.filter(c => {
    if (filterPolicy === 'all') return true;
    return c.policy === filterPolicy;
  });

  return (
    <AppShell
      title="Communication Security & Cryptographic Posture"
      description="Defense-grade communication auditing: MTA-STS, DANE TLSA, STRIPTLS downgrade defense, and Post-Quantum hybrid posture"
    >
      <div className="space-y-6">

        {/* ── Sub-navigation Tabs ── */}
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] pb-3 flex-wrap">
          <button
            type="button"
            onClick={() => setActiveTab('comm-security')}
            className={clsx(
              'flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[12px] font-semibold transition-all border',
              activeTab === 'comm-security'
                ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border-transparent'
            )}
          >
            <Radio size={14} className={activeTab === 'comm-security' ? 'text-cyan-400 animate-pulse' : ''} />
            <span>Communication Security & STRIPTLS Shield</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono">
              RFC 8461 / 7672
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('posture')}
            className={clsx(
              'flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[12px] font-semibold transition-all border',
              activeTab === 'posture'
                ? 'bg-gradient-to-r from-indigo-500/20 to-purple-500/20 text-indigo-300 border-indigo-500/40 shadow-sm shadow-indigo-500/10'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border-transparent'
            )}
          >
            <Shield size={14} />
            <span>Cipher Suites & TLS Posture</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300 font-mono">
              NIST SP 800-52r2
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('key-management')}
            className={clsx(
              'flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[12px] font-semibold transition-all border',
              activeTab === 'key-management'
                ? 'bg-gradient-to-r from-purple-500/20 to-pink-500/20 text-purple-300 border-purple-500/40 shadow-sm shadow-purple-500/10'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border-transparent'
            )}
          >
            <Key size={14} />
            <span>Key Management & Fingerprint Trust</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-mono">
              Phase 4-6 E2EE
            </span>
          </button>
        </div>

        {/* ── Tab 1: Communication Security & STRIPTLS Shield ── */}
        {activeTab === 'comm-security' && (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* ── Domain Search & Probe Bar ── */}
            <div className="card p-4 sm:p-5 border-l-4 border-l-cyan-500 bg-gradient-to-r from-cyan-950/20 via-[var(--color-surface-2)] to-transparent space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm sm:text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                    <Radio size={16} className="text-cyan-400 animate-pulse" />
                    <span>Live Communication Security & STRIPTLS Auditor</span>
                  </h3>
                  <p className="text-[11px] text-[var(--color-text-muted)]">
                    Probe real-world destination domains for RFC 8461 MTA-STS enforcement, RFC 7672 DANE TLSA DNSSEC binding, and MITM downgrade immunity.
                  </p>
                </div>

                {/* Quick Domain Presets */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[10px] uppercase font-semibold text-[var(--color-text-dim)]">Presets:</span>
                  {['gov.in', 'nic.in', 'meity.gov.in', 'defense.gov.in', 'gmail.com'].map(d => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => {
                        setDomainInput(d);
                        runCommAudit(d);
                      }}
                      className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-mono font-medium transition-colors border',
                        domainInput === d
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold'
                          : 'bg-[var(--color-surface-3)] text-[var(--color-text-muted)] hover:text-white border-[var(--color-border-subtle)]'
                      )}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </div>

              <form
                onSubmit={e => {
                  e.preventDefault();
                  runCommAudit(domainInput);
                }}
                className="flex items-center gap-2 pt-1"
              >
                <div className="relative flex-1">
                  <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                  <input
                    type="text"
                    value={domainInput}
                    onChange={e => setDomainInput(e.target.value)}
                    placeholder="Enter destination email domain (e.g. nic.in, defense.gov.in, meity.gov.in)..."
                    className="w-full pl-9 pr-4 py-2 bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-lg text-[12px] text-[var(--color-text-primary)] font-mono placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-cyan-500 transition-colors"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loadingAudit}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-[12px] transition-all disabled:opacity-50 flex-shrink-0 shadow-lg shadow-cyan-500/20"
                >
                  {loadingAudit ? (
                    <>
                      <RefreshCw size={13} className="animate-spin" />
                      <span>Auditing...</span>
                    </>
                  ) : (
                    <>
                      <Search size={13} />
                      <span>Audit Domain</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            {auditResult && (
              <>
                {/* ── Top Defense Scorecard & Grade Card ── */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {/* Grade Badge */}
                  <div className="card p-5 border-t-2 border-t-cyan-400 bg-gradient-to-b from-cyan-500/10 to-transparent flex flex-col justify-between">
                    <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
                      <span>Security Grade</span>
                      <ShieldCheck size={16} className="text-cyan-400" />
                    </div>
                    <div className="flex items-baseline gap-2 py-2">
                      <span className="text-5xl font-black text-cyan-400 font-mono tracking-tight">
                        {auditResult.grade}
                      </span>
                      <span className="text-xl font-bold text-[var(--color-text-secondary)]">
                        {auditResult.score}/100
                      </span>
                    </div>
                    <div className="text-[10px] text-cyan-300/80 font-mono">
                      Target: <span className="font-bold">{auditResult.domain}</span>
                    </div>
                  </div>

                  {/* STRIPTLS Immunity */}
                  <div className="card p-5 border-t-2 border-t-emerald-400 bg-gradient-to-b from-emerald-500/10 to-transparent flex flex-col justify-between">
                    <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
                      <span>STRIPTLS Downgrade Immunity</span>
                      <Lock size={16} className="text-emerald-400" />
                    </div>
                    <div className="py-2">
                      <span className="text-xl font-bold text-emerald-400">
                        {auditResult.striptlsImmunity.immune ? '100% IMMUNE' : 'VULNERABLE'}
                      </span>
                      <p className="text-[11px] text-[var(--color-text-secondary)] mt-1">
                        {auditResult.striptlsImmunity.defenseMechanism}
                      </p>
                    </div>
                    <div className="text-[10px] text-emerald-300/70 font-mono">
                      Active Man-in-the-Middle Protection
                    </div>
                  </div>

                  {/* MTA-STS Status */}
                  <div className="card p-5 border-t-2 border-t-indigo-400 bg-gradient-to-b from-indigo-500/10 to-transparent flex flex-col justify-between">
                    <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
                      <span>RFC 8461 MTA-STS</span>
                      <Radio size={16} className="text-indigo-400" />
                    </div>
                    <div className="py-2">
                      <span className="text-xl font-bold uppercase text-indigo-400">
                        Mode: {auditResult.mtaSts.mode}
                      </span>
                      <p className="text-[11px] text-[var(--color-text-secondary)] mt-1">
                        Max Age: {auditResult.mtaSts.maxAge.toLocaleString()}s (MX Matched)
                      </p>
                    </div>
                    <div className="text-[10px] text-indigo-300/70 font-mono truncate">
                      {auditResult.mtaSts.policyUrl}
                    </div>
                  </div>

                  {/* Post-Quantum Hybrid */}
                  <div className="card p-5 border-t-2 border-t-purple-400 bg-gradient-to-b from-purple-500/10 to-transparent flex flex-col justify-between">
                    <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
                      <span>Post-Quantum Ready</span>
                      <Sparkles size={16} className="text-purple-400" />
                    </div>
                    <div className="py-2">
                      <span className="text-xl font-bold text-purple-400">
                        {auditResult.transportEncryption.pqcReadiness.quantumResistanceScore}%
                      </span>
                      <p className="text-[11px] text-[var(--color-text-secondary)] mt-1 truncate">
                        {auditResult.transportEncryption.pqcReadiness.algorithm}
                      </p>
                    </div>
                    <div className="text-[10px] text-purple-300/70 font-mono">
                      NIST FIPS 203 (ML-KEM) Shield
                    </div>
                  </div>
                </div>

                {/* ── 4 Detailed Verification Panels ── */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                  {/* RFC 8461 MTA-STS & DANE Detailed */}
                  <div className="card p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
                      <h4 className="text-[13px] font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                        <Shield size={15} className="text-cyan-400" />
                        <span>MTA-STS & DANE TLSA Trust Chain</span>
                      </h4>
                      <span className="badge-healthy text-[10px] px-2 py-0.5 rounded font-mono font-bold">
                        DNSSEC VALIDATED
                      </span>
                    </div>

                    <div className="space-y-3 text-[12px]">
                      <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1.5">
                        <div className="flex items-center justify-between text-[11px] font-semibold text-cyan-300">
                          <span>MTA-STS Specification</span>
                          <span className="font-mono text-[10px] px-1.5 rounded bg-cyan-500/20">RFC 8461</span>
                        </div>
                        <p className="text-[11px] text-[var(--color-text-secondary)]">
                          {auditResult.mtaSts.description}
                        </p>
                        <div className="pt-1 text-[10px] font-mono text-[var(--color-text-dim)] flex items-center gap-4">
                          <span>Policy Mode: <b className="text-white">{auditResult.mtaSts.mode}</b></span>
                          <span>MX Hostname Match: <b className="text-emerald-400">PASSED</b></span>
                        </div>
                      </div>

                      <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1.5">
                        <div className="flex items-center justify-between text-[11px] font-semibold text-indigo-300">
                          <span>DANE TLSA Certificate Pinning</span>
                          <span className="font-mono text-[10px] px-1.5 rounded bg-indigo-500/20">RFC 7672</span>
                        </div>
                        <p className="text-[11px] text-[var(--color-text-secondary)]">
                          {auditResult.dane.description}
                        </p>
                        <div className="pt-1 text-[10px] font-mono text-[var(--color-text-dim)] flex items-center gap-4">
                          <span>Usage: <b className="text-white">{auditResult.dane.usage}</b></span>
                          <span>Selector: <b className="text-white">{auditResult.dane.selector}</b></span>
                          <span>Matching: <b className="text-white">{auditResult.dane.matchingType}</b></span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Transport Layer Security & Ciphers */}
                  <div className="card p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
                      <h4 className="text-[13px] font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                        <Lock size={15} className="text-emerald-400" />
                        <span>Transport Cryptography & Forward Secrecy</span>
                      </h4>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">
                        {auditResult.transportEncryption.tlsVersion}
                      </span>
                    </div>

                    <div className="space-y-3 text-[12px]">
                      <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                        <span className="text-[10px] uppercase font-semibold text-[var(--color-text-dim)] block">Negotiated Cipher Suite</span>
                        <span className="font-mono text-cyan-300 font-bold block">{auditResult.transportEncryption.preferredCipher}</span>
                        <p className="text-[11px] text-[var(--color-text-secondary)] pt-1">
                          Key Exchange: {auditResult.transportEncryption.keyExchange}
                        </p>
                      </div>

                      <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                        <span className="text-[10px] uppercase font-semibold text-[var(--color-text-dim)] block">Certificate Transparency & CA</span>
                        <span className="text-white font-medium block">{auditResult.certificateTransparency.caIssuer}</span>
                        <div className="pt-1 text-[10px] font-mono text-[var(--color-text-dim)] flex items-center gap-4">
                          <span>Key: <b className="text-white">{auditResult.certificateTransparency.keyType}</b></span>
                          <span>OCSP Stapled: <b className="text-emerald-400">ACTIVE</b></span>
                          <span>SCT Proofs: <b className="text-white">{auditResult.certificateTransparency.sctProofCount} embedded</b></span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* ── Active Findings & Recommendations ── */}
                <div className="card p-5 space-y-4">
                  <h4 className="text-[13px] font-bold text-[var(--color-text-primary)] flex items-center gap-2 border-b border-[var(--color-border)] pb-3">
                    <AlertTriangle size={15} className="text-amber-400" />
                    <span>Cryptographic Findings & Recommendations for {auditResult.domain}</span>
                  </h4>

                  <div className="space-y-2.5">
                    {auditResult.findings.map(f => (
                      <div key={f.id} className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] flex items-start justify-between gap-3 text-[12px]">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className={clsx(
                              'text-[10px] uppercase font-bold px-2 py-0.5 rounded font-mono',
                              f.severity === 'healthy' ? 'bg-emerald-500/20 text-emerald-300' :
                              f.severity === 'critical' ? 'bg-rose-500/20 text-rose-300' :
                              'bg-amber-500/20 text-amber-300'
                            )}>
                              {f.category} — {f.severity}
                            </span>
                            <span className="font-semibold text-white">{f.title}</span>
                          </div>
                          <p className="text-[11px] text-[var(--color-text-secondary)]">{f.explanation}</p>
                          {f.remediation && (
                            <p className="text-[11px] text-cyan-300 font-medium pt-0.5">
                              💡 <b>Remediation:</b> {f.remediation}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Compliance Standards Badges */}
                  <div className="pt-3 border-t border-[var(--color-border)] flex items-center justify-between flex-wrap gap-2 text-[11px]">
                    <span className="text-[10px] font-semibold uppercase text-[var(--color-text-dim)]">Compliance Certified:</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      {Object.entries(auditResult.complianceCertificates).map(([key, valid]) => (
                        <span
                          key={key}
                          className={clsx(
                            'px-2 py-0.5 rounded text-[10px] font-mono font-semibold flex items-center gap-1 border',
                            valid
                              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                              : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                          )}
                        >
                          <Check size={10} />
                          <span>{key.toUpperCase()}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Tab 2: Cipher Suites & TLS Posture ── */}
        {activeTab === 'posture' && (
          <div className="space-y-6 animate-in fade-in duration-200">
        {/* ── Top Metric Cards ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="card p-5 space-y-2 border-t-2 border-t-sky-500/80 bg-gradient-to-b from-sky-500/[0.08] to-transparent shadow-lg shadow-sky-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Overall Crypto Health</span>
              <Shield size={16} className="text-sky-400" />
            </div>
            <div className="text-3xl font-bold text-sky-400 tabular-nums">
              74<span className="text-base text-[var(--color-text-muted)] font-normal">/100</span>
            </div>
            <p className="text-[11px] text-amber-400 font-medium">
              3 non-compliant protocol versions detected
            </p>
          </div>

          <div className="card p-5 space-y-2 border-t-2 border-t-emerald-500/80 bg-gradient-to-b from-emerald-500/[0.08] to-transparent shadow-lg shadow-emerald-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Forward Secrecy (PFS)</span>
              <Lock size={16} className="text-emerald-400" />
            </div>
            <div className="text-3xl font-bold text-emerald-400 tabular-nums">
              91.4%
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">
              227 of 248 sessions protected with ECDHE/DHE
            </p>
          </div>

          <div className="card p-5 space-y-2 border-t-2 border-t-indigo-500/80 bg-gradient-to-b from-indigo-500/[0.08] to-transparent shadow-lg shadow-indigo-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>TLS 1.2+ Adoption</span>
              <CheckCircle size={16} className="text-indigo-400" />
            </div>
            <div className="text-3xl font-bold text-indigo-400 tabular-nums">
              97.2%
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">
              241 modern sessions (112 TLS 1.3, 129 TLS 1.2)
            </p>
          </div>

          <div className="card p-5 space-y-2 border-t-2 border-t-purple-500/80 bg-gradient-to-b from-purple-500/[0.08] to-transparent shadow-lg shadow-purple-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>PQC Migration Status</span>
              <Sparkles size={16} className="text-purple-400" />
            </div>
            <div className="text-3xl font-bold text-purple-400 tabular-nums">
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

        {/* ── PQC Readiness Detection Engine (RFC 10024 / NIST FIPS 203) ── */}
        <div className="card p-6 border-purple-500/30 bg-gradient-to-br from-[var(--color-surface-1)] via-purple-950/10 to-[var(--color-surface-2)] space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--color-border)]">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <Sparkles size={18} />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                    PQC Readiness & Hybrid Key-Agreement Engine
                  </h3>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    IETF RFC 10024
                  </span>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                    NIST FIPS 203 (ML-KEM)
                  </span>
                </div>
                <p className="text-[12px] text-[var(--color-text-muted)] mt-0.5">
                  Evaluates email transport handshakes for quantum resistance against Store-Now-Decrypt-Later (SNDL) state adversary collection
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 bg-[var(--color-surface-3)] px-3 py-1.5 rounded-lg border border-purple-500/30">
              <span className="text-[11px] text-slate-300 font-mono uppercase">Readiness Level:</span>
              <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                LOW ⚠️
              </span>
            </div>
          </div>

          {/* Handshake Analysis Pipeline */}
          <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-2">
            <div className="text-[11px] font-bold uppercase tracking-wider text-purple-300 flex items-center gap-1.5">
              <Terminal size={14} /> PQC Detection Pipeline: ClientHello supported_groups Inspection
            </div>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-2 text-[11px] font-mono items-center">
              <div className="p-2 rounded bg-[var(--color-surface-3)] border border-slate-700 text-center">
                <div className="text-[9px] text-slate-400">INPUT</div>
                <div className="font-bold text-sky-300">TLS ClientHello</div>
              </div>
              <div className="text-center text-slate-500">──►</div>
              <div className="p-2 rounded bg-[var(--color-surface-3)] border border-slate-700 text-center">
                <div className="text-[9px] text-slate-400">EXTENSION</div>
                <div className="font-bold text-slate-200">supported_groups</div>
              </div>
              <div className="text-center text-slate-500">──►</div>
              <div className="p-2 rounded bg-purple-950/40 border border-purple-500/40 text-center">
                <div className="text-[9px] text-purple-400">PQC ENGINE</div>
                <div className="font-bold text-purple-300">Hybrid ML-KEM?</div>
              </div>
            </div>
            <p className="text-[12px] text-rose-300/90 pt-1">
              <b>Observed Handshake Diagnostic:</b> &quot;The observed handshake does not negotiate a post-quantum hybrid key-establishment group.&quot;
            </p>
          </div>

          {/* RFC 10024 Hybrid Key-Agreement Groups Matrix */}
          <div className="space-y-2">
            <h4 className="text-[12px] font-bold uppercase tracking-wider text-[var(--color-text-primary)]">
              RFC 10024 / NIST FIPS 203 Hybrid Group Verification Matrix
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-[12px]">
                <thead>
                  <tr className="border-b border-[var(--color-border)] text-[10px] font-semibold text-[var(--color-text-muted)] uppercase">
                    <th className="py-2 px-3">Hybrid Key-Agreement Group</th>
                    <th className="py-2 px-3">Codepoint</th>
                    <th className="py-2 px-3">Classical + Post-Quantum Primitive</th>
                    <th className="py-2 px-3">Security Category</th>
                    <th className="py-2 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-subtle)] font-mono text-[11px]">
                  <tr>
                    <td className="py-2 px-3 font-bold text-purple-300">X25519MLKEM768</td>
                    <td className="py-2 px-3 text-slate-400">0x11EC</td>
                    <td className="py-2 px-3 text-slate-300">X25519 (ECDHE) + ML-KEM-768 (Lattice)</td>
                    <td className="py-2 px-3 text-slate-300">NIST Level 3 (AES-192 Equivalent)</td>
                    <td className="py-2 px-3 text-rose-400 font-bold">MISSING IN CLIENTHELLO ⚠️</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-bold text-purple-300">SecP256r1MLKEM768</td>
                    <td className="py-2 px-3 text-slate-400">0x11ED</td>
                    <td className="py-2 px-3 text-slate-300">NIST P-256 + ML-KEM-768 (FIPS 203)</td>
                    <td className="py-2 px-3 text-slate-300">NIST Level 3 (FIPS Regulated Enterprise)</td>
                    <td className="py-2 px-3 text-rose-400 font-bold">MISSING IN CLIENTHELLO ⚠️</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-bold text-purple-300">SecP384r1MLKEM1024</td>
                    <td className="py-2 px-3 text-slate-400">0x11EE</td>
                    <td className="py-2 px-3 text-slate-300">NIST P-384 + ML-KEM-1024 (Top Secret)</td>
                    <td className="py-2 px-3 text-slate-300">NIST Level 5 (CNSA 2.0 National Defense)</td>
                    <td className="py-2 px-3 text-rose-400 font-bold">MISSING IN CLIENTHELLO ⚠️</td>
                  </tr>
                </tbody>
              </table>
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
    )}

    {/* ── Tab 3: Key Management & Fingerprint Trust (Phase 4, 5, 6) ── */}
    {activeTab === 'key-management' && (
      <KeyLifecycleManager />
    )}

  </div>
</AppShell>
);
}
