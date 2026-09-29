'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Award, Shield, AlertTriangle, CheckCircle, XCircle, Search,
  ExternalLink, Calendar, Key, Link as LinkIcon, X, Copy,
  Check, ChevronRight, Layers, FileCheck
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { StatusBadge } from '@/components/ui/shared';
import { mockCertificates, mockSessions } from '@/lib/mock/data';
import { formatDate } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import type { CertificateRecord } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function CertificatesPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'valid' | 'expiring' | 'expired'>('all');
  const [selectedCert, setSelectedCert] = useState<CertificateRecord | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const filteredCerts = mockCertificates.filter((cert) => {
    const matchesSearch =
      cert.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cert.issuer.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cert.subjectAltNames.some(san => san.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesStatus = statusFilter === 'all' || cert.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 1500);
  };

  const validCount = mockCertificates.filter(c => c.status === 'valid').length;
  const expiringCount = mockCertificates.filter(c => c.status === 'expiring').length;
  const expiredCount = mockCertificates.filter(c => c.status === 'expired').length;

  return (
    <AppShell
      title="Certificate Inventory"
      description="Cryptographic inspection of X.509 public key certificates, trust paths, and expiration countdowns"
    >
      <div className="space-y-6">

        {/* ── Top Summary Metrics ── */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Total Certificates</span>
              <Award size={16} className="text-[var(--color-accent)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-text-primary)] tabular-nums">
              {mockCertificates.length}
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">Observed across all TLS handshakes</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Valid & Trusted</span>
              <CheckCircle size={16} className="text-[var(--color-severity-healthy)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-healthy)] tabular-nums">
              {validCount}
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">Valid signature and verified trust root</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Expiring Soon (&lt;30d)</span>
              <AlertTriangle size={16} className="text-[var(--color-severity-high)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-high)] tabular-nums">
              {expiringCount}
            </div>
            <p className="text-[11px] text-[var(--color-severity-high)] font-medium">mail.example.com expires in 18d</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Expired / Weak</span>
              <XCircle size={16} className="text-[var(--color-severity-critical)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-critical)] tabular-nums">
              {expiredCount}
            </div>
            <p className="text-[11px] text-[var(--color-severity-critical)] font-medium">pop3.legacy-mail.internal (expired)</p>
          </div>
        </div>

        {/* ── Search & Filter Controls ── */}
        <div className="card p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-80">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
            <input
              type="text"
              placeholder="Search by subject, issuer, SAN..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] placeholder-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
            />
          </div>

          <div className="flex items-center gap-1.5 bg-[var(--color-surface-2)] p-1 rounded-lg border border-[var(--color-border)] w-full sm:w-auto">
            {(['all', 'valid', 'expiring', 'expired'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={clsx(
                  'flex-1 sm:flex-none px-3 py-1 text-[11px] font-medium rounded-md capitalize transition-colors',
                  statusFilter === status
                    ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                )}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {/* ── Certificate Inventory Table ── */}
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                  <th className="py-3 px-4">Subject (Common Name)</th>
                  <th className="py-3 px-4">Issuer CA</th>
                  <th className="py-3 px-4">Key Spec</th>
                  <th className="py-3 px-4">Signature</th>
                  <th className="py-3 px-4">Validity</th>
                  <th className="py-3 px-4">Remaining</th>
                  <th className="py-3 px-4">Chain Status</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {filteredCerts.map((cert) => (
                  <tr
                    key={cert.id}
                    onClick={() => setSelectedCert(cert)}
                    className="hover:bg-[var(--color-surface-2)] transition-colors cursor-pointer"
                  >
                    <td className="py-3.5 px-4 font-semibold text-[var(--color-text-primary)]">
                      <div className="flex items-center gap-2">
                        <Award size={15} className="text-[var(--color-accent)] flex-shrink-0" />
                        <div>
                          <div>{cert.subject}</div>
                          <div className="text-[10px] text-[var(--color-text-dim)] font-normal">
                            SANs: {cert.subjectAltNames.join(', ')}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-[var(--color-text-secondary)] text-[12px]">
                      {cert.issuer}
                    </td>
                    <td className="py-3.5 px-4 text-mono">
                      <span className={clsx(
                        'px-1.5 py-0.5 rounded text-[11px]',
                        cert.keySize < 2048 && cert.keyType === 'RSA'
                          ? 'bg-[rgba(239,68,68,0.15)] text-[var(--color-severity-critical)] font-bold'
                          : 'bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]'
                      )}>
                        {cert.keyType} {cert.keySize}-bit
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-mono text-[11px] text-[var(--color-text-dim)]">
                      <span className={clsx(cert.algorithm.includes('SHA1') && 'text-[var(--color-severity-critical)] font-bold')}>
                        {cert.algorithm}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-[11px] text-[var(--color-text-dim)] text-mono">
                      {formatDate(cert.validFrom)} → {formatDate(cert.validUntil)}
                    </td>
                    <td className="py-3.5 px-4">
                      {cert.daysRemaining < 0 ? (
                        <span className="badge-critical text-[10px] px-1.5 py-0.5 rounded font-bold">
                          Expired {Math.abs(cert.daysRemaining)}d ago
                        </span>
                      ) : cert.daysRemaining <= 30 ? (
                        <span className="badge-high text-[10px] px-1.5 py-0.5 rounded font-bold animate-pulse">
                          {cert.daysRemaining} days left
                        </span>
                      ) : (
                        <span className="badge-healthy text-[10px] px-1.5 py-0.5 rounded font-semibold">
                          {cert.daysRemaining} days left
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      {cert.chainValid ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-[var(--color-severity-healthy)] font-medium">
                          <CheckCircle size={13} /> {cert.chainLength}-tier Valid
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-[var(--color-severity-critical)] font-bold">
                          <XCircle size={13} /> Broken / Untrusted
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCert(cert);
                        }}
                        className="btn btn-ghost text-[11px] py-1 px-2 text-[var(--color-accent)]"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Detailed X.509 Certificate Inspector Modal ── */}
        <AnimatePresence>
          {selectedCert && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
              <motion.div
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.96 }}
                className="card w-full max-w-2xl bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden max-h-[90vh] flex flex-col"
              >
                {/* Modal Header */}
                <div className="p-5 border-b border-[var(--color-border)] flex items-center justify-between bg-[var(--color-surface-2)]">
                  <div className="flex items-center gap-2.5">
                    <Award size={18} className="text-[var(--color-accent)]" />
                    <div>
                      <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                        X.509 Certificate Inspector
                      </h3>
                      <p className="text-[11px] text-mono text-[var(--color-text-dim)]">
                        {selectedCert.id} • {selectedCert.subject}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedCert(null)}
                    className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-white hover:bg-[var(--color-surface-3)] transition-colors"
                  >
                    <X size={18} />
                  </button>
                </div>

                {/* Modal Scroll Content */}
                <div className="p-6 overflow-y-auto space-y-5 text-[12px]">
                  
                  {/* Status Banner */}
                  <div className={clsx(
                    'p-3.5 rounded-lg border flex items-center justify-between',
                    selectedCert.status === 'expired' && 'border-[rgba(239,68,68,0.4)] bg-[rgba(239,68,68,0.06)]',
                    selectedCert.status === 'expiring' && 'border-[rgba(234,179,8,0.4)] bg-[rgba(234,179,8,0.06)]',
                    selectedCert.status === 'valid' && 'border-[rgba(34,197,94,0.4)] bg-[rgba(34,197,94,0.06)]'
                  )}>
                    <div className="flex items-center gap-2">
                      {selectedCert.status === 'valid' ? (
                        <CheckCircle size={18} className="text-[var(--color-severity-healthy)]" />
                      ) : (
                        <AlertTriangle size={18} className="text-[var(--color-severity-critical)]" />
                      )}
                      <div>
                        <div className="font-bold text-[var(--color-text-primary)]">
                          Certificate Status: {selectedCert.status.toUpperCase()}
                        </div>
                        <div className="text-[11px] text-[var(--color-text-dim)]">
                          {selectedCert.daysRemaining < 0
                            ? `Certificate expired ${Math.abs(selectedCert.daysRemaining)} days ago. Connections will fail strict TLS checks.`
                            : `Expires on ${formatDate(selectedCert.validUntil)} (${selectedCert.daysRemaining} days remaining)`}
                        </div>
                      </div>
                    </div>
                    <StatusBadge status={selectedCert.status} />
                  </div>

                  {/* Subject & Issuer Details */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--color-text-dim)]">
                        Subject Distinguished Name
                      </div>
                      <div className="font-semibold text-[var(--color-text-primary)] text-[13px]">
                        {selectedCert.subject}
                      </div>
                      <div className="pt-2 border-t border-[var(--color-border-subtle)]">
                        <div className="text-[10px] text-[var(--color-text-dim)] mb-1">Alternative Names (SAN):</div>
                        <div className="flex flex-wrap gap-1">
                          {selectedCert.subjectAltNames.map(san => (
                            <span key={san} className="text-[10px] text-mono bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded text-[var(--color-text-secondary)]">
                              {san}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--color-text-dim)]">
                        Issuing Authority (CA)
                      </div>
                      <div className="font-semibold text-[var(--color-text-primary)] text-[13px]">
                        {selectedCert.issuer}
                      </div>
                      <div className="pt-2 border-t border-[var(--color-border-subtle)] space-y-1">
                        <div className="text-[10px] text-[var(--color-text-dim)]">Chain Verification:</div>
                        <div className="text-[11px] font-medium text-[var(--color-text-secondary)]">
                          {selectedCert.chainValid ? '✓ Valid Root Trust Anchor' : '✗ Untrusted Root or Broken Chain'}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic Parameters */}
                  <div className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-3">
                    <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center justify-between">
                      <span>Public Key & Cryptographic Specifications</span>
                      <Key size={14} className="text-[var(--color-accent)]" />
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-mono">
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)]">Algorithm</div>
                        <div className="font-semibold text-[var(--color-text-primary)]">{selectedCert.keyType}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)]">Key Length</div>
                        <div className={clsx(
                          'font-semibold',
                          selectedCert.keySize < 2048 ? 'text-[var(--color-severity-critical)]' : 'text-[var(--color-text-primary)]'
                        )}>
                          {selectedCert.keySize} bits
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)]">Signature Hash</div>
                        <div className={clsx(
                          'font-semibold',
                          selectedCert.algorithm.includes('SHA1') ? 'text-[var(--color-severity-critical)]' : 'text-[var(--color-text-primary)]'
                        )}>
                          {selectedCert.algorithm}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)]">Chain Depth</div>
                        <div className="font-semibold text-[var(--color-text-primary)]">{selectedCert.chainLength} levels</div>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-[var(--color-border-subtle)] flex items-center justify-between">
                      <div>
                        <span className="text-[10px] text-[var(--color-text-dim)]">Serial Number: </span>
                        <span className="text-mono text-[11px] text-[var(--color-text-secondary)]">{selectedCert.serialNumber}</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(selectedCert.serialNumber, 'serial')}
                        className="text-[10px] text-[var(--color-accent)] hover:underline flex items-center gap-1"
                      >
                        {copiedField === 'serial' ? <Check size={12} /> : <Copy size={12} />} Copy Serial
                      </button>
                    </div>
                  </div>

                  {/* Associated Sessions */}
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center justify-between">
                      <span>Associated Email Sessions</span>
                      <LinkIcon size={12} />
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {selectedCert.relatedSessionIds.map(sid => (
                        <Link
                          key={sid}
                          href={`/sessions/${sid}`}
                          className="px-2.5 py-1 rounded bg-[var(--color-surface-3)] border border-[var(--color-border)] text-mono text-[11px] text-[var(--color-accent)] hover:border-[var(--color-accent)] transition-colors flex items-center gap-1"
                        >
                          {sid} <ChevronRight size={12} />
                        </Link>
                      ))}
                    </div>
                  </div>

                </div>

                {/* Modal Footer */}
                <div className="p-4 border-t border-[var(--color-border)] bg-[var(--color-surface-2)] flex items-center justify-end">
                  <button
                    onClick={() => setSelectedCert(null)}
                    className="btn btn-secondary text-[12px] py-1.5 px-4"
                  >
                    Close Inspector
                  </button>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>

      </div>
    </AppShell>
  );
}
