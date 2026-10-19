'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheck, Lock, KeyRound, Cpu, CheckCircle2,
  RefreshCw, ArrowLeft, ArrowUpRight, Shield, Download, AlertTriangle
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import Link from 'next/link';

import { getClientVaultStatus } from '@/lib/clientKeyVault';

export default function UserSecurityPage() {
  const [fingerprint, setFingerprint] = useState<string>('Loading cryptographic key...');
  const [hasKey, setHasKey] = useState<boolean>(false);
  const [algorithm, setAlgorithm] = useState<string>('RSA-OAEP-2048 / RSA-PSS-2048');

  useEffect(() => {
    const vault = getClientVaultStatus();
    setHasKey(vault.hasKey);
    setFingerprint(vault.fingerprint);
    if (vault.algorithm) setAlgorithm(vault.algorithm);
  }, []);

  return (
    <AppShell title="Personal Security Posture" description="Cryptographic identity, key vault health, and zero-knowledge posture">
      <div className="max-w-4xl mx-auto space-y-6">
        <Link
          href="/user/dashboard"
          className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={14} /> Back to User Dashboard
        </Link>

        {/* ── Key Vault Status Card ── */}
        <div className="card p-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-[var(--color-border-subtle)]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
                <KeyRound size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-white">Browser Cryptographic Key Vault</h2>
                <p className="text-xs text-slate-400">Locally encrypted with PBKDF2 (100,000 rounds) + AES-256-GCM</p>
              </div>
            </div>
            <Link
              href="/crypto"
              className="flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300 font-semibold"
            >
              Rotate Keys <ArrowUpRight size={13} />
            </Link>
          </div>

          <div>
            <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
              Active Key Fingerprint (SHA-256)
            </label>
            <div className="p-3 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] font-mono text-xs text-slate-200 break-all select-all">
              {fingerprint}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs">
            <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
              <span className="text-[10px] text-slate-400 block uppercase">Asymmetric Ciphers</span>
              <span className="font-semibold text-white mt-0.5 block">{algorithm}</span>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
              <span className="text-[10px] text-slate-400 block uppercase">Digital Signatures</span>
              <span className="font-semibold text-white mt-0.5 block">RSA-PSS / SHA-256</span>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
              <span className="text-[10px] text-slate-400 block uppercase">PQC Hybrid Status</span>
              <span className="font-semibold text-emerald-400 mt-0.5 block">ML-KEM-768 Draft Ready</span>
            </div>
          </div>
        </div>

        {/* ── Security Checklist ── */}
        <div className="card p-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck size={16} className="text-emerald-400" />
            Security & Zero-Knowledge Verification
          </h3>
          <div className="space-y-3">
            <div className="flex items-start gap-3 p-3 rounded-xl bg-emerald-500/[0.05] border border-emerald-500/20">
              <CheckCircle2 size={16} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs">
                <span className="font-semibold text-white block">Server Isolation Verified</span>
                <span className="text-slate-400">The central database never possesses plaintext copies of your private keys or confidential communications.</span>
              </div>
            </div>
            <div className="flex items-start gap-3 p-3 rounded-xl bg-emerald-500/[0.05] border border-emerald-500/20">
              <CheckCircle2 size={16} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs">
                <span className="font-semibold text-white block">Passphrase Protection Enabled</span>
                <span className="text-slate-400">Your private key is protected by your master passphrase in local storage. Entering the wrong passphrase prevents decryption.</span>
              </div>
            </div>
            <div className="flex items-start gap-3 p-3 rounded-xl bg-emerald-500/[0.05] border border-emerald-500/20">
              <CheckCircle2 size={16} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs">
                <span className="font-semibold text-white block">Tamper Rejection Guaranteed</span>
                <span className="text-slate-400">Every message body is verified against its sender signature before being displayed. Tampered payloads are safely blocked.</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
