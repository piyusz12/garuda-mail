'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheck, Lock, Mail, Users, KeyRound, CheckCircle2,
  Send, AlertCircle, ArrowUpRight, ShieldAlert, Cpu, Sparkles,
  RefreshCw, Shield, FileText, UserCheck, ExternalLink
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import Link from 'next/link';
import clsx from 'clsx';
import { getClientVaultStatus } from '@/lib/clientKeyVault';

interface UserDashboardClientProps {
  currentUser: {
    id: string;
    name?: string | null;
    email: string;
    role: string;
    status: string;
  };
}

interface RecentMessage {
  id: string;
  subject: string;
  from: string;
  date: string;
  isEncrypted: boolean;
  read: boolean;
}

const fadeUp = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] },
};

const stagger = {
  animate: { transition: { staggerChildren: 0.06 } },
};

export default function UserDashboardClient({ currentUser }: UserDashboardClientProps) {
  const [recentMessages, setRecentMessages] = useState<RecentMessage[]>([]);
  const [loadingMessages, setLoadingMessages] = useState(true);
  const [onlinePeers, setOnlinePeers] = useState<number>(0);
  const [hasLocalKey, setHasLocalKey] = useState<boolean>(false);
  const [fingerprint, setFingerprint] = useState<string>('Generating / loading local key...');

  useEffect(() => {
    // Check client-side cryptographic vault via single source of truth
    const vault = getClientVaultStatus();
    setHasLocalKey(vault.hasKey);
    setFingerprint(vault.hasKey ? vault.fingerprint : 'No local vault initialized. Visit Cryptographic Keys to generate.');

    // Fetch user's emails
    async function loadUserOverview() {
      try {
        setLoadingMessages(true);
        const res = await fetch('/api/emails?folder=inbox');
        if (res.ok) {
          const data = await res.json();
          const msgs: RecentMessage[] = (data.emails || []).slice(0, 5).map((e: any) => ({
            id: e.id,
            subject: e.subject,
            from: e.from?.name || e.from?.email || 'Unknown',
            date: e.createdAt ? new Date(e.createdAt).toLocaleDateString() : 'Today',
            isEncrypted: Boolean(e.body?.includes('<!--GARUDA-E2EE-V2-->') || e.body?.includes('<!--GARUDA-E2EE-->')),
            read: Boolean(e.read),
          }));
          setRecentMessages(msgs);
        }
      } catch (err) {
        console.error('Failed to load user overview messages:', err);
      } finally {
        setLoadingMessages(false);
      }

      // Fetch directory presence count
      try {
        const presRes = await fetch('/api/users');
        if (presRes.ok) {
          const presData = await presRes.json();
          setOnlinePeers(presData.onlineCount || 0);
        }
      } catch {}
    }

    loadUserOverview();
  }, []);

  return (
    <AppShell title="Personal Security Dashboard" description="GARUDA — Sovereign End-to-End Encrypted Workspace">
      <motion.div initial="initial" animate="animate" variants={stagger} className="space-y-6">

        {/* ── Welcome & Profile Hero Card ── */}
        <motion.div
          variants={fadeUp}
          className="card p-5 sm:p-6 rounded-2xl bg-gradient-to-r from-sky-500/[0.08] via-indigo-500/[0.05] to-purple-600/[0.08] border border-sky-500/20 relative overflow-hidden"
        >
          <div className="absolute right-0 top-0 w-80 h-80 bg-sky-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
          
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 relative z-10">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center text-white text-xl font-bold shadow-lg shadow-sky-500/25 border border-white/20">
                {(currentUser.name || currentUser.email)[0].toUpperCase()}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-white tracking-tight">
                    Welcome, {currentUser.name || 'Operative'}
                  </h2>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    {currentUser.status.toUpperCase()}
                  </span>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-sky-500/15 text-sky-300 border border-sky-500/30 uppercase">
                    {currentUser.role}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
                  <span>{currentUser.email}</span>
                  <span className="text-slate-600">•</span>
                  <span>Tactical Communications Workspace</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Link
                href="/compose"
                className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-500/20 transition-all active:scale-95"
              >
                <Send size={13} /> Compose Encrypted
              </Link>
              <Link
                href="/inbox"
                className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] text-slate-200 text-xs font-semibold border border-[var(--color-border)] transition-all"
              >
                <Mail size={13} /> Open Inbox
              </Link>
            </div>
          </div>
        </motion.div>

        {/* ── Key Metrics Grid ── */}
        <motion.div variants={stagger} className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div variants={fadeUp} className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">E2EE Protocol</span>
              <Lock size={15} className="text-sky-400" />
            </div>
            <div className="text-lg font-bold text-white tracking-tight">RSA-OAEP + AES</div>
            <p className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
              <CheckCircle2 size={11} /> 2048-bit Zero-Knowledge
            </p>
          </motion.div>

          <motion.div variants={fadeUp} className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Digital Signatures</span>
              <ShieldCheck size={15} className="text-indigo-400" />
            </div>
            <div className="text-lg font-bold text-white tracking-tight">RSA-PSS SHA-256</div>
            <p className="text-[11px] text-indigo-300 mt-1">Tamper-evident verification</p>
          </motion.div>

          <motion.div variants={fadeUp} className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Online Participants</span>
              <Users size={15} className="text-emerald-400" />
            </div>
            <div className="text-lg font-bold text-white tracking-tight">{onlinePeers} Active</div>
            <p className="text-[11px] text-slate-400 mt-1">Local network directory</p>
          </motion.div>

          <motion.div variants={fadeUp} className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Client Key Vault</span>
              <KeyRound size={15} className="text-amber-400" />
            </div>
            <div className="text-lg font-bold text-white tracking-tight">
              {hasLocalKey ? 'Secured' : 'Pending'}
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              {hasLocalKey ? 'PBKDF2 encrypted in browser' : 'No local key registered'}
            </p>
          </motion.div>
        </motion.div>

        {/* ── Two Columns: Cryptographic Identity & Recent Messages ── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* Left: Cryptographic Identity & Posture (5 cols) */}
          <motion.div variants={fadeUp} className="lg:col-span-5 space-y-4">
            <div className="card p-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--color-border-subtle)] pb-3">
                <div className="flex items-center gap-2">
                  <KeyRound size={16} className="text-sky-400" />
                  <h3 className="text-sm font-semibold text-white">Cryptographic Identity</h3>
                </div>
                <Link
                  href="/crypto"
                  className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 font-medium"
                >
                  Manage Keys <ArrowUpRight size={12} />
                </Link>
              </div>

              <div>
                <label className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block mb-1">
                  Public Key SHA-256 Fingerprint
                </label>
                <div className="p-2.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] font-mono text-[11px] text-slate-300 break-all select-all">
                  {fingerprint}
                </div>
                <p className="text-[10px] text-slate-400 mt-1.5">
                  Share this fingerprint with peer communicators out-of-band to verify end-to-end authenticity.
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-emerald-500/[0.07] border border-emerald-500/20 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                  <ShieldCheck size={14} /> Zero-Knowledge Security Guarantees
                </div>
                <ul className="text-[11px] text-slate-300 space-y-1 list-disc list-inside">
                  <li>Your private key never leaves this browser device.</li>
                  <li>The server holds only encrypted ciphertext envelopes.</li>
                  <li>Every outgoing message carries your verifiable digital signature.</li>
                </ul>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                <Link
                  href="/user/security"
                  className="p-2.5 rounded-lg bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] text-slate-200 text-center font-medium transition-colors"
                >
                  Security Audit
                </Link>
                <Link
                  href="/user/contacts"
                  className="p-2.5 rounded-lg bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] text-slate-200 text-center font-medium transition-colors"
                >
                  Verified Contacts
                </Link>
              </div>
            </div>
          </motion.div>

          {/* Right: Recent Encrypted Conversations (7 cols) */}
          <motion.div variants={fadeUp} className="lg:col-span-7">
            <div className="card p-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--color-border-subtle)] pb-3">
                <div className="flex items-center gap-2">
                  <Mail size={16} className="text-indigo-400" />
                  <h3 className="text-sm font-semibold text-white">Recent Encrypted Messages</h3>
                </div>
                <Link
                  href="/inbox"
                  className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
                >
                  View All Messages <ArrowUpRight size={12} />
                </Link>
              </div>

              {loadingMessages ? (
                <div className="py-12 text-center text-xs text-slate-500">
                  <RefreshCw size={16} className="animate-spin mx-auto mb-2 text-sky-400" />
                  Retrieving secure message ledger...
                </div>
              ) : recentMessages.length === 0 ? (
                <div className="py-10 text-center text-slate-400 space-y-2">
                  <Mail size={24} className="mx-auto text-slate-600" />
                  <p className="text-xs">No recent messages in your inbox.</p>
                  <Link
                    href="/compose"
                    className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline"
                  >
                    Start an encrypted conversation
                  </Link>
                </div>
              ) : (
                <div className="divide-y divide-[var(--color-border-subtle)]">
                  {recentMessages.map((msg) => (
                    <Link
                      key={msg.id}
                      href={`/inbox/${msg.id}`}
                      className="py-3 px-2 flex items-center justify-between hover:bg-[var(--color-surface-2)] rounded-lg transition-colors group"
                    >
                      <div className="min-w-0 pr-4">
                        <div className="flex items-center gap-2">
                          <span className={clsx('text-xs font-semibold truncate', msg.read ? 'text-slate-300' : 'text-white')}>
                            {msg.subject || '(Encrypted Subject)'}
                          </span>
                          {msg.isEncrypted && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-sky-500/15 text-sky-300 border border-sky-500/30 flex items-center gap-1 flex-shrink-0">
                              <Lock size={9} /> E2EE
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">
                          From: {msg.from}
                        </p>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <span className="text-[10px] text-slate-400 block">{msg.date}</span>
                        <span className="text-[10px] text-sky-400 opacity-0 group-hover:opacity-100 transition-opacity">
                          Read ➔
                        </span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </motion.div>

        </div>

      </motion.div>
    </AppShell>
  );
}
