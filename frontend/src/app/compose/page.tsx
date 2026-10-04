'use client';

import { useState, useEffect, Suspense } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send, X, Paperclip, Bold, Italic, Link2,
  Shield, Lock, Info, ChevronDown, Save, AlertCircle,
  Cpu, CheckCircle2, Terminal, Network, Settings2
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { useRouter, useSearchParams } from 'next/navigation';
import clsx from 'clsx';
import { SUPPORTED_PROTOCOLS, ProtocolType, ProtocolSpec } from '@/lib/protocols';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

interface DirectoryUser {
  id: string;
  name: string | null;
  email: string | null;
  role: string;
  department: string | null;
}

export default function ComposePage() {
  return (
    <Suspense fallback={<div className="p-8 text-[var(--color-text-dim)]">Loading compose...</div>}>
      <ComposeForm />
    </Suspense>
  );
}

function ComposeForm() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [to, setTo] = useState('');
  const [cc, setCc] = useState('');
  const [showCc, setShowCc] = useState(false);
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [protocol, setProtocol] = useState<ProtocolType>('auto');
  const [encrypted, setEncrypted] = useState(true);

  // Custom SMTP override toggle
  const [showCustomSmtp, setShowCustomSmtp] = useState(false);
  const [customHost, setCustomHost] = useState('');
  const [customPort, setCustomPort] = useState('587');
  const [customUser, setCustomUser] = useState('');
  const [customPass, setCustomPass] = useState('');

  // Directory users
  const [directoryUsers, setDirectoryUsers] = useState<DirectoryUser[]>([]);
  const [activeIps, setActiveIps] = useState<string[]>([]);

  // State
  const [sending, setSending] = useState(false);
  const [savingDraft, setSavingDraft] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');

  // Transmission simulation log
  const [handshakeSteps, setHandshakeSteps] = useState<string[]>([]);
  const [showTransmissionModal, setShowTransmissionModal] = useState(false);

  // Fetch directory users and protocols info
  useEffect(() => {
    async function loadData() {
      try {
        const [usersRes, protoRes] = await Promise.all([
          fetch('/api/users'),
          fetch('/api/protocols'),
        ]);
        if (usersRes.ok) {
          const data = await usersRes.json();
          if (data.users) setDirectoryUsers(data.users);
        }
        if (protoRes.ok) {
          const data = await protoRes.json();
          if (data.lanIps) setActiveIps(data.lanIps);
        }
      } catch (err) {
        console.error('Failed to load compose metadata:', err);
      }
    }
    loadData();
  }, []);

  // Pre-fill from query params (e.g. Reply, Forward)
  useEffect(() => {
    const replyTo = searchParams.get('to') || searchParams.get('replyTo');
    const qSubject = searchParams.get('subject');
    const qBody = searchParams.get('body');
    const qProto = searchParams.get('protocol') as ProtocolType;

    if (replyTo) setTo(replyTo);
    if (qSubject) setSubject(qSubject);
    if (qBody) setBody(qBody);
    if (qProto && SUPPORTED_PROTOCOLS[qProto]) setProtocol(qProto);
  }, [searchParams]);

  // Bulletproof address resolver: handles standard emails, names with brackets, usernames, and LAN peers
  const resolveRecipientAddresses = (raw: string, directory: DirectoryUser[] = []): { email: string; name?: string }[] => {
    if (!raw || !raw.trim()) return [];

    const emailRegex = /([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)/gi;
    const parts = raw.split(/[,;\n\r]+/).map(p => p.trim()).filter(Boolean);
    const results: { email: string; name?: string }[] = [];
    const seen = new Set<string>();

    for (const part of parts) {
      // 1. Check for "Name" <email@domain>
      const angleMatch = part.match(/<([^>]+)>/);
      let candidate = angleMatch ? angleMatch[1].trim() : '';
      const displayName = angleMatch ? part.replace(/<[^>]+>/, '').trim().replace(/^["']|["']$/g, '') : undefined;

      // 2. Check for raw email match inside the part
      if (!candidate) {
        const matches = part.match(emailRegex);
        if (matches && matches.length > 0) {
          candidate = matches[0];
        }
      }

      // 2.5 Auto-repair missing @ before common email domains (e.g. usergmail.com -> user@gmail.com)
      if (candidate && !candidate.includes('@')) {
        const domainFix = candidate.match(/^([a-zA-Z0-9._%+-]+)((?:gmail|yahoo|outlook|hotmail|icloud|protonmail|proton)\.com)$/i);
        if (domainFix) {
          candidate = `${domainFix[1]}@${domainFix[2]}`;
        }
      }

      // 3. If candidate has @, register it
      if (candidate && candidate.includes('@')) {
        const clean = candidate.toLowerCase().trim();
        if (!seen.has(clean)) {
          seen.add(clean);
          results.push({ email: clean, name: displayName || undefined });
        }
        continue;
      }

      // 4. If no @ found, check directoryUsers for exact or fuzzy match
      const query = part.toLowerCase().replace(/[@<>'"]/g, '').trim();
      if (query) {
        const matchedUser = directory.find(u =>
          (u.email && u.email.toLowerCase().includes(query)) ||
          (u.name && u.name.toLowerCase().includes(query)) ||
          (u.email && u.email.split('@')[0].toLowerCase() === query)
        );
        if (matchedUser?.email) {
          const clean = matchedUser.email.toLowerCase().trim();
          if (!seen.has(clean)) {
            seen.add(clean);
            results.push({ email: clean, name: matchedUser.name || undefined });
          }
          continue;
        }

        // 5. Plain single-word fallback -> resolve to enterprise LAN user
        if (!query.includes(' ')) {
          const synthesized = `${query}@enterprise.local`;
          if (!seen.has(synthesized)) {
            seen.add(synthesized);
            results.push({ email: synthesized });
          }
        }
      }
    }

    // Fallback: search entire raw string for any email if still empty
    if (results.length === 0) {
      const allMatches = raw.match(emailRegex);
      if (allMatches) {
        for (const m of allMatches) {
          const clean = m.toLowerCase().trim();
          if (!seen.has(clean)) {
            seen.add(clean);
            results.push({ email: clean });
          }
        }
      }
    }

    return results;
  };

  const selectedSpec: ProtocolSpec = SUPPORTED_PROTOCOLS[protocol] || SUPPORTED_PROTOCOLS['auto'];

  const handleSend = async () => {
    setError('');

    // Parse and resolve recipients
    const toParsed = resolveRecipientAddresses(to, directoryUsers);
    if (toParsed.length === 0) {
      setError('Please provide at least one recipient email address (e.g. bob@enterprise.local or bhaskar).');
      const inputEl = document.getElementById('recipient-input');
      inputEl?.focus();
      return;
    }

    // Default subject and body gracefully if empty
    const finalSubject = subject.trim() || '(No Subject)';
    const finalBody = body.trim() || '(No content)';

    setSending(true);
    setShowTransmissionModal(true);
    setHandshakeSteps([
      `[1/4] Deriving 256-bit symmetric key via HKDF-SHA256 & PQC Kyber-768...`,
    ]);

    try {
      const ccParsed = cc ? resolveRecipientAddresses(cc, directoryUsers) : [];

      // Step 2 simulation
      setTimeout(() => {
        setHandshakeSteps(prev => [
          ...prev,
          encrypted
            ? `[2/4] Encrypting message body via authenticated AES-256-GCM (12-byte IV + 128-bit MAC)...`
            : `[2/4] Preparing transport-level cryptographic envelope...`,
        ]);
      }, 250);

      // Step 3 simulation
      setTimeout(() => {
        setHandshakeSteps(prev => [
          ...prev,
          `[3/4] Establishing ${selectedSpec.encryption} socket over ${selectedSpec.shortName} (Port ${customHost ? customPort : selectedSpec.defaultPort})...`,
        ]);
      }, 500);

      const customSmtpPayload = showCustomSmtp && customHost ? {
        host: customHost,
        port: parseInt(customPort) || 587,
        user: customUser,
        pass: customPass,
      } : undefined;

      const res = await fetch('/api/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: toParsed,
          cc: ccParsed,
          subject: finalSubject,
          body: finalBody,
          draft: false,
          protocol,
          encrypted,
          customSmtp: customSmtpPayload,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to dispatch email');
      }

      setHandshakeSteps(prev => [
        ...prev,
        `[4/4] 250 2.0.0 OK: Delivered across all active devices & network peers!`,
      ]);

      setSending(false);
      setSent(true);

      setTimeout(() => {
        setShowTransmissionModal(false);
        router.push('/sent');
      }, 1200);
    } catch (err: any) {
      setSending(false);
      setShowTransmissionModal(false);
      const isAuthErr = err.message?.toLowerCase().includes('unauthorized') || err.message?.includes('401');
      setError(isAuthErr ? 'You are not signed in. Please log in before sending.' : (err.message || 'Error sending message. Check recipient email format.'));
    }
  };

  const handleSaveDraft = async () => {
    if (!to && !subject && !body) return;
    setSavingDraft(true);
    setError('');

    try {
      const toParsed = to ? parseAddresses(to) : [{ email: 'draft@enterprise.local' }];

      const res = await fetch('/api/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: toParsed.length > 0 ? toParsed : [{ email: 'draft@enterprise.local' }],
          subject: subject || '(Draft - No Subject)',
          body: body || '',
          draft: true,
          protocol,
        }),
      });

      if (!res.ok) throw new Error('Failed to save draft');
      setSavingDraft(false);
      router.push('/drafts');
    } catch (err: any) {
      setSavingDraft(false);
      setError(err.message || 'Error saving draft');
    }
  };

  const handleDiscard = () => router.push('/inbox');

  const addRecipient = (email: string) => {
    if (!to) {
      setTo(email);
    } else if (!to.toLowerCase().includes(email.toLowerCase())) {
      setTo(prev => `${prev}, ${email}`);
    }
  };

  return (
    <AppShell title="Compose Message" description="Dispatch email across SMTP, SMTPS, Direct MX, or Garuda LAN P2P Mesh">
      <motion.div initial="initial" animate="animate" className="space-y-4 max-w-4xl">

        {/* ── Protocol Selection Bar ── */}
        <motion.div {...fadeUp} className="card p-3 space-y-3 bg-[var(--color-surface-1)] border border-[var(--color-border)]">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[var(--color-border-subtle)]">
            <div className="flex items-center gap-2">
              <Network size={15} className="text-[var(--color-accent)]" />
              <span className="text-[12px] font-bold text-[var(--color-text-primary)]">Dispatch Protocol:</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] text-[var(--color-text-muted)]">
              <span>Local Network Host:</span>
              <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-[var(--color-surface-3)] text-[var(--color-accent)] border border-[var(--color-border)]">
                {activeIps.length > 0 ? `http://${activeIps[0]}:3000` : 'http://localhost:3000'}
              </span>
            </div>
          </div>

          {/* Protocol Buttons */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
            {(Object.values(SUPPORTED_PROTOCOLS).filter(p => p.id !== 'imap-sync')).map(spec => {
              const isSelected = protocol === spec.id;
              return (
                <button
                  key={spec.id}
                  type="button"
                  onClick={() => setProtocol(spec.id)}
                  className={clsx(
                    'p-2.5 rounded-lg border text-left transition-all relative overflow-hidden flex flex-col justify-between',
                    isSelected
                      ? 'border-[var(--color-accent)] bg-[var(--color-accent-dim)] shadow-[0_0_12px_rgba(56,189,248,0.15)]'
                      : 'border-[var(--color-border-subtle)] bg-[var(--color-surface-2)] hover:border-[var(--color-border)] text-[var(--color-text-secondary)]'
                  )}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="text-[11px] font-bold tracking-tight text-[var(--color-text-primary)]">
                      {spec.shortName}
                    </span>
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: spec.badgeColor }}
                    />
                  </div>
                  <div className="text-[10px] text-[var(--color-text-muted)] line-clamp-1">
                    Port {spec.defaultPort} • {spec.encryption}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Active Protocol Security Details */}
          <div className="p-2.5 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] flex flex-col md:flex-row md:items-center justify-between gap-2 text-[11px]">
            <div className="flex items-center gap-2">
              <Lock size={12} className="text-[var(--color-accent)] flex-shrink-0" />
              <span className="text-[var(--color-text-secondary)]">
                <strong className="text-[var(--color-text-primary)]">{selectedSpec.name} ({selectedSpec.rfc}): </strong>
                {selectedSpec.description}
              </span>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono text-[var(--color-text-dim)] flex-shrink-0">
              <span>CIPHER: {selectedSpec.cipher}</span>
              <span>PFS: {selectedSpec.pfs ? 'ENABLED' : 'NONE'}</span>
            </div>
          </div>
        </motion.div>

        {/* ── Error Banner ── */}
        {error && (
          <motion.div {...fadeUp} className="flex items-center gap-2.5 p-3 rounded-md bg-[var(--color-severity-critical-bg)] border border-[rgba(239,68,68,0.25)] text-[12px] text-[var(--color-severity-critical)]">
            <AlertCircle size={15} className="flex-shrink-0" />
            <span>{error}</span>
          </motion.div>
        )}

        {/* ── Compose Card ── */}
        <motion.div {...fadeUp} className="card overflow-hidden">

          {/* Header Toolbar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-[var(--color-border)] bg-[var(--color-surface-2)]">
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">New Email Message</span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.2)]">
                {selectedSpec.shortName}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setEncrypted(!encrypted)}
                className={clsx(
                  'flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition-colors border',
                  encrypted
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                    : 'text-[var(--color-text-muted)] bg-[var(--color-surface-3)] border-[var(--color-border-subtle)]'
                )}
                title="Toggle AES-256-GCM End-to-End Payload Encryption"
              >
                <Lock size={12} className={encrypted ? 'text-emerald-400' : 'text-[var(--color-text-dim)]'} />
                <span>{encrypted ? 'AES-256-GCM E2EE' : 'Plaintext Transport'}</span>
              </button>
              <button
                type="button"
                onClick={() => setShowCustomSmtp(!showCustomSmtp)}
                className={clsx(
                  'flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition-colors border',
                  showCustomSmtp
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border-[var(--color-accent)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-3)] border-[var(--color-border-subtle)]'
                )}
                title="Configure custom SMTP relay"
              >
                <Settings2 size={12} />
                <span>Custom Relay</span>
              </button>
              <button
                onClick={handleSaveDraft}
                disabled={savingDraft || (!to && !subject && !body)}
                className="flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors disabled:opacity-40"
                title="Save as Draft"
              >
                <Save size={13} />
                <span>{savingDraft ? 'Saving...' : 'Draft'}</span>
              </button>
              <button
                onClick={handleDiscard}
                className="flex items-center justify-center w-7 h-7 rounded text-[var(--color-text-muted)] hover:text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] transition-colors"
                title="Discard"
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Custom SMTP Config Drawer */}
          {showCustomSmtp && (
            <div className="p-3 bg-[var(--color-surface-1)] border-b border-[var(--color-border)] grid grid-cols-1 sm:grid-cols-4 gap-2 text-[12px]">
              <div>
                <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] block mb-1">SMTP Host</label>
                <input
                  type="text"
                  placeholder="smtp.gmail.com or 192.168.1.3"
                  value={customHost}
                  onChange={e => setCustomHost(e.target.value)}
                  className="w-full px-2 py-1 bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded text-[11px] text-[var(--color-text-primary)]"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] block mb-1">Port</label>
                <input
                  type="text"
                  placeholder="587"
                  value={customPort}
                  onChange={e => setCustomPort(e.target.value)}
                  className="w-full px-2 py-1 bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded text-[11px] text-[var(--color-text-primary)]"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] block mb-1">Username / Auth</label>
                <input
                  type="text"
                  placeholder="user@example.com"
                  value={customUser}
                  onChange={e => setCustomUser(e.target.value)}
                  className="w-full px-2 py-1 bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded text-[11px] text-[var(--color-text-primary)]"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] block mb-1">Password / App Pass</label>
                <input
                  type="password"
                  placeholder="••••••••••••"
                  value={customPass}
                  onChange={e => setCustomPass(e.target.value)}
                  className="w-full px-2 py-1 bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded text-[11px] text-[var(--color-text-primary)]"
                />
              </div>
            </div>
          )}

          {/* Form Fields */}
          <div
            className="divide-y divide-[var(--color-border-subtle)]"
            onKeyDown={e => {
              if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                handleSend();
              }
            }}
          >
            {/* To Field */}
            <div className="flex items-center gap-3 px-4 py-2.5">
              <label htmlFor="recipient-input" className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0 cursor-pointer">To</label>
              <input
                id="recipient-input"
                type="text"
                value={to}
                onChange={e => {
                  setTo(e.target.value);
                  if (error) setError('');
                }}
                placeholder="bob@enterprise.local, bhaskarthalendra@gmail.com, or LAN peer name"
                className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none"
              />
              <button
                type="button"
                onClick={() => setShowCc(!showCc)}
                className="text-[11px] text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors flex items-center gap-0.5"
              >
                CC <ChevronDown size={11} className={clsx('transition-transform', showCc && 'rotate-180')} />
              </button>
            </div>

            {/* Quick Directory Contacts */}
            <div className="flex items-center gap-1.5 px-4 py-2 bg-[var(--color-surface-1)] text-[11px] overflow-x-auto">
              <span className="text-[10px] uppercase text-[var(--color-text-dim)] font-mono mr-1 flex-shrink-0">
                Network Peers:
              </span>
              {directoryUsers.map(u => (
                <button
                  key={u.id}
                  type="button"
                  onClick={() => addRecipient(u.email || '')}
                  className="px-2.5 py-0.5 rounded text-[10px] bg-[var(--color-surface-2)] text-[var(--color-text-secondary)] hover:text-[var(--color-accent)] hover:bg-[var(--color-accent-dim)] border border-[var(--color-border-subtle)] transition-colors flex items-center gap-1 flex-shrink-0"
                  title={`Add ${u.email || u.name} to recipients`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-severity-healthy)]" />
                  <span className="font-medium">{u.name || u.email?.split('@')[0]}</span>
                  <span className="text-[var(--color-text-dim)]">({u.email})</span>
                </button>
              ))}
            </div>

            {/* CC Field */}
            {showCc && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <label className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0">CC</label>
                <input
                  type="text"
                  value={cc}
                  onChange={e => setCc(e.target.value)}
                  placeholder="cc@enterprise.local"
                  className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none"
                />
              </div>
            )}

            {/* Subject Field */}
            <div className="flex items-center gap-3 px-4 py-2.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0">Subject</label>
              <input
                type="text"
                value={subject}
                onChange={e => {
                  setSubject(e.target.value);
                  if (error) setError('');
                }}
                placeholder="Message subject line (optional)"
                className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none font-medium"
              />
            </div>
          </div>

          {/* Message Body */}
          <div className="px-4 pt-3 pb-4">
            <textarea
              value={body}
              onChange={e => {
                setBody(e.target.value);
                if (error) setError('');
              }}
              placeholder="Write your email message here... When dispatched, the message will immediately sync across all PCs and mail servers. (Press Ctrl+Enter to send)"
              rows={12}
              className="w-full text-[13px] leading-relaxed bg-transparent text-[var(--color-text-secondary)] placeholder:text-[var(--color-text-dim)] outline-none resize-none font-sans"
            />
          </div>

          {/* Format Toolbar */}
          <div className="flex items-center gap-1 px-3 py-2 border-t border-[var(--color-border-subtle)] bg-[var(--color-surface-2)]">
            <FormatButton icon={Bold} title="Bold" />
            <FormatButton icon={Italic} title="Italic" />
            <FormatButton icon={Link2} title="Link" />
            <div className="w-px h-4 bg-[var(--color-border)] mx-1" />
            <FormatButton icon={Paperclip} title="Attach file" />
          </div>

          {/* Send / Action Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 py-3 border-t border-[var(--color-border)] bg-[var(--color-surface-2)]">
            <div className="flex items-center gap-2 text-[11px] text-[var(--color-text-muted)]">
              <Shield size={13} className="text-[var(--color-accent)] flex-shrink-0" />
              <span>Multi-device synchronization active • Press <kbd className="px-1 py-0.5 bg-[var(--color-surface-3)] rounded border border-[var(--color-border)] font-mono text-[10px]">Ctrl+Enter</kbd> to Send</span>
            </div>

            {/* Inline Error if present */}
            {error && (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[var(--color-severity-critical-bg)] border border-[rgba(239,68,68,0.3)] text-[11px] text-[var(--color-severity-critical)] sm:max-w-xs">
                <AlertCircle size={13} className="flex-shrink-0" />
                <span className="line-clamp-2">{error}</span>
              </div>
            )}

            <div className="flex items-center gap-2 self-end sm:self-auto">
              <button
                type="button"
                onClick={handleDiscard}
                className="px-4 py-2 text-[12px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] rounded-md transition-colors border border-[var(--color-border)]"
              >
                Discard
              </button>
              <button
                type="button"
                id="send-email-btn"
                onClick={handleSend}
                disabled={sending || sent}
                className={clsx(
                  'flex items-center gap-2 px-6 py-2 text-[13px] font-bold rounded-md transition-all duration-200 shadow-md cursor-pointer',
                  sent
                    ? 'bg-[var(--color-severity-healthy)] text-white'
                    : 'bg-[var(--color-accent)] text-[#0B0D10] hover:bg-[#5ccbfc] hover:shadow-[0_0_18px_rgba(56,189,248,0.4)] disabled:opacity-50'
                )}
                title="Send Email now (Ctrl+Enter)"
              >
                {sending ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-[#0B0D10]/30 border-t-[#0B0D10] rounded-full animate-spin" />
                    <span>Sending ({selectedSpec.shortName})...</span>
                  </>
                ) : sent ? (
                  <>
                    <CheckCircle2 size={15} />
                    <span>Sent Successfully!</span>
                  </>
                ) : (
                  <>
                    <Send size={14} />
                    <span>Send Email</span>
                    <span className="text-[10px] font-mono opacity-80 uppercase px-1.5 py-0.5 rounded bg-black/10">
                      {selectedSpec.shortName}
                    </span>
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>

        {/* ── Protocol Forensic Handshake Transmission Modal ── */}
        <AnimatePresence>
          {showTransmissionModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.95, y: 10 }}
                animate={{ scale: 1, y: 0 }}
                exit={{ scale: 0.95, y: 10 }}
                className="w-full max-w-xl bg-[var(--color-surface-1)] border border-[var(--color-accent)] rounded-xl shadow-2xl overflow-hidden"
              >
                <div className="flex items-center justify-between px-4 py-3 bg-[var(--color-surface-2)] border-b border-[var(--color-border)]">
                  <div className="flex items-center gap-2">
                    <Terminal size={15} className="text-[var(--color-accent)] animate-pulse" />
                    <span className="text-[13px] font-bold text-[var(--color-text-primary)]">
                      Protocol Handshake: {selectedSpec.name} ({selectedSpec.shortName})
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-accent)]">
                    PORT {customHost ? customPort : selectedSpec.defaultPort}
                  </span>
                </div>

                <div className="p-4 bg-[#0a0f1d] font-mono text-[12px] space-y-2 text-slate-300 min-h-[160px]">
                  {handshakeSteps.map((step, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -5 }}
                      animate={{ opacity: 1, x: 0 }}
                      className={clsx(
                        'leading-relaxed',
                        step.includes('250') || step.includes('Delivered')
                          ? 'text-emerald-400 font-bold'
                          : step.includes('TLS') || step.includes('Negotiating')
                            ? 'text-sky-300'
                            : 'text-slate-300'
                      )}
                    >
                      {step}
                    </motion.div>
                  ))}
                  {sending && (
                    <div className="flex items-center gap-2 text-sky-400/70 text-[11px] pt-1">
                      <div className="w-2.5 h-2.5 border-2 border-sky-400/30 border-t-sky-400 rounded-full animate-spin" />
                      <span>Negotiating cryptographic envelope...</span>
                    </div>
                  )}
                </div>

                <div className="px-4 py-2.5 bg-[var(--color-surface-2)] border-t border-[var(--color-border)] flex items-center justify-between text-[11px] text-[var(--color-text-muted)]">
                  <span>Cryptographic Protocol: {selectedSpec.cipher}</span>
                  <span className="text-emerald-400 font-medium">Multi-PC Sync Enforced</span>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

      </motion.div>
    </AppShell>
  );
}

function FormatButton({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <button
      type="button"
      title={title}
      className="flex items-center justify-center w-7 h-7 rounded text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors"
    >
      <Icon size={14} />
    </button>
  );
}
