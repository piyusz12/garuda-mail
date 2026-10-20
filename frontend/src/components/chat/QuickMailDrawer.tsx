'use client';

import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send, X, Search, Users, CheckCheck, Lock, Shield, Zap,
  ChevronLeft, Sparkles, AlertCircle, ArrowUpRight, MessageSquare,
  CheckCircle2, Loader2, RefreshCw
} from 'lucide-react';
import clsx from 'clsx';
import { useSession } from 'next-auth/react';
import type { UserPresence } from '@/lib/presence';
import { saveDispatchedEmailToStorage } from '@/lib/clientEmailStore';

export interface QuickMailDrawerProps {
  initialContact?: UserPresence | null;
  onClose?: () => void;
}

const QUICK_TEMPLATES = [
  { label: '⚡ Rapid Ping', subject: 'Garuda Mesh Network Ping', body: 'Handshake ping: Confirming secure link connectivity across our cryptographic mesh.' },
  { label: '🔐 PQC Handshake', subject: 'Post-Quantum TLS Verification', body: 'Please verify receipt of this E2EE message secured with CRYSTALS-Kyber-768 hybrid key exchange.' },
  { label: '⚠️ Urgent Anomaly', subject: 'URGENT: Suspicious Session Detected', body: 'Sensor probe detected anomalous cipher suite negotiation. Please review the forensic trace in SOC.' },
  { label: '📁 Report Ready', subject: 'Compliance & CBOM Report Ready', body: 'The cryptographic bill of materials assessment has been compiled and indexed in your mailbox.' },
  { label: '✅ Acknowledged', subject: 'Task Acknowledged', body: 'Received and confirmed. Taking immediate mitigation actions.' },
];

export default function QuickMailDrawer() {
  const { data: session } = useSession();
  const [isOpen, setIsOpen] = useState(false);
  const [users, setUsers] = useState<UserPresence[]>([]);
  const [onlineCount, setOnlineCount] = useState(0);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [filter, setFilter] = useState<'all' | 'online'>('online');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected recipient & compose form state
  const [selectedUser, setSelectedUser] = useState<UserPresence | null>(null);
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [encrypted, setEncrypted] = useState(true);
  const [protocol, setProtocol] = useState<'auto' | 'smtp-starttls' | 'smtps' | 'p2p-mesh'>('auto');
  const [sending, setSending] = useState(false);
  const [sentSuccess, setSentSuccess] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const bodyInputRef = useRef<HTMLTextAreaElement>(null);

  // Fetch directory with online presence
  const fetchPresence = async () => {
    try {
      setLoadingUsers(true);
      const res = await fetch('/api/presence');
      if (res.ok) {
        const data = await res.json();
        if (data.users) setUsers(data.users);
        if (typeof data.onlineCount === 'number') setOnlineCount(data.onlineCount);
      }
    } catch (err) {
      console.warn('Failed to fetch online presence:', err);
    } finally {
      setLoadingUsers(false);
    }
  };

  // Initial load & periodic presence heartbeat (every 25 seconds)
  useEffect(() => {
    fetchPresence();
    const interval = setInterval(() => {
      fetch('/api/presence', { method: 'POST' }).catch(() => {});
      fetchPresence();
    }, 25000);
    return () => clearInterval(interval);
  }, []);

  // Listen for custom event to open quick mail with a specific user
  useEffect(() => {
    const handleOpenQuickMail = (e: CustomEvent<{ user?: UserPresence; email?: string; name?: string }>) => {
      setIsOpen(true);
      if (e.detail?.user) {
        setSelectedUser(e.detail.user);
      } else if (e.detail?.email) {
        const found = users.find(u => u.email.toLowerCase() === e.detail.email?.toLowerCase());
        if (found) {
          setSelectedUser(found);
        } else {
          setSelectedUser({
            id: `temp-${Date.now()}`,
            name: e.detail.name || e.detail.email.split('@')[0],
            email: e.detail.email,
            role: 'user',
            avatarColor: '#38BDF8',
            isOnline: true,
            statusText: 'Active now',
            lastActive: Date.now(),
          });
        }
      }
    };

    window.addEventListener('open-quick-mail' as any, handleOpenQuickMail as EventListener);
    return () => {
      window.removeEventListener('open-quick-mail' as any, handleOpenQuickMail as EventListener);
    };
  }, [users]);

  // Focus textarea when a user is selected
  useEffect(() => {
    if (selectedUser) {
      setSentSuccess(false);
      setErrorMsg('');
      setTimeout(() => bodyInputRef.current?.focus(), 150);
    }
  }, [selectedUser]);

  const handleSelectContact = (user: UserPresence) => {
    setSelectedUser(user);
    if (!subject) setSubject('⚡ Quick Message from ' + (session?.user?.name || 'Garuda User'));
    setErrorMsg('');
    setSentSuccess(false);
  };

  const handleApplyTemplate = (tmpl: typeof QUICK_TEMPLATES[0]) => {
    setSubject(tmpl.subject);
    setBody(tmpl.body);
    setErrorMsg('');
  };

  const handleSendQuick = async () => {
    if (!selectedUser) return;
    if (!body.trim()) {
      setErrorMsg('Please write a message before sending.');
      bodyInputRef.current?.focus();
      return;
    }

    setSending(true);
    setErrorMsg('');

    try {
      const res = await fetch('/api/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: [{ email: selectedUser.email, name: selectedUser.name }],
          subject: subject.trim() || `⚡ Quick Dispatch: ${(session?.user?.name || 'Garuda Operator')}`,
          body: body.trim(),
          draft: false,
          protocol,
          encrypted,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to dispatch email');
      }

      setSending(false);
      setSentSuccess(true);

      if (data.email) {
        saveDispatchedEmailToStorage(data.email);
      }

      // Trigger custom event so Inbox or Sent lists update live
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('email-dispatched', { detail: data }));
      }

      // Reset after short delay or keep success notification
      setTimeout(() => {
        setBody('');
      }, 1000);
    } catch (err: unknown) {
      setSending(false);
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg || 'Error dispatching message');
    }
  };

  // Filtered contacts
  const filteredUsers = users.filter(u => {
    // Exclude current user from contact picker
    if (session?.user?.email && u.email.toLowerCase() === session.user.email.toLowerCase()) {
      return false;
    }
    if (filter === 'online' && !u.isOnline) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q) || (u.department && u.department.toLowerCase().includes(q));
    }
    return true;
  });

  return (
    <>
      {/* ── Persistent Floating WhatsApp-style Trigger Badge (Bottom Right) ── */}
      <div className="fixed bottom-20 md:bottom-6 right-4 sm:right-6 z-40">
        <motion.button
          type="button"
          id="quick-mail-floating-btn"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => {
            setIsOpen(!isOpen);
            if (!isOpen) fetchPresence();
          }}
          className={clsx(
            'flex items-center gap-2.5 px-4 py-2.5 rounded-full shadow-2xl transition-all duration-300 font-sans border backdrop-blur-md cursor-pointer',
            isOpen
              ? 'bg-[#0f172a] text-white border-sky-400 shadow-[0_0_25px_rgba(56,189,248,0.35)]'
              : 'bg-gradient-to-r from-emerald-600 to-teal-700 text-white border-emerald-400/40 shadow-[0_4px_20px_rgba(16,185,129,0.4)] hover:shadow-[0_6px_25px_rgba(16,185,129,0.55)]'
          )}
          title="WhatsApp-style Online Users & Quick Email Dispatch"
        >
          <div className="relative">
            <MessageSquare size={18} className="text-white" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-300 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400 border border-black" />
            </span>
          </div>

          <span className="text-[12px] font-bold tracking-wide">Quick Mail</span>

          {onlineCount > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-white/20 border border-white/30 text-white">
              {onlineCount} Online
            </span>
          )}
        </motion.button>
      </div>

      {/* ── Sliding WhatsApp-Style Drawer ── */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 30, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 30, scale: 0.97 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            className="fixed bottom-24 md:bottom-20 right-2 sm:right-6 w-[94vw] sm:w-[420px] max-h-[85vh] h-[620px] bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.6)] flex flex-col z-50 overflow-hidden backdrop-blur-xl"
          >
            {/* ── Drawer Header (WhatsApp Green Accent Header) ── */}
            <div className="px-4 py-3 bg-gradient-to-r from-[#0d2818] via-[#0b1e15] to-[#0f172a] border-b border-emerald-900/40 flex items-center justify-between text-white">
              <div className="flex items-center gap-2.5">
                {selectedUser ? (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedUser(null);
                      setSentSuccess(false);
                    }}
                    className="p-1 rounded-full hover:bg-white/10 text-emerald-300 transition-colors"
                    title="Back to contacts list"
                  >
                    <ChevronLeft size={20} />
                  </button>
                ) : (
                  <div className="relative">
                    <div className="w-8 h-8 rounded-full bg-emerald-500/20 border border-emerald-400/40 flex items-center justify-center text-emerald-400">
                      <Zap size={16} />
                    </div>
                    <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-emerald-400 border border-black" />
                  </div>
                )}

                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[13px] font-bold leading-tight">
                      {selectedUser ? selectedUser.name : 'Active Peers & Quick Mail'}
                    </span>
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      {selectedUser ? selectedUser.statusText : `${onlineCount} Online`}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-300 truncate max-w-[220px]">
                    {selectedUser ? selectedUser.email : 'WhatsApp-style instant encrypted peer delivery'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={fetchPresence}
                  disabled={loadingUsers}
                  className="p-1.5 rounded-md hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
                  title="Refresh presence"
                >
                  <RefreshCw size={14} className={clsx(loadingUsers && 'animate-spin')} />
                </button>
                <button
                  type="button"
                  onClick={() => setIsOpen(false)}
                  className="p-1.5 rounded-md hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
                  title="Close"
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* ── View 1: Contact Directory (WhatsApp Chats List) ── */}
            {!selectedUser && (
              <div className="flex-1 flex flex-col min-h-0 bg-[var(--color-surface-0)]">
                {/* Search & Tabs */}
                <div className="p-3 border-b border-[var(--color-border-subtle)] space-y-2 bg-[var(--color-surface-1)]">
                  <div className="relative">
                    <Search size={14} className="absolute left-3 top-2.5 text-[var(--color-text-dim)]" />
                    <input
                      type="text"
                      placeholder="Search colleagues by name or email..."
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[12px] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none focus:border-emerald-500 transition-colors"
                    />
                  </div>

                  {/* Filter Pills */}
                  <div className="flex items-center gap-2 text-[11px]">
                    <button
                      type="button"
                      onClick={() => setFilter('online')}
                      className={clsx(
                        'px-2.5 py-1 rounded-full font-medium transition-all flex items-center gap-1.5',
                        filter === 'online'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm'
                          : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]'
                      )}
                    >
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      <span>Online ({onlineCount})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setFilter('all')}
                      className={clsx(
                        'px-2.5 py-1 rounded-full font-medium transition-all flex items-center gap-1',
                        filter === 'all'
                          ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] border border-[var(--color-border)]'
                          : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]'
                      )}
                    >
                      <Users size={12} />
                      <span>All Contacts ({users.length})</span>
                    </button>
                  </div>
                </div>

                {/* Contacts List */}
                <div className="flex-1 overflow-y-auto divide-y divide-[var(--color-border-subtle)]">
                  {filteredUsers.length === 0 ? (
                    <div className="p-8 text-center space-y-2">
                      <div className="w-10 h-10 rounded-full bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-center justify-center mx-auto text-[var(--color-text-dim)]">
                        <Users size={18} />
                      </div>
                      <p className="text-[12px] font-medium text-[var(--color-text-secondary)]">No peers found</p>
                      <p className="text-[11px] text-[var(--color-text-dim)]">
                        {filter === 'online' ? 'No other operators are online right now' : 'No matching contacts'}
                      </p>
                    </div>
                  ) : (
                    filteredUsers.map(user => {
                      const initials = user.name
                        .split(' ')
                        .map(n => n[0])
                        .join('')
                        .slice(0, 2)
                        .toUpperCase();

                      return (
                        <button
                          key={user.id}
                          id={`contact-item-${user.id}`}
                          type="button"
                          onClick={() => handleSelectContact(user)}
                          className="w-full px-3.5 py-2.5 flex items-center justify-between hover:bg-[var(--color-surface-2)] transition-colors text-left group"
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            {/* WhatsApp Avatar with live status dot */}
                            <div className="relative flex-shrink-0">
                              <div
                                className="w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-[13px] border border-white/10 shadow-sm"
                                style={{ backgroundColor: user.avatarColor || '#38BDF8' }}
                              >
                                {initials}
                              </div>
                              {user.isOnline ? (
                                <span className="absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-emerald-400 border-2 border-[var(--color-surface-0)] flex items-center justify-center">
                                  <span className="w-1.5 h-1.5 rounded-full bg-white" />
                                </span>
                              ) : (
                                <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-slate-500 border-2 border-[var(--color-surface-0)]" />
                              )}
                            </div>

                            <div className="min-w-0">
                              <div className="flex items-center gap-1.5">
                                <span className="text-[13px] font-semibold text-[var(--color-text-primary)] truncate group-hover:text-emerald-400 transition-colors">
                                  {user.name}
                                </span>
                                {user.role === 'admin' && (
                                  <span className="text-[9px] uppercase px-1 py-0.2 rounded font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                                    Admin
                                  </span>
                                )}
                              </div>
                              <p className="text-[11px] text-[var(--color-text-dim)] truncate">
                                {user.email}
                              </p>
                            </div>
                          </div>

                          <div className="flex flex-col items-end gap-1 flex-shrink-0 ml-2">
                            <span
                              className={clsx(
                                'text-[10px] font-medium flex items-center gap-1',
                                user.isOnline ? 'text-emerald-400 font-semibold' : 'text-[var(--color-text-dim)]'
                              )}
                            >
                              {user.isOnline && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
                              {user.statusText}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-muted)] group-hover:bg-emerald-500/20 group-hover:text-emerald-300 transition-colors flex items-center gap-0.5">
                              <span>Message</span>
                              <Send size={9} />
                            </span>
                          </div>
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            )}

            {/* ── View 2: Quick Email / Chat Compose (WhatsApp Message Style) ── */}
            {selectedUser && (
              <div className="flex-1 flex flex-col min-h-0 bg-[var(--color-surface-0)]">
                {/* Contact Banner */}
                <div className="px-4 py-2.5 bg-[var(--color-surface-2)] border-b border-[var(--color-border-subtle)] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-6 h-6 rounded-full flex items-center justify-center text-white text-[10px] font-bold"
                      style={{ backgroundColor: selectedUser.avatarColor || '#38BDF8' }}
                    >
                      {selectedUser.name.slice(0, 2).toUpperCase()}
                    </div>
                    <div className="text-[11px]">
                      <span className="text-[var(--color-text-muted)]">To: </span>
                      <strong className="text-[var(--color-text-primary)]">{selectedUser.name}</strong>
                      <span className="text-[var(--color-text-dim)] ml-1">({selectedUser.email})</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 font-semibold">
                    <Shield size={11} />
                    <span>E2EE Active</span>
                  </div>
                </div>

                {/* Quick Templates Strip */}
                <div className="px-3 py-2 bg-[var(--color-surface-1)] border-b border-[var(--color-border-subtle)] overflow-x-auto flex items-center gap-1.5 no-scrollbar">
                  <span className="text-[10px] uppercase font-mono text-[var(--color-text-dim)] mr-1 flex-shrink-0">
                    Quick:
                  </span>
                  {QUICK_TEMPLATES.map((tmpl, idx) => (
                    <button
                      key={idx}
                      id={`quick-tmpl-btn-${idx}`}
                      type="button"
                      onClick={() => handleApplyTemplate(tmpl)}
                      className="px-2.5 py-1 rounded-full text-[10px] font-medium bg-[var(--color-surface-2)] text-[var(--color-text-secondary)] hover:text-emerald-400 hover:bg-emerald-500/15 border border-[var(--color-border-subtle)] transition-colors whitespace-nowrap flex-shrink-0 flex items-center gap-1"
                    >
                      <span>{tmpl.label}</span>
                    </button>
                  ))}
                </div>

                {/* Form Fields */}
                <div className="flex-1 p-3.5 space-y-3 overflow-y-auto">
                  {/* Subject */}
                  <div>
                    <label className="text-[10px] font-mono uppercase text-[var(--color-text-dim)] block mb-1">
                      Subject
                    </label>
                    <input
                      type="text"
                      value={subject}
                      onChange={e => setSubject(e.target.value)}
                      placeholder="Subject line..."
                      className="w-full px-3 py-1.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[12px] text-[var(--color-text-primary)] outline-none focus:border-emerald-500 font-medium transition-colors"
                    />
                  </div>

                  {/* Body Textarea */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-[10px] font-mono uppercase text-[var(--color-text-dim)]">
                        Message Content
                      </label>
                      <span className="text-[10px] text-[var(--color-text-dim)] font-mono">
                        Press Ctrl+Enter to send
                      </span>
                    </div>
                    <textarea
                      ref={bodyInputRef}
                      id="quick-mail-body-input"
                      value={body}
                      onChange={e => {
                        setBody(e.target.value);
                        if (errorMsg) setErrorMsg('');
                      }}
                      onKeyDown={e => {
                        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                          e.preventDefault();
                          handleSendQuick();
                        }
                      }}
                      rows={7}
                      placeholder={`Write a quick message to ${selectedUser.name}... Dispatches instantaneously with AES-256-GCM encryption.`}
                      className="w-full p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[12px] leading-relaxed text-[var(--color-text-primary)] outline-none focus:border-emerald-500 resize-none transition-colors font-sans"
                    />
                  </div>

                  {/* Dispatch Options Strip */}
                  <div className="p-2.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] flex items-center justify-between gap-2 text-[11px]">
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setEncrypted(!encrypted)}
                        className={clsx(
                          'flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border transition-colors',
                          encrypted
                            ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                            : 'bg-[var(--color-surface-3)] text-[var(--color-text-dim)] border-[var(--color-border)]'
                        )}
                      >
                        <Lock size={10} />
                        <span>{encrypted ? 'AES-256 E2EE' : 'Plaintext'}</span>
                      </button>

                      <select
                        value={protocol}
                        onChange={e => setProtocol(e.target.value as any)}
                        className="px-2 py-0.5 rounded text-[10px] font-mono bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] border border-[var(--color-border)] outline-none"
                      >
                        <option value="auto">Auto Mesh</option>
                        <option value="smtp-starttls">SMTP/587</option>
                        <option value="smtps">SMTPS/465</option>
                        <option value="p2p-mesh">P2P Mesh</option>
                      </select>
                    </div>

                    <a
                      href={`/compose?to=${encodeURIComponent(selectedUser.email)}&subject=${encodeURIComponent(subject)}`}
                      className="text-[10px] text-[var(--color-accent)] hover:underline flex items-center gap-0.5 font-medium"
                    >
                      <span>Full Composer</span>
                      <ArrowUpRight size={10} />
                    </a>
                  </div>

                  {/* Status Banner */}
                  {sentSuccess && (
                    <motion.div
                      initial={{ opacity: 0, y: 5 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="p-3 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px] flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2">
                        <CheckCheck size={16} className="text-emerald-400 flex-shrink-0" />
                        <div>
                          <strong className="block font-semibold">Dispatched Successfully!</strong>
                          <span className="text-[10px] opacity-80">
                            Sent to {selectedUser.email} via encrypted peer transport.
                          </span>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setSentSuccess(false);
                          setBody('');
                        }}
                        className="px-2 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 text-[10px] font-semibold"
                      >
                        Send Another
                      </button>
                    </motion.div>
                  )}

                  {errorMsg && (
                    <motion.div
                      initial={{ opacity: 0, y: 5 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="p-2.5 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[11px] flex items-center gap-2"
                    >
                      <AlertCircle size={14} className="text-rose-400 flex-shrink-0" />
                      <span>{errorMsg}</span>
                    </motion.div>
                  )}
                </div>

                {/* Footer Send Bar */}
                <div className="p-3 bg-[var(--color-surface-1)] border-t border-[var(--color-border)] flex items-center justify-between gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedUser(null);
                      setSentSuccess(false);
                    }}
                    className="px-3 py-1.5 text-[11px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] transition-colors"
                  >
                    Back to Peers
                  </button>

                  <button
                    type="button"
                    id="quick-mail-submit-btn"
                    onClick={handleSendQuick}
                    disabled={sending || !body.trim()}
                    className={clsx(
                      'flex items-center gap-2 px-5 py-2 rounded-lg text-[12px] font-bold text-white transition-all duration-200 shadow-md cursor-pointer disabled:opacity-40',
                      sentSuccess
                        ? 'bg-emerald-600 hover:bg-emerald-500'
                        : 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 shadow-[0_4px_14px_rgba(16,185,129,0.35)]'
                    )}
                  >
                    {sending ? (
                      <>
                        <Loader2 size={13} className="animate-spin" />
                        <span>Dispatching...</span>
                      </>
                    ) : sentSuccess ? (
                      <>
                        <CheckCheck size={14} />
                        <span>Sent (✓✓)</span>
                      </>
                    ) : (
                      <>
                        <Send size={13} />
                        <span>Send Quick Mail</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
