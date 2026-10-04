'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Shield, AlertTriangle, Network, MessageSquare,
  Plus, CheckCircle, Clock, ChevronRight, FileText,
  User, Send, X, Download, Tag
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, StatusBadge } from '@/components/ui/shared';
import { mockInvestigations } from '@/lib/mock/details';
import { mockFindings, mockSessions } from '@/lib/mock/data';
import { formatDateTime } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import type { Investigation, InvestigationNote } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function InvestigationsPage() {
  const [investigations, setInvestigations] = useState<Investigation[]>(mockInvestigations);
  const [selectedCase, setSelectedCase] = useState<Investigation>(mockInvestigations[0]);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim()) return;

    const newNote: InvestigationNote = {
      id: `NOTE-${Date.now().toString().slice(-4)}`,
      content: newNoteContent.trim(),
      author: 'Forensic Lead',
      createdAt: new Date().toISOString(),
    };

    const updatedCase = {
      ...selectedCase,
      updatedAt: new Date().toISOString(),
      notes: [...selectedCase.notes, newNote],
    };

    setSelectedCase(updatedCase);
    setInvestigations(prev => prev.map(inv => inv.id === updatedCase.id ? updatedCase : inv));
    setNewNoteContent('');
  };

  const handleCreateCase = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    const newCase: Investigation = {
      id: `INV-00${investigations.length + 1}`,
      title: newTitle.trim(),
      description: newDescription.trim() || 'Custom forensic inquiry',
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      sessionIds: ['SMTP-0192'],
      findingIds: ['TLS-001'],
      notes: [{
        id: `NOTE-${Date.now().toString().slice(-4)}`,
        content: 'Case initiated by investigator.',
        author: 'Forensic Lead',
        createdAt: new Date().toISOString(),
      }],
    };

    setInvestigations([newCase, ...investigations]);
    setSelectedCase(newCase);
    setIsCreateModalOpen(false);
    setNewTitle('');
    setNewDescription('');
  };

  const exportDossier = () => {
    const dossierData = JSON.stringify(selectedCase, null, 2);
    const blob = new Blob([dossierData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedCase.id}-dossier.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AppShell
      title="Forensic Investigations"
      description="Collaborative case management, evidence consolidation, and chronological analyst notes"
    >
      <div className="space-y-6">

        {/* ── Top Bar ── */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
              Active Investigation Cases
            </h3>
            <p className="text-[12px] text-[var(--color-text-muted)]">
              Consolidated incident files linking sessions, cryptographic findings, and analyst logs
            </p>
          </div>

          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="btn btn-primary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
          >
            <Plus size={15} /> New Investigation Case
          </button>
        </div>

        {/* ── Main Layout: Case List (1 col) + Case Detail (2 cols) ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Left Column: Cases List */}
          <div className="space-y-3">
            {investigations.map((inv) => (
              <div
                key={inv.id}
                onClick={() => setSelectedCase(inv)}
                className={clsx(
                  'card p-4 cursor-pointer transition-all duration-150 space-y-2',
                  selectedCase.id === inv.id
                    ? 'border-[var(--color-accent)] bg-[rgba(56,189,248,0.04)] ring-1 ring-[var(--color-accent)]'
                    : 'hover:border-[var(--color-border-hover)]'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-mono font-bold text-[12px] text-[var(--color-accent)]">
                    {inv.id}
                  </span>
                  <span className={clsx(
                    'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded',
                    inv.status === 'active' ? 'badge-critical' : 'badge-healthy'
                  )}>
                    {inv.status}
                  </span>
                </div>

                <h4 className="text-[13px] font-semibold text-[var(--color-text-primary)] line-clamp-1">
                  {inv.title}
                </h4>

                <p className="text-[11px] text-[var(--color-text-dim)] line-clamp-2">
                  {inv.description}
                </p>

                <div className="flex items-center justify-between text-[10px] text-[var(--color-text-dim)] pt-2 border-t border-[var(--color-border-subtle)]">
                  <span>{inv.findingIds.length} findings • {inv.sessionIds.length} sessions</span>
                  <span>{formatDateTime(inv.updatedAt)}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Right Column: Case Workspace */}
          <div className="lg:col-span-2">
            <div className="card p-6 space-y-6">

              {/* Case Header */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[var(--color-border)]">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-mono font-bold text-sm text-[var(--color-accent)]">
                      {selectedCase.id}
                    </span>
                    <h3 className="text-lg font-bold text-[var(--color-text-primary)]">
                      {selectedCase.title}
                    </h3>
                  </div>
                  <p className="text-[12px] text-[var(--color-text-muted)]">
                    Created on {formatDateTime(selectedCase.createdAt)} • Last updated {formatDateTime(selectedCase.updatedAt)}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={exportDossier}
                    className="btn btn-secondary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
                  >
                    <Download size={13} /> Export Dossier
                  </button>
                </div>
              </div>

              {/* Case Description */}
              <div className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-secondary)] leading-relaxed">
                {selectedCase.description}
              </div>

              {/* Linked Evidence: Findings & Sessions */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                {/* Linked Findings */}
                <div className="space-y-2">
                  <div className="text-[11px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center gap-1.5">
                    <AlertTriangle size={14} className="text-[var(--color-severity-critical)]" />
                    Linked Security Findings ({selectedCase.findingIds.length})
                  </div>

                  <div className="space-y-2">
                    {selectedCase.findingIds.map(fid => {
                      const finding = mockFindings.find(f => f.id === fid);
                      return (
                        <div key={fid} className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-start justify-between gap-2">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-mono text-[11px] text-[var(--color-text-dim)]">{fid}</span>
                              {finding && <SeverityBadge severity={finding.severity} size="xs" />}
                            </div>
                            <div className="text-[12px] font-semibold text-[var(--color-text-primary)] mt-0.5">
                              {finding ? finding.title : fid}
                            </div>
                          </div>
                          <Link
                            href={`/findings/${fid}`}
                            className="text-[11px] text-[var(--color-accent)] hover:underline flex items-center gap-0.5 flex-shrink-0"
                          >
                            Inspect <ChevronRight size={12} />
                          </Link>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Linked Sessions */}
                <div className="space-y-2">
                  <div className="text-[11px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center gap-1.5">
                    <Network size={14} className="text-[var(--color-accent)]" />
                    Linked Forensic Sessions ({selectedCase.sessionIds.length})
                  </div>

                  <div className="space-y-2">
                    {selectedCase.sessionIds.map(sid => {
                      const session = mockSessions.find(s => s.id === sid);
                      return (
                        <div key={sid} className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-start justify-between gap-2">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-mono font-bold text-[12px] text-[var(--color-accent)]">{sid}</span>
                              {session && (
                                <span className="text-[10px] text-mono bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded text-[var(--color-text-secondary)]">
                                  {session.protocol}
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-[var(--color-text-dim)] mt-0.5">
                              {session ? `${session.sourceIp} → ${session.destHostname || session.destIp}` : sid}
                            </div>
                          </div>
                          <Link
                            href={`/sessions/${sid}`}
                            className="text-[11px] text-[var(--color-accent)] hover:underline flex items-center gap-0.5 flex-shrink-0"
                          >
                            Trace <ChevronRight size={12} />
                          </Link>
                        </div>
                      );
                    })}
                  </div>
                </div>

              </div>

              {/* Analyst Notes Log */}
              <div className="space-y-3 pt-2">
                <div className="text-[11px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center gap-1.5">
                  <MessageSquare size={14} className="text-[var(--color-accent)]" />
                  Chronological Analyst Log ({selectedCase.notes.length})
                </div>

                <div className="space-y-2.5">
                  {selectedCase.notes.map((note) => (
                    <div key={note.id} className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-[var(--color-text-primary)] flex items-center gap-1.5">
                          <User size={12} className="text-[var(--color-accent)]" />
                          {note.author}
                        </span>
                        <span className="text-[var(--color-text-dim)] text-mono">
                          {formatDateTime(note.createdAt)}
                        </span>
                      </div>
                      <p className="text-[12px] text-[var(--color-text-secondary)] leading-relaxed">
                        {note.content}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleAddNote} className="space-y-2 pt-2">
                  <textarea
                    rows={2}
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                    placeholder="Add an analyst note or remediation observation..."
                    className="w-full p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[12px] text-[var(--color-text-primary)] placeholder-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] resize-none"
                  />
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={!newNoteContent.trim()}
                      className="btn btn-primary text-[12px] py-1 px-3 flex items-center gap-1.5"
                    >
                      <Send size={12} /> Post Note
                    </button>
                  </div>
                </form>
              </div>

            </div>
          </div>

        </div>

        {/* ── Create Investigation Modal ── */}
        <AnimatePresence>
          {isCreateModalOpen && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
              <motion.div
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.96 }}
                className="card w-full max-w-lg bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden"
              >
                <div className="p-5 border-b border-[var(--color-border)] flex items-center justify-between bg-[var(--color-surface-2)]">
                  <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                    Initiate New Investigation
                  </h3>
                  <button
                    onClick={() => setIsCreateModalOpen(false)}
                    className="p-1 rounded text-[var(--color-text-muted)] hover:text-white"
                  >
                    <X size={18} />
                  </button>
                </div>

                <form onSubmit={handleCreateCase} className="p-6 space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Case Title
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. Unauthenticated Relay Incident"
                      value={newTitle}
                      onChange={(e) => setNewTitle(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Case Summary & Scope
                    </label>
                    <textarea
                      rows={3}
                      placeholder="Describe the suspect traffic, affected mail endpoints, and scope..."
                      value={newDescription}
                      onChange={(e) => setNewDescription(e.target.value)}
                      className="w-full p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[12px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] resize-none"
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-3 border-t border-[var(--color-border)]">
                    <button
                      type="button"
                      onClick={() => setIsCreateModalOpen(false)}
                      className="btn btn-secondary text-[12px] py-1.5 px-3"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={!newTitle.trim()}
                      className="btn btn-primary text-[12px] py-1.5 px-4"
                    >
                      Create Case
                    </button>
                  </div>
                </form>
              </motion.div>
            </div>
          )}
        </AnimatePresence>

      </div>
    </AppShell>
  );
}
