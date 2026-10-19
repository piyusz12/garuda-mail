'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Users, KeyRound, Mail, CheckCircle2, Shield, Search, ArrowLeft } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import Link from 'next/link';

interface DirectoryUser {
  id: string;
  name: string;
  email: string;
  role: string;
  department?: string;
  avatarColor?: string;
  isOnline?: boolean;
}

export default function UserContactsPage() {
  const [contacts, setContacts] = useState<DirectoryUser[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadContacts() {
      try {
        setLoading(true);
        const res = await fetch('/api/users');
        if (res.ok) {
          const data = await res.json();
          setContacts(data.users || []);
        }
      } catch (err) {
        console.error('Failed to load contacts:', err);
      } finally {
        setLoading(false);
      }
    }
    loadContacts();
  }, []);

  const filtered = contacts.filter(
    c => c.name.toLowerCase().includes(search.toLowerCase()) || c.email.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <AppShell title="Verified Contacts & Key Directory" description="Peer public-key directory for E2EE communications">
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <Link
            href="/user/dashboard"
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft size={14} /> Back to User Dashboard
          </Link>
          <div className="relative w-full sm:w-72">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search peers by name or email..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full h-9 pl-9 pr-3 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
        </div>

        {loading ? (
          <div className="card p-12 text-center text-xs text-slate-500">
            Loading directory participants...
          </div>
        ) : filtered.length === 0 ? (
          <div className="card p-12 text-center text-xs text-slate-400">
            No contacts match your search query.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filtered.map(contact => (
              <div
                key={contact.id}
                className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] flex items-center justify-between gap-4 hover:border-sky-500/30 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div
                    className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-white text-xs flex-shrink-0"
                    style={{ backgroundColor: contact.avatarColor || '#38BDF8' }}
                  >
                    {contact.name[0].toUpperCase()}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-white truncate">{contact.name}</span>
                      {contact.isOnline && (
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" title="Online" />
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 truncate">{contact.email}</p>
                    <p className="text-[10px] text-slate-500 font-mono mt-0.5">
                      {contact.department || 'Cryptographic SOC'}
                    </p>
                  </div>
                </div>

                <Link
                  href={`/compose?to=${encodeURIComponent(contact.email)}`}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-300 text-xs font-semibold transition-colors flex-shrink-0"
                >
                  <Mail size={12} /> Send E2EE
                </Link>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
