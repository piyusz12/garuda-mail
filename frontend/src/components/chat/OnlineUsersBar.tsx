'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Zap, MessageSquare, Users, Sparkles, ChevronRight } from 'lucide-react';
import clsx from 'clsx';
import { useSession } from 'next-auth/react';
import type { UserPresence } from '@/lib/presence';

export default function OnlineUsersBar() {
  const { data: session } = useSession();
  const [users, setUsers] = useState<UserPresence[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/presence');
      if (res.ok) {
        const data = await res.json();
        if (data.users) setUsers(data.users);
      }
    } catch {
      // quiet failover
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
    const interval = setInterval(fetchUsers, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleOpenQuickMail = (user?: UserPresence) => {
    window.dispatchEvent(
      new CustomEvent('open-quick-mail', {
        detail: user ? { user, email: user.email, name: user.name } : {},
      })
    );
  };

  const onlineUsers = users.filter(
    u => u.isOnline && u.email.toLowerCase() !== session?.user?.email?.toLowerCase()
  );

  if (users.length === 0 && !loading) {
    return null;
  }

  return (
    <div className="card p-3 bg-gradient-to-r from-[var(--color-surface-1)] via-[var(--color-surface-2)] to-[var(--color-surface-1)] border border-[var(--color-border)] shadow-sm">
      <div className="flex items-center justify-between gap-2 mb-2 px-1">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
          </span>
          <span className="text-[12px] font-bold text-[var(--color-text-primary)] tracking-tight">
            Active Peers & Contacts
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold">
            {onlineUsers.length} Online
          </span>
        </div>

        <button
          type="button"
          onClick={() => handleOpenQuickMail()}
          className="text-[11px] text-[var(--color-accent)] hover:text-white hover:bg-[var(--color-accent-dim)] px-2 py-0.5 rounded transition-colors flex items-center gap-1 font-medium"
        >
          <span>All Peers</span>
          <ChevronRight size={12} />
        </button>
      </div>

      {/* Horizontal WhatsApp-style avatars tray */}
      <div className="flex items-center gap-3 overflow-x-auto pb-1 pt-1 no-scrollbar">
        {/* Quick Send to Anyone Button */}
        <button
          type="button"
          id="tray-quick-send-btn"
          onClick={() => handleOpenQuickMail()}
          className="flex flex-col items-center gap-1 flex-shrink-0 group cursor-pointer"
          title="Open Quick Mail Composer"
        >
          <div className="w-12 h-12 rounded-full border-2 border-dashed border-emerald-500/50 hover:border-emerald-400 bg-emerald-500/10 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-all">
            <Zap size={18} className="text-emerald-400" />
          </div>
          <span className="text-[10px] font-semibold text-emerald-400 max-w-[60px] truncate text-center">
            Quick Send
          </span>
        </button>

        {/* Online Colleagues / Contacts */}
        {users.map(u => {
          const isCurrent = u.email.toLowerCase() === session?.user?.email?.toLowerCase();
          const initials = u.name
            .split(' ')
            .map(n => n[0])
            .join('')
            .slice(0, 2)
            .toUpperCase();

          return (
            <button
              key={u.id}
              type="button"
              id={`tray-peer-avatar-${u.id}`}
              onClick={() => !isCurrent && handleOpenQuickMail(u)}
              disabled={isCurrent}
              className={clsx(
                'flex flex-col items-center gap-1 flex-shrink-0 transition-transform cursor-pointer group',
                !isCurrent && 'hover:scale-105',
                isCurrent && 'opacity-80 cursor-default'
              )}
              title={isCurrent ? 'You' : `Click to send instant email to ${u.name} (${u.statusText})`}
            >
              <div className="relative">
                {/* WhatsApp Ring around active user */}
                <div
                  className={clsx(
                    'w-12 h-12 rounded-full p-[2px] transition-all',
                    u.isOnline
                      ? 'bg-gradient-to-tr from-emerald-500 via-teal-400 to-sky-400 shadow-[0_0_12px_rgba(16,185,129,0.35)]'
                      : 'bg-[var(--color-border)]'
                  )}
                >
                  <div
                    className="w-full h-full rounded-full flex items-center justify-center text-white font-bold text-[12px] border-2 border-[var(--color-surface-1)] shadow-inner"
                    style={{ backgroundColor: u.avatarColor || '#38BDF8' }}
                  >
                    {initials}
                  </div>
                </div>

                {/* Status Dot */}
                {u.isOnline && (
                  <span className="absolute bottom-0 right-0 w-3.5 h-3.5 rounded-full bg-emerald-400 border-2 border-[var(--color-surface-1)] flex items-center justify-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-white" />
                  </span>
                )}
              </div>

              <div className="flex flex-col items-center max-w-[68px]">
                <span className="text-[11px] font-medium text-[var(--color-text-primary)] truncate text-center group-hover:text-emerald-400 transition-colors">
                  {isCurrent ? 'You' : u.name.split(' ')[0]}
                </span>
                <span
                  className={clsx(
                    'text-[9px] font-mono leading-none truncate',
                    u.isOnline ? 'text-emerald-400 font-semibold' : 'text-[var(--color-text-dim)]'
                  )}
                >
                  {isCurrent ? 'Online' : u.isOnline ? 'Online' : 'Offline'}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
