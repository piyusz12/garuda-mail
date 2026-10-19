'use client';

import { useState } from 'react';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import BottomNav from './BottomNav';
import QuickMailDrawer from '@/components/chat/QuickMailDrawer';
import clsx from 'clsx';

interface AppShellProps {
  children: React.ReactNode;
  title: string;
  description?: string;
}

export default function AppShell({ children, title, description }: AppShellProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] flex flex-col relative overflow-x-hidden">
      {/* ── Ambient Background Color Glow Mesh ── */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0" aria-hidden="true">
        <div className="absolute -top-32 -left-32 w-[500px] h-[500px] bg-indigo-500/[0.07] rounded-full blur-[120px]" />
        <div className="absolute top-1/4 -right-32 w-[450px] h-[450px] bg-sky-500/[0.06] rounded-full blur-[120px]" />
        <div className="absolute bottom-10 left-1/3 w-[550px] h-[550px] bg-purple-600/[0.05] rounded-full blur-[140px]" />
      </div>

      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileDrawerOpen}
        onCloseMobile={() => setMobileDrawerOpen(false)}
      />

      <div
        className={clsx(
          'flex-1 flex flex-col transition-all duration-300 ease-in-out min-w-0 relative z-10',
          'ml-0',
          sidebarCollapsed ? 'md:ml-[60px]' : 'md:ml-[240px]'
        )}
      >
        <TopBar
          title={title}
          description={description}
          onOpenMobileMenu={() => setMobileDrawerOpen(true)}
        />
        <main className="flex-1 p-3 sm:p-5 md:p-6 pb-24 md:pb-6 overflow-x-hidden min-w-0">
          {children}
        </main>
      </div>

      {/* Mobile Bottom Navigation Bar */}
      <BottomNav
        onOpenMenu={() => setMobileDrawerOpen(!mobileDrawerOpen)}
        isMenuOpen={mobileDrawerOpen}
      />

      {/* WhatsApp-Style Online Users & Quick Mail Drawer */}
      <QuickMailDrawer />
    </div>
  );
}
