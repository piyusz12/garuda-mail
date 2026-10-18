'use client';

import { useState } from 'react';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import BottomNav from './BottomNav';
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
    <div className="min-h-screen bg-[var(--color-surface-0)] flex flex-col">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileDrawerOpen}
        onCloseMobile={() => setMobileDrawerOpen(false)}
      />

      <div
        className={clsx(
          'flex-1 flex flex-col transition-all duration-300 ease-in-out min-w-0',
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
    </div>
  );
}
