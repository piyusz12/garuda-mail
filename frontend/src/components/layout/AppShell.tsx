'use client';

import { useState } from 'react';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import clsx from 'clsx';

interface AppShellProps {
  children: React.ReactNode;
  title: string;
  description?: string;
}

export default function AppShell({ children, title, description }: AppShellProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-[var(--color-surface-0)]">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      <div
        className={clsx(
          'transition-all duration-300 ease-in-out',
          sidebarCollapsed ? 'ml-[60px]' : 'ml-[240px]'
        )}
      >
        <TopBar title={title} description={description} />
        <main className="p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
