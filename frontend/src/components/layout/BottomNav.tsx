'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Inbox, AlertTriangle, Layers, Activity, Menu } from 'lucide-react';
import clsx from 'clsx';

interface BottomNavProps {
  onOpenMenu: () => void;
  isMenuOpen: boolean;
}

export default function BottomNav({ onOpenMenu, isMenuOpen }: BottomNavProps) {
  const pathname = usePathname();

  const navItems = [
    { name: 'Inbox', href: '/inbox', icon: Inbox },
    { name: 'Findings', href: '/findings', icon: AlertTriangle },
    { name: 'CBOM', href: '/cbom', icon: Layers },
    { name: 'Ops', href: '/operations', icon: Activity },
  ];

  return (
    <nav
      className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-16 bg-[#0B0D10]/95 border-t border-[var(--color-border)] backdrop-blur-xl px-2 flex items-center justify-around shadow-2xl safe-area-pb"
      aria-label="Mobile Navigation Bar"
    >
      {navItems.map((item) => {
        const Icon = item.icon;
        const isActive = pathname === item.href || (item.href !== '/inbox' && pathname.startsWith(item.href));
        return (
          <Link
            key={item.name}
            href={item.href}
            className={clsx(
              'flex flex-col items-center justify-center flex-1 py-1 transition-all duration-150 rounded-lg group',
              isActive
                ? 'text-[var(--color-accent)] font-semibold'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <div className={clsx('relative p-1 rounded-full transition-transform', isActive && 'scale-110')}>
              <Icon size={20} strokeWidth={isActive ? 2.3 : 1.8} />
              {isActive && (
                <span className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full bg-[var(--color-accent)] shadow-[0_0_8px_var(--color-accent)]" />
              )}
            </div>
            <span className="text-[10px] mt-0.5 tracking-tight">{item.name}</span>
          </Link>
        );
      })}

      {/* Menu / All Tools Trigger */}
      <button
        type="button"
        onClick={onOpenMenu}
        className={clsx(
          'flex flex-col items-center justify-center flex-1 py-1 transition-all duration-150 rounded-lg',
          isMenuOpen
            ? 'text-[var(--color-accent)] font-semibold'
            : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
        )}
        aria-label="Open all navigation options"
      >
        <div className={clsx('p-1 rounded-full transition-transform', isMenuOpen && 'scale-110')}>
          <Menu size={20} strokeWidth={isMenuOpen ? 2.3 : 1.8} />
        </div>
        <span className="text-[10px] mt-0.5 tracking-tight">More</span>
      </button>
    </nav>
  );
}
