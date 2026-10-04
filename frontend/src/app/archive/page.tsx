'use client';

import { motion } from 'framer-motion';
import { Archive as ArchiveIcon } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function ArchivePage() {
  const emails = getEmailsByFolder('archive');

  return (
    <AppShell title="Archive" description={`${emails.length} archived messages`}>
      <motion.div {...fadeUp} className="card overflow-hidden">
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <ArchiveIcon size={40} className="text-[var(--color-text-dim)] mb-4" />
          <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">Archive is empty</h3>
          <p className="text-[13px] text-[var(--color-text-muted)]">Archived messages will appear here.</p>
        </div>
      </motion.div>
    </AppShell>
  );
}
