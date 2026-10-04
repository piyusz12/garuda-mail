'use client';

import { motion } from 'framer-motion';
import { Trash2 } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function TrashPage() {
  const emails = getEmailsByFolder('trash');

  return (
    <AppShell title="Trash" description={`${emails.length} deleted messages`}>
      <motion.div {...fadeUp} className="card overflow-hidden">
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Trash2 size={40} className="text-[var(--color-text-dim)] mb-4" />
          <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">Trash is empty</h3>
          <p className="text-[13px] text-[var(--color-text-muted)]">Deleted messages will appear here for 30 days.</p>
        </div>
      </motion.div>
    </AppShell>
  );
}
