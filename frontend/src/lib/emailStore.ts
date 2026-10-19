import fs from 'fs';
import path from 'path';
import { FALLBACK_EMAILS, type FallbackEmail } from './fallbackEmails';

// ── Ephemeral /tmp and in-memory fallback storage for dispatched emails ───
const TMP_EMAILS_FILE = path.join(
  process.env.VERCEL ? '/tmp' : process.env.TEMP || process.env.TMP || '.',
  'garuda_emails_store.json'
);

declare global {
  var __garudaCustomEmails: FallbackEmail[] | undefined;
}

export function readCustomEmails(): FallbackEmail[] {
  if (global.__garudaCustomEmails && Array.isArray(global.__garudaCustomEmails)) {
    return global.__garudaCustomEmails;
  }
  try {
    if (fs.existsSync(TMP_EMAILS_FILE)) {
      const data = fs.readFileSync(TMP_EMAILS_FILE, 'utf-8');
      const list = JSON.parse(data);
      if (Array.isArray(list)) {
        global.__garudaCustomEmails = list;
        return list;
      }
    }
  } catch {}
  if (!global.__garudaCustomEmails) {
    global.__garudaCustomEmails = [];
  }
  return global.__garudaCustomEmails;
}

export function saveCustomEmail(email: FallbackEmail) {
  const list = readCustomEmails();
  const existingIdx = list.findIndex(e => e.id === email.id);
  if (existingIdx >= 0) {
    list[existingIdx] = email;
  } else {
    list.unshift(email);
  }
  global.__garudaCustomEmails = list;
  try {
    fs.writeFileSync(TMP_EMAILS_FILE, JSON.stringify(list), 'utf-8');
  } catch {}
}

export function updateCustomEmail(id: string, updates: Partial<FallbackEmail>): boolean {
  const list = readCustomEmails();
  let email = list.find(e => e.id === id);
  if (!email) {
    const fb = FALLBACK_EMAILS.find(e => e.id === id);
    if (fb) {
      email = { ...fb, ...updates };
      saveCustomEmail(email);
      return true;
    }
    return false;
  }
  Object.assign(email, updates);
  if (updates.read !== undefined) {
    for (const r of email.recipients) {
      r.read = updates.read;
    }
  }
  if (updates.starred !== undefined) {
    for (const r of email.recipients) {
      r.starred = updates.starred;
    }
  }
  if (updates.folder !== undefined) {
    for (const r of email.recipients) {
      r.folder = updates.folder;
    }
  }
  saveCustomEmail(email);
  return true;
}

export function deleteCustomEmail(id: string, permanent: boolean = false): boolean {
  let list = readCustomEmails();
  if (permanent) {
    list = list.filter(e => e.id !== id);
    global.__garudaCustomEmails = list;
    try {
      fs.writeFileSync(TMP_EMAILS_FILE, JSON.stringify(list), 'utf-8');
    } catch {}
    return true;
  } else {
    return updateCustomEmail(id, { folder: 'trash' });
  }
}

export function findCustomEmailById(id: string): FallbackEmail | null {
  const custom = readCustomEmails().find(e => e.id === id);
  if (custom) return custom;
  const builtin = FALLBACK_EMAILS.find(e => e.id === id);
  return builtin || null;
}

export function getServerFallbackEmailsResponse(
  folder: string = 'inbox',
  search: string = '',
  userEmail?: string,
  userId?: string
) {
  const custom = readCustomEmails();
  const customIds = new Set(custom.map(c => c.id));
  const combined = [...custom, ...FALLBACK_EMAILS.filter(fb => !customIds.has(fb.id))];

  const normalizedUserEmail = userEmail?.toLowerCase().trim();

  let list = combined.filter(e => {
    const isSender = (userId && e.fromId === userId) || (normalizedUserEmail && e.from?.email?.toLowerCase() === normalizedUserEmail);
    const matchedRecipient = e.recipients.find(r => 
      (userId && r.userId === userId) || 
      (normalizedUserEmail && r.address?.toLowerCase() === normalizedUserEmail)
    );

    if (folder === 'sent') {
      return isSender && !e.draft && e.folder !== 'trash';
    } else if (folder === 'drafts' || folder === 'draft') {
      return isSender && Boolean(e.draft) && e.folder !== 'trash';
    } else if (folder === 'starred') {
      return (e.starred || matchedRecipient?.starred) && e.folder !== 'trash';
    } else if (folder === 'trash') {
      return e.folder === 'trash' || matchedRecipient?.folder === 'trash';
    } else if (folder === 'archive') {
      return e.folder === 'archive' || matchedRecipient?.folder === 'archive';
    } else {
      // inbox
      if (e.folder === 'trash' || e.draft) return false;
      if (matchedRecipient) {
        return matchedRecipient.folder === 'inbox' || !matchedRecipient.folder;
      }
      return !isSender && (e.folder === 'inbox' || !e.folder);
    }
  });

  if (search) {
    const s = search.toLowerCase();
    list = list.filter(e =>
      e.subject.toLowerCase().includes(s) ||
      e.body.toLowerCase().includes(s) ||
      e.from?.email?.toLowerCase().includes(s) ||
      e.from?.name?.toLowerCase().includes(s)
    );
  }

  // Count unreads for folder badges
  let inboxUnread = 0;
  let starredUnread = 0;
  let draftsCount = 0;

  for (const e of combined) {
    if (e.folder === 'trash') continue;
    const isSender = (userId && e.fromId === userId) || (normalizedUserEmail && e.from?.email?.toLowerCase() === normalizedUserEmail);
    const matchedRecipient = e.recipients.find(r => 
      (userId && r.userId === userId) || 
      (normalizedUserEmail && r.address?.toLowerCase() === normalizedUserEmail)
    );
    if (e.draft && isSender) {
      draftsCount++;
    }
    const isUnread = matchedRecipient ? !matchedRecipient.read : (e.recipients.length > 0 ? !e.recipients[0].read : false);
    if (isUnread) {
      if (matchedRecipient?.folder === 'inbox' || (!isSender && e.folder === 'inbox')) {
        inboxUnread++;
      }
      if (e.starred || matchedRecipient?.starred) {
        starredUnread++;
      }
    }
  }

  return {
    emails: list,
    unreadCounts: {
      inbox: inboxUnread,
      starred: starredUnread,
      sent: 0,
      drafts: draftsCount,
      trash: 0,
      archive: 0,
    },
    page: 1,
    total: list.length,
  };
}
