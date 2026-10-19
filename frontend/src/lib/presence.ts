import { listAllUsers, type UserRecord } from '@/lib/users';

export interface UserPresence {
  id: string;
  name: string;
  email: string;
  role: string;
  department?: string;
  avatarColor: string;
  isOnline: boolean;
  statusText: string;
  lastActive: number; // timestamp ms
}

declare global {
  var __garudaPresenceMap: Map<string, number> | undefined;
}

const presenceMap: Map<string, number> =
  global.__garudaPresenceMap || (global.__garudaPresenceMap = new Map());

// Heartbeat window in ms: 5 minutes
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

export function recordUserHeartbeat(email: string) {
  if (!email) return;
  const normalized = email.toLowerCase().trim();
  presenceMap.set(normalized, Date.now());
}

export function getUserPresenceStatus(email: string, isCurrentUser: boolean = false): {
  isOnline: boolean;
  statusText: string;
  lastActive: number;
} {
  const normalized = email.toLowerCase().trim();
  const lastTime = presenceMap.get(normalized);
  const now = Date.now();

  if (isCurrentUser) {
    return {
      isOnline: true,
      statusText: 'Online (You)',
      lastActive: now,
    };
  }

  if (lastTime && now - lastTime < ONLINE_WINDOW_MS) {
    const diffSec = Math.floor((now - lastTime) / 1000);
    return {
      isOnline: true,
      statusText: diffSec < 60 ? 'Active now' : `${Math.floor(diffSec / 60)}m ago`,
      lastActive: lastTime,
    };
  }

  // Builtin colleagues default presence for lively SOC environment
  const simulatedOnlineEmails = [
    'analyst@garuda.internal',
    'officer@garuda.internal',
    'security@enterprise.local',
  ];

  if (simulatedOnlineEmails.includes(normalized)) {
    return {
      isOnline: true,
      statusText: 'Online',
      lastActive: now - 15000,
    };
  }

  if (lastTime) {
    const diffMin = Math.floor((now - lastTime) / 60000);
    if (diffMin < 60) {
      return { isOnline: false, statusText: `Last seen ${diffMin}m ago`, lastActive: lastTime };
    }
    const diffHours = Math.floor(diffMin / 60);
    return { isOnline: false, statusText: `Last seen ${diffHours}h ago`, lastActive: lastTime };
  }

  return {
    isOnline: false,
    statusText: 'Offline',
    lastActive: 0,
  };
}

export async function getDirectoryWithPresence(currentUserEmail?: string): Promise<{
  users: UserPresence[];
  onlineCount: number;
}> {
  if (currentUserEmail) {
    recordUserHeartbeat(currentUserEmail);
  }

  const allUsers = await listAllUsers();
  const normalizedCurrent = currentUserEmail?.toLowerCase().trim();

  const usersWithPresence: UserPresence[] = allUsers.map(user => {
    const isCurrent = Boolean(normalizedCurrent && user.email.toLowerCase().trim() === normalizedCurrent);
    const presence = getUserPresenceStatus(user.email, isCurrent);

    return {
      id: user.id,
      name: user.name || 'User',
      email: user.email,
      role: user.role,
      department: user.department,
      avatarColor: user.avatarColor || '#38BDF8',
      isOnline: presence.isOnline,
      statusText: presence.statusText,
      lastActive: presence.lastActive,
    };
  });

  // Sort: Current user first, then Online users, then by name
  usersWithPresence.sort((a, b) => {
    const aIsCurrent = Boolean(normalizedCurrent && a.email.toLowerCase().trim() === normalizedCurrent);
    const bIsCurrent = Boolean(normalizedCurrent && b.email.toLowerCase().trim() === normalizedCurrent);
    if (aIsCurrent) return -1;
    if (bIsCurrent) return 1;
    if (a.isOnline && !b.isOnline) return -1;
    if (!a.isOnline && b.isOnline) return 1;
    return a.name.localeCompare(b.name);
  });

  const onlineCount = usersWithPresence.filter(u => u.isOnline).length;

  return {
    users: usersWithPresence,
    onlineCount,
  };
}
