import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import prisma from '@/lib/db';
import fs from 'fs';
import path from 'path';

export interface UserRecord {
  id: string;
  name: string;
  email: string;
  password: string; // bcrypt hash
  role: string;
  department?: string;
  avatarColor: string;
  createdAt: Date;
  updatedAt: Date;
}

const SECRET = process.env.NEXTAUTH_SECRET || 'garuda-mail-super-secret-production-jwt-2026-key';

// Precomputed bcrypt hash of 'password123'
const DEFAULT_PASSWORD_HASH = '$2b$10$hi/Il7vn75r1yktS//xhWeqhqACFTVG7Aw2PVZ5i8p4YjjJ6cZJNu';

// ── Built-in Seed Users (available immediately in all environments) ────
export const BUILTIN_USERS: UserRecord[] = [
  {
    id: 'user-thalendra-001',
    name: 'Thalendra Bhaskar',
    email: 'bhaskarthalendra@gmail.com',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    department: 'Cryptographic Forensics & SecOps',
    avatarColor: '#38BDF8',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-piyush-002',
    name: 'Piyush Tembhurkar',
    email: 'piyushtembhurkar12@gmail.com',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    department: 'Cryptographic Architecture',
    avatarColor: '#F43F5E',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-analyst-003',
    name: 'Garuda Analyst',
    email: 'analyst@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'analyst',
    department: 'Cryptographic SOC',
    avatarColor: '#38BDF8',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-security-004',
    name: 'Security Operations',
    email: 'security@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    department: 'SecOps Infrastructure',
    avatarColor: '#F43F5E',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-bob-005',
    name: 'Bob Henderson',
    email: 'bob@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'analyst',
    department: 'Network Forensics',
    avatarColor: '#10B981',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-alice-006',
    name: 'Alice Vance',
    email: 'alice@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'analyst',
    department: 'Cryptography & CBOM',
    avatarColor: '#8B5CF6',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-admin-007',
    name: 'System Administrator',
    email: 'admin@garudamail.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    department: 'Security Operations',
    avatarColor: '#E11D48',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-demo-008',
    name: 'Garuda User',
    email: 'user@garudamail.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'analyst',
    department: 'Security Operations',
    avatarColor: '#0EA5E9',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
];

// ── In-Memory User Registry across re-evaluations ───────────────────────
declare global {
  // eslint-disable-next-line no-var
  var __garudaInMemoryUsers: Map<string, UserRecord> | undefined;
}

const inMemoryUsers: Map<string, UserRecord> =
  global.__garudaInMemoryUsers || (global.__garudaInMemoryUsers = new Map());

// Pre-populate in-memory users with builtins
for (const u of BUILTIN_USERS) {
  if (!inMemoryUsers.has(u.email)) {
    inMemoryUsers.set(u.email, u);
  }
}

// ── Ephemeral /tmp fallback storage (survives container reuse) ─────────
const TMP_USERS_FILE = path.join(
  process.env.VERCEL ? '/tmp' : process.env.TEMP || process.env.TMP || '.',
  'garuda_users_store.json'
);

function readTmpUsers(): Record<string, UserRecord> {
  try {
    if (fs.existsSync(TMP_USERS_FILE)) {
      const data = fs.readFileSync(TMP_USERS_FILE, 'utf-8');
      return JSON.parse(data);
    }
  } catch {
    // ignore read errors
  }
  return {};
}

function writeTmpUser(user: UserRecord) {
  try {
    const existing = readTmpUsers();
    existing[user.email] = user;
    fs.writeFileSync(TMP_USERS_FILE, JSON.stringify(existing), 'utf-8');
  } catch {
    // ignore write errors in restricted environments
  }
}

// ── Signed Fallback Token (Client cookie persistence) ─────────────────
export function createFallbackToken(user: UserRecord): string {
  const payload = {
    id: user.id,
    name: user.name,
    email: user.email,
    password: user.password,
    role: user.role,
    department: user.department,
    avatarColor: user.avatarColor,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
  };
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

export function verifyFallbackToken(token: string): UserRecord | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [b64, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', SECRET).update(b64).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8'));
    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }
    return {
      id: payload.id,
      name: payload.name,
      email: payload.email,
      password: payload.password,
      role: payload.role || 'analyst',
      department: payload.department,
      avatarColor: payload.avatarColor || '#38BDF8',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  } catch {
    return null;
  }
}

function parseCookie(cookieHeader: string, name: string): string | null {
  const cookies = cookieHeader.split(';');
  for (const c of cookies) {
    const [k, ...v] = c.trim().split('=');
    if (k === name) {
      return decodeURIComponent(v.join('='));
    }
  }
  return null;
}

// ── Multi-Tier Lookup: DB -> Memory -> /tmp -> Cookie -> Builtins ───────
export async function findUserByEmail(
  email: string,
  cookieHeader?: string | null
): Promise<UserRecord | null> {
  const normalizedEmail = email.toLowerCase().trim();

  // Tier 1: Try Prisma Database
  try {
    const dbUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (dbUser && dbUser.password) {
      return {
        id: dbUser.id,
        name: dbUser.name || 'User',
        email: dbUser.email!,
        password: dbUser.password,
        role: dbUser.role || 'analyst',
        department: dbUser.department || undefined,
        avatarColor: dbUser.avatarColor || '#38BDF8',
        createdAt: dbUser.createdAt,
        updatedAt: dbUser.updatedAt,
      };
    }
  } catch (dbErr) {
    // Database query failed (e.g. SQLite read-only or not connected on Vercel)
    // Safe to fall through to tier 2
  }

  // Tier 2: In-Memory Registry
  if (inMemoryUsers.has(normalizedEmail)) {
    return inMemoryUsers.get(normalizedEmail)!;
  }

  // Tier 3: /tmp File Store
  const tmpUsers = readTmpUsers();
  if (tmpUsers[normalizedEmail]) {
    const u = tmpUsers[normalizedEmail];
    inMemoryUsers.set(normalizedEmail, u);
    return u;
  }

  // Tier 4: Signed Cookie Token (from incoming request header)
  if (cookieHeader) {
    const token = parseCookie(cookieHeader, 'garuda_usr_reg');
    if (token) {
      const cookieUser = verifyFallbackToken(token);
      if (cookieUser && cookieUser.email.toLowerCase().trim() === normalizedEmail) {
        inMemoryUsers.set(normalizedEmail, cookieUser);
        writeTmpUser(cookieUser);
        return cookieUser;
      }
    }
  }

  // Tier 5: Built-in Users
  const builtin = BUILTIN_USERS.find(u => u.email.toLowerCase().trim() === normalizedEmail);
  if (builtin) {
    return builtin;
  }

  return null;
}

// ── Verify Password ──────────────────────────────────────────────────
export async function verifyUserPassword(user: UserRecord, passwordInput: string): Promise<boolean> {
  // Builtin user convenience: permit 'password123' if matching
  if (
    passwordInput === 'password123' &&
    BUILTIN_USERS.some(u => u.email.toLowerCase() === user.email.toLowerCase())
  ) {
    return true;
  }

  // Bcrypt comparison
  try {
    return await bcrypt.compare(passwordInput, user.password);
  } catch {
    return false;
  }
}

// ── Register User ────────────────────────────────────────────────────
export async function registerUser(name: string, email: string, passwordPlain: string): Promise<{
  user: Omit<UserRecord, 'password'>;
  cookieToken: string;
}> {
  const normalizedEmail = email.toLowerCase().trim();
  const hashedPassword = await bcrypt.hash(passwordPlain, 12);
  const colors = ['#38BDF8', '#34D399', '#A78BFA', '#F472B6', '#FB923C', '#FACC15'];
  const avatarColor = colors[Math.floor(Math.random() * colors.length)];

  const newUser: UserRecord = {
    id: `usr_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    name: name.trim(),
    email: normalizedEmail,
    password: hashedPassword,
    role: 'analyst',
    department: 'Cryptographic SOC',
    avatarColor,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Attempt to write to Prisma if DB is accessible
  try {
    const created = await prisma.user.create({
      data: {
        name: newUser.name,
        email: newUser.email,
        password: newUser.password,
        role: newUser.role,
        department: newUser.department,
        avatarColor: newUser.avatarColor,
      },
    });
    newUser.id = created.id;
  } catch (e) {
    console.warn('[Register] Prisma write unavailable on current environment, saved to fallback stores.');
  }

  // Save to Memory & /tmp
  inMemoryUsers.set(normalizedEmail, newUser);
  writeTmpUser(newUser);

  // Generate signed cookie token
  const cookieToken = createFallbackToken(newUser);

  // Return public user
  const { password: _, ...publicUser } = newUser;
  return { user: publicUser, cookieToken };
}

// ── List All Users ───────────────────────────────────────────────────
export async function listAllUsers(): Promise<Array<Omit<UserRecord, 'password'>>> {
  const userMap = new Map<string, Omit<UserRecord, 'password'>>();

  // Add builtins first
  for (const u of BUILTIN_USERS) {
    const { password: _, ...pub } = u;
    userMap.set(u.email, pub);
  }

  // Add in-memory
  for (const [em, u] of inMemoryUsers.entries()) {
    const { password: _, ...pub } = u;
    userMap.set(em, pub);
  }

  // Add tmp users
  const tmp = readTmpUsers();
  for (const [em, u] of Object.entries(tmp)) {
    const { password: _, ...pub } = u;
    userMap.set(em, pub);
  }

  // Add database users if query succeeds
  try {
    const dbUsers = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        avatarColor: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    for (const dbu of dbUsers) {
      if (dbu.email) {
        userMap.set(dbu.email, {
          id: dbu.id,
          name: dbu.name || 'User',
          email: dbu.email,
          role: dbu.role,
          department: dbu.department || undefined,
          avatarColor: dbu.avatarColor || '#38BDF8',
          createdAt: dbu.createdAt,
          updatedAt: dbu.updatedAt,
        });
      }
    }
  } catch {
    // database not reachable, rely on memory/builtins
  }

  return Array.from(userMap.values());
}
