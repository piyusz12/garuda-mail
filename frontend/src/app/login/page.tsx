'use client';

import { useState, useEffect, Suspense, useCallback } from 'react';
import { getSession, signIn } from 'next-auth/react';
import { useRouter, useSearchParams } from 'next/navigation';
import { motion } from 'framer-motion';
import { Mail, Lock, Eye, EyeOff, AlertCircle, Loader2, Zap, ShieldAlert, Shield, User, ArrowRight } from 'lucide-react';
import Link from 'next/link';
import { getProtectedRouteForRole } from '@/lib/roles';

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[var(--color-surface-0)] flex items-center justify-center text-[var(--color-text-dim)]">Loading Garuda Mail...</div>}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const rawCallback = searchParams.get('callbackUrl') || '/inbox';
  const callbackUrl = rawCallback.startsWith('/') ? rawCallback : '/inbox';
  const registered = searchParams.get('registered') === 'true';
  const instantParam = searchParams.get('instant');

  const urlError = searchParams.get('error');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [instantLoading, setInstantLoading] = useState(false);
  const [error, setError] = useState(
    urlError === 'admin_required'
      ? 'Administrator privileges required. Use Instant Admin Login below.'
      : urlError === 'account_suspended'
      ? 'This account has been suspended by an administrator.'
      : urlError === 'forbidden'
      ? 'Access forbidden. You do not have permission to view that resource.'
      : ''
  );

  const handleInstantLogin = useCallback(async (targetEmail = 'admin@garudamail.local', targetPass = 'GarudaAdmin2026!') => {
    setInstantLoading(true);
    setError('');

    try {
      const result = await signIn('credentials', {
        email: targetEmail,
        password: targetPass,
        redirect: false,
      });

      if (result?.error) {
        setError('Instant login failed: ' + result.error);
        setInstantLoading(false);
      } else {
        window.location.href = targetEmail.includes('admin') ? '/admin/dashboard' : '/user/dashboard';
      }
    } catch (err: any) {
      setError(err?.message || 'Instant login failed');
      setInstantLoading(false);
    }
  }, []);

  // Handle URL parameter ?instant=admin for direct 1-click execution
  useEffect(() => {
    if (instantParam === 'admin') {
      handleInstantLogin('admin@garudamail.local', 'GarudaAdmin2026!');
    }
  }, [instantParam, handleInstantLogin]);

  // Clear any auto-populated credentials on mount for a 100% fresh login
  useEffect(() => {
    setEmail('');
    setPassword('');
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    setLoading(true);
    setError('');

    const result = await signIn('credentials', {
      email: email.toLowerCase().trim(),
      password,
      redirect: false,
    });

    setLoading(false);

    if (result?.error) {
      if (result.error.toLowerCase().includes('suspended')) {
        setError('This account is suspended. Please contact your system administrator.');
      } else {
        setError('Invalid email or password. Please try again.');
      }
    } else {
      const session = await getSession();
      const role = session?.user?.role || 'user';
      const targetRoute = getProtectedRouteForRole(role);
      
      // If callbackUrl matches the role's allowed scope, honor it, otherwise send to role dashboard
      if (role === 'admin' && callbackUrl.startsWith('/admin')) {
        router.push(callbackUrl);
      } else if (role !== 'admin' && callbackUrl.startsWith('/user')) {
        router.push(callbackUrl);
      } else {
        router.push(targetRoute);
      }
      router.refresh();
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Multi-Color Ambient Glows */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden="true">
        <div className="absolute -top-40 -left-40 w-[550px] h-[550px] bg-indigo-500/10 rounded-full blur-[140px]" />
        <div className="absolute top-1/3 -right-40 w-[500px] h-[500px] bg-sky-500/10 rounded-full blur-[140px]" />
        <div className="absolute -bottom-40 left-1/3 w-[600px] h-[600px] bg-purple-600/10 rounded-full blur-[160px]" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-[420px] space-y-5 relative"
      >
        {/* Logo */}
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-[var(--color-surface-2)] border border-[var(--color-border)] mb-3">
            <svg viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-8 h-8">
              <path d="M14 2L24 8V20L14 26L4 20V8L14 2Z" stroke="var(--color-accent)" strokeWidth="1.5" fill="none" />
              <path d="M14 6L20 9.5V16.5L14 20L8 16.5V9.5L14 6Z" stroke="var(--color-accent)" strokeWidth="1" fill="var(--color-accent-dim)" />
              <path d="M14 10L17 11.75V15.25L14 17L11 15.25V11.75L14 10Z" fill="var(--color-accent)" />
            </svg>
          </div>
          <h1 className="text-[22px] font-bold text-[var(--color-text-primary)]">Garuda Mail</h1>
          <p className="text-[13px] text-[var(--color-text-muted)] mt-0.5">
            Cryptographic Forensics & Security Intelligence
          </p>
        </div>

        {/* ── HIGHLIGHTED: Instant Admin Login One-Click Hero Button ── */}
        <motion.div
          whileHover={{ scale: 1.01 }}
          whileTap={{ scale: 0.99 }}
          className="relative p-[1px] rounded-2xl bg-gradient-to-r from-rose-500 via-amber-500 to-indigo-600 shadow-xl shadow-rose-950/30 overflow-hidden"
        >
          <button
            id="instant-admin-login-button"
            type="button"
            onClick={() => handleInstantLogin('admin@garudamail.local', 'GarudaAdmin2026!')}
            disabled={instantLoading || loading}
            className="w-full p-4 rounded-[15px] bg-[var(--color-surface-1)] hover:bg-[var(--color-surface-2)] transition-all flex items-center justify-between text-left group cursor-pointer disabled:opacity-50"
          >
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-500 to-amber-600 flex items-center justify-center text-white shadow-md shadow-rose-500/25 flex-shrink-0 group-hover:scale-105 transition-transform">
                {instantLoading ? (
                  <Loader2 size={18} className="animate-spin text-white" />
                ) : (
                  <Zap size={20} className="text-yellow-200 fill-yellow-200 animate-pulse" />
                )}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[14px] font-bold text-white group-hover:text-rose-200 transition-colors">
                    Instant Admin Login
                  </span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] font-extrabold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    1-Click
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 truncate">
                  Direct access to Cryptographic SOC & Forensics Console
                </p>
              </div>
            </div>
            <ArrowRight size={16} className="text-rose-400 group-hover:translate-x-1 transition-transform flex-shrink-0 ml-2" />
          </button>
        </motion.div>

        {/* Success message after registration */}
        {registered && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex items-center gap-2.5 p-3 rounded-lg bg-[rgba(16,185,129,0.1)] border border-[rgba(16,185,129,0.2)] text-[13px] text-[var(--color-severity-healthy)]"
          >
            <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-severity-healthy)] flex-shrink-0" />
            Account created! Sign in to continue.
          </motion.div>
        )}

        {/* Form Card */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-[14px] font-semibold text-[var(--color-text-primary)]">
              Or sign in with credentials
            </h2>
            <span className="text-[11px] text-[var(--color-text-dim)]">Standard Auth</span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off" suppressHydrationWarning>
            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                <input
                  id="email"
                  name="email_fresh_input"
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="Enter your email address"
                  required
                  autoComplete="off"
                  data-lpignore="true"
                  suppressHydrationWarning
                  className="w-full h-10 pl-9 pr-4 text-[13px] rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                <input
                  id="password"
                  name="password_fresh_input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  autoComplete="new-password"
                  data-lpignore="true"
                  suppressHydrationWarning
                  className="w-full h-10 pl-9 pr-10 text-[13px] rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  suppressHydrationWarning
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)] hover:text-[var(--color-text-secondary)] transition-colors"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex items-center gap-2 p-3 rounded-md bg-[var(--color-severity-critical-bg)] border border-[rgba(239,68,68,0.2)] text-[12px] text-[var(--color-severity-critical)]"
              >
                <AlertCircle size={13} className="flex-shrink-0" />
                {error}
              </motion.div>
            )}

            {/* Submit */}
            <button
              id="login-submit"
              type="submit"
              suppressHydrationWarning
              disabled={loading || !email || !password}
              className="w-full h-10 flex items-center justify-center gap-2 text-[13px] font-semibold rounded-xl bg-gradient-to-r from-sky-500 via-indigo-500 to-purple-600 hover:from-sky-400 hover:via-indigo-400 hover:to-purple-500 text-white shadow-lg shadow-indigo-500/25 disabled:opacity-50 disabled:pointer-events-none transition-all duration-200 active:scale-[0.98] border border-white/20 cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  Signing in...
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Quick Demo Accounts Selection */}
          <div className="mt-5 pt-4 border-t border-[var(--color-border)]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-dim)] flex items-center gap-1 mb-2">
              <Zap size={11} className="text-amber-400" />
              1-Click Demo Profiles
            </span>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleInstantLogin('admin@garudamail.local', 'GarudaAdmin2026!')}
                disabled={instantLoading || loading}
                className="p-2 rounded-lg bg-[var(--color-surface-2)] hover:bg-rose-500/10 border border-[var(--color-border)] hover:border-rose-500/30 text-left transition-all group cursor-pointer disabled:opacity-50"
              >
                <div className="text-[11px] font-semibold text-rose-400 flex items-center gap-1">
                  <span>👑 Admin</span>
                </div>
                <div className="text-[9px] text-[var(--color-text-dim)] truncate mt-0.5">
                  Full SOC Access
                </div>
              </button>

              <button
                type="button"
                onClick={() => handleInstantLogin('officer@garudamail.local', 'GarudaAdmin2026!')}
                disabled={instantLoading || loading}
                className="p-2 rounded-lg bg-[var(--color-surface-2)] hover:bg-sky-500/10 border border-[var(--color-border)] hover:border-sky-500/30 text-left transition-all group cursor-pointer disabled:opacity-50"
              >
                <div className="text-[11px] font-semibold text-sky-400 flex items-center gap-1">
                  <span>🛡️ Officer</span>
                </div>
                <div className="text-[9px] text-[var(--color-text-dim)] truncate mt-0.5">
                  Forensic Analyst
                </div>
              </button>

              <button
                type="button"
                onClick={() => handleInstantLogin('user@garudamail.local', 'GarudaAdmin2026!')}
                disabled={instantLoading || loading}
                className="p-2 rounded-lg bg-[var(--color-surface-2)] hover:bg-emerald-500/10 border border-[var(--color-border)] hover:border-emerald-500/30 text-left transition-all group cursor-pointer disabled:opacity-50"
              >
                <div className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1">
                  <span>👤 Operative</span>
                </div>
                <div className="text-[9px] text-[var(--color-text-dim)] truncate mt-0.5">
                  Standard E2EE
                </div>
              </button>
            </div>
          </div>
        </div>

        {/* Register link */}
        <p className="text-center text-[12px] text-[var(--color-text-muted)]">
          Don&apos;t have an account?{' '}
          <Link href="/register" className="text-[var(--color-accent)] hover:underline font-medium">
            Create account
          </Link>
        </p>

        {/* Footer */}
        <p className="text-center text-[10px] text-[var(--color-text-dim)]">
          Garuda Mail — Cryptographic Forensics & Security Intelligence
        </p>
      </motion.div>
    </div>
  );
}
