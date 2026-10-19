'use client';

import { useState, useEffect, Suspense } from 'react';
import { getSession, signIn } from 'next-auth/react';
import { useRouter, useSearchParams } from 'next/navigation';
import { motion } from 'framer-motion';
import { Mail, Lock, Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react';
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

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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
      setError('Invalid email or password. Please try again.');
    } else {
      const session = await getSession();
      const role = session?.user?.role || 'user';
      router.push(getProtectedRouteForRole(role));
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
        className="w-full max-w-[400px] space-y-6 relative"
      >
        {/* Logo */}
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-[var(--color-surface-2)] border border-[var(--color-border)] mb-4">
            <svg viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-8 h-8">
              <path d="M14 2L24 8V20L14 26L4 20V8L14 2Z" stroke="var(--color-accent)" strokeWidth="1.5" fill="none" />
              <path d="M14 6L20 9.5V16.5L14 20L8 16.5V9.5L14 6Z" stroke="var(--color-accent)" strokeWidth="1" fill="var(--color-accent-dim)" />
              <path d="M14 10L17 11.75V15.25L14 17L11 15.25V11.75L14 10Z" fill="var(--color-accent)" />
            </svg>
          </div>
          <h1 className="text-[22px] font-bold text-[var(--color-text-primary)]">Garuda Mail</h1>
          <p className="text-[13px] text-[var(--color-text-muted)] mt-1">
            AI-Assisted Email Security Platform
          </p>
        </div>

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
          <h2 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-5">
            Sign in to your account
          </h2>

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
