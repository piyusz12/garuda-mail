'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
import { motion } from 'framer-motion';
import { User, Mail, Lock, Eye, EyeOff, AlertCircle, Loader2, CheckCircle } from 'lucide-react';
import Link from 'next/link';

export default function RegisterPage() {
  const router = useRouter();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const passwordStrength = (() => {
    if (!password) return 0;
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  })();

  const strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][passwordStrength];
  const strengthColor = ['', '#ef4444', '#f59e0b', '#22c55e', '#10b981'][passwordStrength];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const cleanEmail = email.toLowerCase().trim();
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), email: cleanEmail, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Registration failed');
        setLoading(false);
        return;
      }

      setSuccess(true);

      // Auto sign-in with newly created account
      const authResult = await signIn('credentials', {
        email: cleanEmail,
        password,
        redirect: false,
      });

      if (authResult && !authResult.error) {
        router.push('/inbox');
        router.refresh();
      } else {
        // Fallback to login page with pre-filled email
        setTimeout(() => {
          router.push(`/login?registered=true&email=${encodeURIComponent(cleanEmail)}`);
        }, 1200);
      }
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-[var(--color-accent)] opacity-[0.03] rounded-full blur-3xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-[420px] space-y-6 relative"
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
          <h1 className="text-[22px] font-bold text-[var(--color-text-primary)]">Create Account</h1>
          <p className="text-[13px] text-[var(--color-text-muted)] mt-1">Join Garuda Mail</p>
        </div>

        {/* Success */}
        {success && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex items-center gap-2.5 p-4 rounded-lg bg-[rgba(16,185,129,0.1)] border border-[rgba(16,185,129,0.2)]"
          >
            <CheckCircle size={16} className="text-[var(--color-severity-healthy)] flex-shrink-0" />
            <div>
              <div className="text-[13px] font-semibold text-[var(--color-severity-healthy)]">Account created!</div>
              <div className="text-[12px] text-[var(--color-text-muted)]">Redirecting to sign in...</div>
            </div>
          </motion.div>
        )}

        <div className="card p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Name */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Full Name
              </label>
              <div className="relative">
                <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                <input
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="John Analyst"
                  required
                  autoComplete="name"
                  className="w-full h-10 pl-9 pr-4 text-[13px] rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
                />
              </div>
            </div>

            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  autoComplete="email"
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
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Min. 8 characters"
                  required
                  autoComplete="new-password"
                  className="w-full h-10 pl-9 pr-10 text-[13px] rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)] hover:text-[var(--color-text-secondary)]"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              {/* Password strength */}
              {password && (
                <div className="space-y-1">
                  <div className="flex gap-1">
                    {[1, 2, 3, 4].map(i => (
                      <div
                        key={i}
                        className="h-1 flex-1 rounded-full transition-all duration-300"
                        style={{ backgroundColor: i <= passwordStrength ? strengthColor : 'var(--color-surface-3)' }}
                      />
                    ))}
                  </div>
                  <span className="text-[10px]" style={{ color: strengthColor }}>
                    {strengthLabel}
                  </span>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                Confirm Password
              </label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  placeholder="Repeat password"
                  required
                  autoComplete="new-password"
                  className="w-full h-10 pl-9 pr-4 text-[13px] rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)] transition-colors"
                  style={{ borderColor: confirmPassword && confirmPassword !== password ? '#ef4444' : '' }}
                />
              </div>
              {confirmPassword && confirmPassword !== password && (
                <p className="text-[11px] text-[var(--color-severity-critical)]">Passwords do not match</p>
              )}
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
              id="register-submit"
              type="submit"
              disabled={loading || success || !name || !email || !password || !confirmPassword}
              className="w-full h-10 flex items-center justify-center gap-2 text-[13px] font-semibold rounded-md bg-[var(--color-accent)] text-[#0B0D10] hover:bg-[#5ccbfc] disabled:opacity-50 disabled:pointer-events-none transition-all duration-200 active:scale-[0.98]"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  Creating account...
                </>
              ) : success ? (
                <>
                  <CheckCircle size={14} />
                  Account Created!
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-[12px] text-[var(--color-text-muted)]">
          Already have an account?{' '}
          <Link href="/login" className="text-[var(--color-accent)] hover:underline font-medium">
            Sign in
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
