'use client';

import { useState, useEffect, use, useCallback } from 'react';
import { motion } from 'framer-motion';
import { CheckCircle2, Shield, RefreshCw, HeartHandshake, AlertTriangle, RotateCcw } from 'lucide-react';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

type UnsubStatus = 'loading' | 'success' | 'error' | 'resubscribed';

export default function UnsubscribePage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = use(params);

  const [status, setStatus] = useState<UnsubStatus>('loading');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);
  const [selectedReason, setSelectedReason] = useState<string>('');

  const executeOptOut = useCallback(async () => {
    setStatus('loading');
    setErrorMessage('');
    try {
      const res = await fetch(`/api/unsubscribe/${token}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.success) {
        setEmail(data.email || 'your email address');
        setStatus('success');
      } else {
        setStatus('error');
        setErrorMessage(data.error || 'Invalid or expired unsubscribe signature.');
      }
    } catch {
      setStatus('error');
      setErrorMessage('Network connection lost while processing one-click opt out.');
    }
  }, [token]);

  useEffect(() => {
    executeOptOut();
  }, [executeOptOut]);

  const handleResubscribe = async () => {
    try {
      const res = await fetch(`/api/unsubscribe/${token}`, { method: 'PATCH' });
      if (res.ok) {
        setStatus('resubscribed');
      }
    } catch {}
  };

  const handleFeedbackSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFeedbackSubmitted(true);
  };

  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] flex flex-col justify-center items-center p-4">
      <motion.div {...fadeUp} className="card-elevated max-w-lg w-full p-8 space-y-6 text-center">
        {/* Garuda Mail Logo Mark */}
        <div className="flex items-center justify-center gap-2">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center text-white font-bold text-lg shadow-md">
            G
          </div>
          <span className="font-bold text-xl text-[var(--color-text-primary)]">Garuda Mail</span>
        </div>

        {status === 'loading' && (
          <div className="py-8 space-y-3">
            <RefreshCw className="w-8 h-8 text-sky-500 animate-spin mx-auto" />
            <p className="text-sm text-[var(--color-text-dim)]">Processing one-click opt-out...</p>
          </div>
        )}

        {status === 'error' && (
          <div className="py-4 space-y-4">
            <div className="w-12 h-12 rounded-full bg-rose-500/15 text-rose-600 dark:text-rose-400 flex items-center justify-center mx-auto">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h2 className="text-lg font-bold text-[var(--color-text-primary)]">Unable to Process Opt-Out</h2>
              <p className="text-sm text-[var(--color-text-dim)]">{errorMessage}</p>
            </div>
            <button
              type="button"
              onClick={executeOptOut}
              className="btn btn-secondary px-4 py-2 text-xs font-semibold inline-flex items-center gap-2"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Retry Unsubscribe
            </button>
          </div>
        )}

        {status === 'resubscribed' && (
          <div className="py-4 space-y-3">
            <div className="w-12 h-12 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 flex items-center justify-center mx-auto">
              <HeartHandshake className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-[var(--color-text-primary)]">Welcome Back!</h2>
            <p className="text-sm text-[var(--color-text-dim)]">
              Your subscription for <span className="font-semibold text-[var(--color-text-primary)]">{email}</span> has been restored. You will continue to receive communications.
            </p>
          </div>
        )}

        {status === 'success' && (
          <div className="space-y-4">
            <div className="w-12 h-12 rounded-full bg-sky-500/15 text-sky-600 dark:text-sky-400 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6" />
            </div>

            <div className="space-y-1">
              <h2 className="text-xl font-bold text-[var(--color-text-primary)]">
                You Have Been Unsubscribed
              </h2>
              <p className="text-sm text-[var(--color-text-dim)]">
                <span className="font-mono text-[var(--color-text-primary)]">{email}</span> has been removed from this mailing list in accordance with RFC 8058 &amp; CAN-SPAM regulations.
              </p>
            </div>

            {/* Accidental Click Recovery */}
            <div className="p-3.5 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Did you click this by mistake?</span>
              <button
                type="button"
                onClick={handleResubscribe}
                className="btn btn-secondary px-3 py-1 font-semibold text-sky-600 dark:text-sky-400"
              >
                Re-subscribe
              </button>
            </div>

            {/* Optional Post-Opt-Out Survey (Strictly after opt-out, never blocking) */}
            {!feedbackSubmitted ? (
              <form onSubmit={handleFeedbackSubmit} className="pt-2 border-t border-[var(--color-border)] space-y-3 text-left">
                <p className="text-xs font-semibold text-[var(--color-text-dim)]">
                  Optional: Help us improve by letting us know why you left:
                </p>
                <div className="space-y-2">
                  {[
                    'I receive too many emails from this sender',
                    'The content is no longer relevant to me',
                    'I never signed up for this mailing list',
                    'Technical issues or formatting glitches',
                  ].map((reason) => (
                    <label key={reason} className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)] cursor-pointer">
                      <input
                        type="radio"
                        name="reason"
                        value={reason}
                        checked={selectedReason === reason}
                        onChange={(e) => setSelectedReason(e.target.value)}
                        className="text-sky-600 focus:ring-sky-500 h-3.5 w-3.5"
                      />
                      <span>{reason}</span>
                    </label>
                  ))}
                </div>
                <button
                  type="submit"
                  disabled={!selectedReason}
                  className="btn btn-secondary w-full py-1.5 text-xs font-semibold disabled:opacity-40"
                >
                  Submit Feedback
                </button>
              </form>
            ) : (
              <p className="text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                Thank you for your feedback! It helps us improve our communications.
              </p>
            )}
          </div>
        )}

        <div className="pt-4 border-t border-[var(--color-border)] text-xs text-[var(--color-text-muted)] flex items-center justify-center gap-1">
          <Shield className="w-3.5 h-3.5 text-emerald-500" />
          <span>Garuda Mail Cryptographic Security &amp; Compliance Engine</span>
        </div>
      </motion.div>
    </div>
  );
}

