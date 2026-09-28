import clsx from 'clsx';
import type { Severity } from '@/types';

/* ─── Severity Badge ────────────────────────────────────────────── */

export function SeverityBadge({ severity, size = 'sm' }: { severity: Severity; size?: 'xs' | 'sm' | 'md' }) {
  const classes = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    informational: 'badge-info',
  }[severity];

  const sizeClasses = {
    xs: 'px-1.5 py-0 text-[9px]',
    sm: 'px-2 py-0.5 text-[10px]',
    md: 'px-2.5 py-1 text-[11px]',
  }[size];

  return (
    <span className={clsx(classes, sizeClasses, 'inline-flex items-center font-semibold uppercase tracking-wider rounded')}>
      {severity}
    </span>
  );
}

/* ─── Status Badge ──────────────────────────────────────────────── */

export function StatusBadge({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    connected: 'badge-healthy',
    completed: 'badge-healthy',
    valid: 'badge-healthy',
    open: 'badge-critical',
    processing: 'text-[var(--color-accent)] bg-[var(--color-accent-dim)] border border-[rgba(56,189,248,0.15)]',
    analyzing: 'text-[var(--color-accent)] bg-[var(--color-accent-dim)] border border-[rgba(56,189,248,0.15)]',
    expiring: 'badge-high',
    expired: 'badge-critical',
    weak: 'badge-high',
    degraded: 'badge-high',
    offline: 'badge-critical',
    failed: 'badge-critical',
    ready: 'badge-healthy',
    reviewed: 'badge-low',
    mitigated: 'badge-healthy',
  };

  return (
    <span className={clsx(
      colorMap[status.toLowerCase()] || 'badge-info',
      'inline-flex items-center px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded'
    )}>
      {status}
    </span>
  );
}

/* ─── Metric Card ───────────────────────────────────────────────── */

export function MetricCard({
  label, value, sub, accent, className,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: 'critical' | 'high' | 'accent' | 'healthy';
  className?: string;
}) {
  const accentColor = {
    critical: 'text-[var(--color-severity-critical)]',
    high: 'text-[var(--color-severity-high)]',
    accent: 'text-[var(--color-accent)]',
    healthy: 'text-[var(--color-severity-healthy)]',
  }[accent || 'accent'];

  return (
    <div className={clsx('card p-4 card-hover', className)}>
      <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium mb-1.5">
        {label}
      </div>
      <div className={clsx('text-2xl font-bold tabular-nums', accentColor)}>
        {value}
      </div>
      {sub && (
        <div className="text-[11px] text-[var(--color-text-dim)] mt-0.5">{sub}</div>
      )}
    </div>
  );
}

/* ─── Risk Score Indicator ──────────────────────────────────────── */

export function RiskScore({ score, size = 'lg' }: { score: number; size?: 'sm' | 'md' | 'lg' }) {
  const radius = size === 'lg' ? 54 : size === 'md' ? 38 : 24;
  const stroke = size === 'lg' ? 6 : size === 'md' ? 4 : 3;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const svgSize = (radius + stroke) * 2;

  const color = score >= 75 ? 'var(--color-severity-critical)'
    : score >= 50 ? 'var(--color-severity-high)'
    : score >= 25 ? 'var(--color-severity-medium)'
    : 'var(--color-severity-healthy)';

  const label = score >= 75 ? 'Critical' : score >= 50 ? 'High' : score >= 25 ? 'Medium' : 'Low';
  const fontSize = size === 'lg' ? 'text-3xl' : size === 'md' ? 'text-xl' : 'text-sm';

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: svgSize, height: svgSize }}>
        <svg width={svgSize} height={svgSize} className="-rotate-90">
          <circle
            cx={radius + stroke}
            cy={radius + stroke}
            r={radius}
            fill="none"
            stroke="var(--color-surface-3)"
            strokeWidth={stroke}
          />
          <circle
            cx={radius + stroke}
            cy={radius + stroke}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={clsx(fontSize, 'font-bold tabular-nums')} style={{ color }}>{score}</span>
          {size !== 'sm' && (
            <span className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">/100</span>
          )}
        </div>
      </div>
      {size === 'lg' && (
        <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color }}>{label} Risk</span>
      )}
    </div>
  );
}

/* ─── Posture Bar ───────────────────────────────────────────────── */

export function PostureBar({ label, score, status, detail }: {
  label: string;
  score: number;
  status: 'good' | 'warning' | 'critical';
  detail: string;
}) {
  const barColor = {
    good: 'bg-[var(--color-severity-healthy)]',
    warning: 'bg-[var(--color-severity-high)]',
    critical: 'bg-[var(--color-severity-critical)]',
  }[status];

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[12px] font-medium text-[var(--color-text-secondary)]">{label}</span>
        <span className="text-[12px] font-bold tabular-nums text-[var(--color-text-primary)]">{score}%</span>
      </div>
      <div className="h-1.5 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
        <div
          className={clsx(barColor, 'h-full rounded-full transition-all duration-700 ease-out')}
          style={{ width: `${score}%` }}
        />
      </div>
      <div className="text-[10px] text-[var(--color-text-dim)]">{detail}</div>
    </div>
  );
}

/* ─── Finding Severity Distribution ─────────────────────────────── */

export function SeverityDistribution({ critical, high, medium, low, informational }: {
  critical: number; high: number; medium: number; low: number; informational: number;
}) {
  const total = critical + high + medium + low + informational;
  if (total === 0) return null;

  const segments = [
    { count: critical, color: 'var(--color-severity-critical)', label: 'Critical' },
    { count: high, color: 'var(--color-severity-high)', label: 'High' },
    { count: medium, color: 'var(--color-severity-medium)', label: 'Medium' },
    { count: low, color: 'var(--color-severity-low)', label: 'Low' },
    { count: informational, color: 'var(--color-severity-info)', label: 'Info' },
  ].filter(s => s.count > 0);

  return (
    <div className="space-y-2">
      {/* Bar */}
      <div className="flex h-2 rounded-full overflow-hidden gap-px">
        {segments.map((seg, i) => (
          <div
            key={i}
            className="h-full first:rounded-l-full last:rounded-r-full transition-all duration-500"
            style={{ width: `${(seg.count / total) * 100}%`, backgroundColor: seg.color }}
          />
        ))}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-4 flex-wrap">
        {segments.map((seg, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: seg.color }} />
            <span className="text-[11px] text-[var(--color-text-muted)]">{seg.label}</span>
            <span className="text-[11px] font-semibold text-[var(--color-text-secondary)] tabular-nums">{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Empty State ───────────────────────────────────────────────── */

export function EmptyState({ icon: Icon, title, description, action }: {
  icon: React.ElementType;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-12 h-12 rounded-xl bg-[var(--color-surface-2)] border border-default flex items-center justify-center mb-4">
        <Icon size={24} className="text-[var(--color-text-dim)]" />
      </div>
      <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">{title}</h3>
      <p className="text-[13px] text-[var(--color-text-muted)] max-w-md mb-4">{description}</p>
      {action}
    </div>
  );
}
