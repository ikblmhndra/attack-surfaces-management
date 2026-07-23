"use client";

import { cn } from "@/lib/utils";

// ── Grade Ring ─────────────────────────────────────────────────
interface GradeRingProps {
  score: number;
  grade: string;
  size?: number;
  strokeWidth?: number;
  className?: string;
}

// Colors resolve through CSS vars (--grade-a..f in globals.css) so the ring
// re-colors correctly in both light and dark theme, not just at mount time.
const GRADE_CONFIG: Record<string, { colorVar: string; label: string }> = {
  A: { colorVar: "--grade-a", label: "Excellent" },
  B: { colorVar: "--grade-b", label: "Good" },
  C: { colorVar: "--grade-c", label: "Fair" },
  D: { colorVar: "--grade-d", label: "Poor" },
  F: { colorVar: "--grade-f", label: "Critical" },
};

export function GradeRing({
  score,
  grade,
  size = 160,
  strokeWidth = 10,
  className,
}: GradeRingProps) {
  const config = GRADE_CONFIG[grade] || GRADE_CONFIG["F"];
  const color = `hsl(var(${config.colorVar}))`;
  const glow = `hsl(var(${config.colorVar}) / 0.3)`;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score));
  const dashOffset = circumference - (pct / 100) * circumference;
  const center = size / 2;

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)}>
      <svg
        width={size}
        height={size}
        style={{ transform: "rotate(-90deg)" }}
        aria-label={`Security grade ${grade}: ${score}/100`}
      >
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Track */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="hsl(var(--border))"
          strokeWidth={strokeWidth}
        />

        {/* Progress arc */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          filter="url(#glow)"
          style={{ transition: "stroke-dashoffset 1s ease-out" }}
        />
      </svg>

      {/* Center content */}
      <div
        className="absolute inset-0 flex flex-col items-center justify-center"
        style={{ textAlign: "center" }}
      >
        <span
          className="font-black leading-none"
          style={{
            fontSize: size * 0.28,
            color,
            textShadow: `0 0 20px ${glow}`,
          }}
        >
          {grade}
        </span>
        <span
          className="font-mono tabular-nums text-muted-foreground"
          style={{ fontSize: size * 0.13 }}
        >
          {score}/100
        </span>
        <span
          className="text-muted-foreground"
          style={{ fontSize: size * 0.09 }}
        >
          {config.label}
        </span>
      </div>
    </div>
  );
}

// ── Severity Badge ─────────────────────────────────────────────
interface SeverityBadgeProps {
  severity: string;
  compact?: boolean;
  className?: string;
}

// bg/text/border all key off the same theme-aware token (critical/high/
// medium/low/info -- see tailwind.config.ts + globals.css), so these badges
// stay legible in both themes instead of hardcoding a dark-mode-only shade.
const SEVERITY_CONFIG = {
  critical: { label: "Critical", short: "CRIT", cls: "bg-critical/10 text-critical border-critical/30" },
  high: { label: "High", short: "HIGH", cls: "bg-high/10 text-high border-high/30" },
  medium: { label: "Medium", short: "MED", cls: "bg-medium/10 text-medium border-medium/30" },
  low: { label: "Low", short: "LOW", cls: "bg-low/10 text-low border-low/30" },
  info: { label: "Info", short: "INFO", cls: "bg-info/10 text-info border-info/30" },
};

export function SeverityBadge({ severity, compact = false, className }: SeverityBadgeProps) {
  const cfg = SEVERITY_CONFIG[severity?.toLowerCase() as keyof typeof SEVERITY_CONFIG]
    || SEVERITY_CONFIG.info;

  if (compact) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-bold border",
          cfg.cls,
          className,
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0 bg-current" />
        {cfg.short}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-semibold border",
        cfg.cls,
        className,
      )}
    >
      <span className="w-2 h-2 rounded-full flex-shrink-0 bg-current" />
      {cfg.label}
    </span>
  );
}

// ── Status Badge ───────────────────────────────────────────────
interface StatusBadgeProps {
  status: string;
  className?: string;
}

// Reuses the same theme-aware severity/grade tokens instead of hardcoded
// emerald/gray/red/yellow shades, so status pills adapt with the rest of
// the badge system.
const STATUS_CONFIG: Record<string, { label: string; cls: string; pulse?: boolean }> = {
  active:         { label: "Active",          cls: "bg-grade-a/10 text-grade-a border-grade-a/30" },
  inactive:       { label: "Inactive",        cls: "bg-info/10 text-info border-info/30" },
  open:           { label: "Open",            cls: "bg-critical/10 text-critical border-critical/30" },
  resolved:       { label: "Resolved",        cls: "bg-grade-a/10 text-grade-a border-grade-a/30" },
  false_positive: { label: "False Positive",  cls: "bg-info/10 text-info border-info/30" },
  accepted:       { label: "Risk Accepted",   cls: "bg-medium/10 text-medium border-medium/30" },
  running:        { label: "Running",         cls: "bg-brand-500/10 text-brand-400 border-brand-500/30", pulse: true },
  completed:      { label: "Completed",       cls: "bg-grade-a/10 text-grade-a border-grade-a/30" },
  failed:         { label: "Failed",          cls: "bg-critical/10 text-critical border-critical/30" },
  pending:        { label: "Pending",         cls: "bg-medium/10 text-medium border-medium/30" },
  queued:         { label: "Queued",          cls: "bg-medium/10 text-medium border-medium/30" },
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const cfg = STATUS_CONFIG[status?.toLowerCase()] || {
    label: status,
    cls: "bg-info/10 text-info border-info/30",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border",
        cfg.cls,
        className,
      )}
    >
      <span
        className={cn(
          "w-1.5 h-1.5 rounded-full flex-shrink-0 bg-current",
          cfg.pulse && "animate-pulse",
        )}
      />
      {cfg.label}
    </span>
  );
}

// ── Score Pill ─────────────────────────────────────────────────
interface ScorePillProps {
  score: number;
  showGrade?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
}

function scoreToGrade(s: number) {
  if (s >= 90) return "A";
  if (s >= 75) return "B";
  if (s >= 60) return "C";
  if (s >= 40) return "D";
  return "F";
}

export function ScorePill({ score, showGrade = true, size = "md", className }: ScorePillProps) {
  const grade = scoreToGrade(score);
  const config = GRADE_CONFIG[grade];

  const sizes = {
    sm: "text-xs px-1.5 py-0.5",
    md: "text-sm px-2 py-1",
    lg: "text-base px-3 py-1.5",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-lg font-bold border tabular-nums",
        sizes[size],
        className,
      )}
      style={{
        color: `hsl(var(${config.colorVar}))`,
        backgroundColor: `hsl(var(${config.colorVar}) / 0.1)`,
        borderColor: `hsl(var(${config.colorVar}) / 0.3)`,
      }}
    >
      {score}
      {showGrade && <span className="opacity-70">{grade}</span>}
    </span>
  );
}

// ── CVE Badge ──────────────────────────────────────────────────
export function CVEBadge({ cveId, className }: { cveId: string; className?: string }) {
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-mono",
        "bg-purple-500/10 text-purple-700 dark:text-purple-400 border border-purple-500/20",
        "hover:bg-purple-500/20 transition-colors",
        className,
      )}
    >
      {cveId}
    </a>
  );
}

// ── KEV Badge (CISA Known Exploited Vulnerabilities) ────────────
interface KEVBadgeProps {
  knownRansomware?: boolean;
  compact?: boolean;
  className?: string;
}

export function KEVBadge({ knownRansomware, compact = false, className }: KEVBadgeProps) {
  return (
    <span
      title={
        knownRansomware
          ? "CISA KEV: confirmed active exploitation, known ransomware use"
          : "CISA KEV: confirmed active exploitation in the wild"
      }
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-bold border",
        "bg-critical/15 text-critical border-critical/40",
        className,
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse flex-shrink-0" />
      {compact ? "KEV" : knownRansomware ? "Actively Exploited · Ransomware" : "Actively Exploited"}
    </span>
  );
}

// ── EPSS Badge ───────────────────────────────────────────────────
export function EPSSBadge({ score, className }: { score: number; className?: string }) {
  const pct = Math.round(score * 100);
  const high = score >= 0.5;
  return (
    <span
      title={`EPSS: ${pct}% predicted probability of exploitation in the next 30 days (FIRST.org)`}
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-mono border",
        high
          ? "bg-high/10 text-high border-high/30"
          : "bg-info/10 text-info border-info/30",
        className,
      )}
    >
      EPSS {pct}%
    </span>
  );
}

// ── Confidence Indicator ────────────────────────────────────────
const CONFIDENCE_CONFIG: Record<string, { label: string; cls: string }> = {
  high: {
    label: "High confidence — the CVE template's expected product matches this asset's fingerprinted tech stack",
    cls: "text-grade-a",
  },
  low: {
    label: "Low confidence — the CVE template's expected product does not match this asset's fingerprinted tech stack (still reported, not dropped — worth a second look)",
    cls: "text-medium",
  },
};

export function ConfidenceIndicator({ confidence, className }: { confidence?: string; className?: string }) {
  if (!confidence || confidence === "unknown") return null;
  const cfg = CONFIDENCE_CONFIG[confidence];
  if (!cfg) return null;
  return (
    <span title={cfg.label} className={cn("inline-flex items-center gap-1", cfg.cls, className)}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0 bg-current" />
      <span className="text-[10px] uppercase tracking-wide font-semibold">
        {confidence} conf.
      </span>
    </span>
  );
}
