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

const GRADE_CONFIG: Record<string, { color: string; glow: string; label: string }> = {
  A: { color: "#10b981", glow: "rgba(16,185,129,0.3)", label: "Excellent" },
  B: { color: "#3b82f6", glow: "rgba(59,130,246,0.3)", label: "Good" },
  C: { color: "#eab308", glow: "rgba(234,179,8,0.3)",  label: "Fair" },
  D: { color: "#f97316", glow: "rgba(249,115,22,0.3)", label: "Poor" },
  F: { color: "#ef4444", glow: "rgba(239,68,68,0.3)",  label: "Critical" },
};

export function GradeRing({
  score,
  grade,
  size = 160,
  strokeWidth = 10,
  className,
}: GradeRingProps) {
  const config = GRADE_CONFIG[grade] || GRADE_CONFIG["F"];
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
          stroke="hsl(217 33% 14%)"
          strokeWidth={strokeWidth}
        />

        {/* Progress arc */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={config.color}
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
            color: config.color,
            textShadow: `0 0 20px ${config.glow}`,
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

const SEVERITY_CONFIG = {
  critical: {
    label: "Critical",
    short: "CRIT",
    dot: "#ef4444",
    bg: "bg-red-500/10",
    text: "text-red-400",
    border: "border-red-500/30",
  },
  high: {
    label: "High",
    short: "HIGH",
    dot: "#f97316",
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    border: "border-orange-500/30",
  },
  medium: {
    label: "Medium",
    short: "MED",
    dot: "#eab308",
    bg: "bg-yellow-500/10",
    text: "text-yellow-400",
    border: "border-yellow-500/30",
  },
  low: {
    label: "Low",
    short: "LOW",
    dot: "#3b82f6",
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    border: "border-blue-500/30",
  },
  info: {
    label: "Info",
    short: "INFO",
    dot: "#6b7280",
    bg: "bg-gray-500/10",
    text: "text-gray-400",
    border: "border-gray-500/30",
  },
};

export function SeverityBadge({ severity, compact = false, className }: SeverityBadgeProps) {
  const cfg = SEVERITY_CONFIG[severity?.toLowerCase() as keyof typeof SEVERITY_CONFIG]
    || SEVERITY_CONFIG.info;

  if (compact) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-bold border",
          cfg.bg, cfg.text, cfg.border,
          className,
        )}
      >
        <span
          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
          style={{ backgroundColor: cfg.dot }}
        />
        {cfg.short}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-semibold border",
        cfg.bg, cfg.text, cfg.border,
        className,
      )}
    >
      <span
        className="w-2 h-2 rounded-full flex-shrink-0"
        style={{ backgroundColor: cfg.dot }}
      />
      {cfg.label}
    </span>
  );
}

// ── Status Badge ───────────────────────────────────────────────
interface StatusBadgeProps {
  status: string;
  className?: string;
}

const STATUS_CONFIG: Record<string, { label: string; bg: string; text: string; border: string; dot: string }> = {
  active:         { label: "Active",          dot: "#10b981", bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/20" },
  inactive:       { label: "Inactive",        dot: "#6b7280", bg: "bg-gray-500/10",    text: "text-gray-400",    border: "border-gray-500/20"    },
  open:           { label: "Open",            dot: "#ef4444", bg: "bg-red-500/10",     text: "text-red-400",     border: "border-red-500/20"     },
  resolved:       { label: "Resolved",        dot: "#10b981", bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/20" },
  false_positive: { label: "False Positive",  dot: "#6b7280", bg: "bg-gray-500/10",    text: "text-gray-400",    border: "border-gray-500/20"    },
  accepted:       { label: "Risk Accepted",   dot: "#eab308", bg: "bg-yellow-500/10",  text: "text-yellow-400",  border: "border-yellow-500/20"  },
  running:        { label: "Running",         dot: "#0ea5e9", bg: "bg-brand-500/10",   text: "text-brand-400",   border: "border-brand-500/20"   },
  completed:      { label: "Completed",       dot: "#10b981", bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/20" },
  failed:         { label: "Failed",          dot: "#ef4444", bg: "bg-red-500/10",     text: "text-red-400",     border: "border-red-500/20"     },
  pending:        { label: "Pending",         dot: "#eab308", bg: "bg-yellow-500/10",  text: "text-yellow-400",  border: "border-yellow-500/20"  },
  queued:         { label: "Queued",          dot: "#eab308", bg: "bg-yellow-500/10",  text: "text-yellow-400",  border: "border-yellow-500/20"  },
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const cfg = STATUS_CONFIG[status?.toLowerCase()] || {
    label: status,
    dot: "#6b7280",
    bg: "bg-gray-500/10",
    text: "text-gray-400",
    border: "border-gray-500/20",
  };

  const isRunning = status === "running";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border",
        cfg.bg, cfg.text, cfg.border,
        className,
      )}
    >
      <span
        className={cn(
          "w-1.5 h-1.5 rounded-full flex-shrink-0",
          isRunning && "animate-pulse",
        )}
        style={{ backgroundColor: cfg.dot }}
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
  const cfg = GRADE_CONFIG[grade];

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
        color: cfg.color,
        backgroundColor: `${cfg.color}15`,
        borderColor: `${cfg.color}30`,
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
        "bg-purple-500/10 text-purple-400 border border-purple-500/20",
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
        "bg-red-600/15 text-red-400 border-red-600/40",
        className,
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse flex-shrink-0" />
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
          ? "bg-orange-500/10 text-orange-400 border-orange-500/30"
          : "bg-gray-500/10 text-gray-400 border-gray-500/20",
        className,
      )}
    >
      EPSS {pct}%
    </span>
  );
}

// ── Confidence Indicator ────────────────────────────────────────
const CONFIDENCE_CONFIG: Record<string, { label: string; dot: string; text: string }> = {
  high: {
    label: "High confidence — the CVE template's expected product matches this asset's fingerprinted tech stack",
    dot: "#10b981",
    text: "text-emerald-400",
  },
  low: {
    label: "Low confidence — the CVE template's expected product does not match this asset's fingerprinted tech stack (still reported, not dropped — worth a second look)",
    dot: "#eab308",
    text: "text-yellow-400",
  },
};

export function ConfidenceIndicator({ confidence, className }: { confidence?: string; className?: string }) {
  if (!confidence || confidence === "unknown") return null;
  const cfg = CONFIDENCE_CONFIG[confidence];
  if (!cfg) return null;
  return (
    <span title={cfg.label} className={cn("inline-flex items-center gap-1", className)}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: cfg.dot }} />
      <span className={cn("text-[10px] uppercase tracking-wide font-semibold", cfg.text)}>
        {confidence} conf.
      </span>
    </span>
  );
}
