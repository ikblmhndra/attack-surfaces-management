"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, ArrowLeft, CheckCircle, Clock, ExternalLink,
  ListChecks, RefreshCw, Target, XCircle
} from "lucide-react";

import { apiClient } from "@/lib/api";
import { cn, formatRelative } from "@/lib/utils";

const STATUS_ICON: Record<string, any> = {
  completed: CheckCircle,
  running: RefreshCw,
  queued: Clock,
  pending: Clock,
  skipped: XCircle,
  failed: AlertTriangle,
};

const STATUS_CLASS: Record<string, string> = {
  completed: "text-emerald-400",
  running: "text-brand-400",
  queued: "text-yellow-400",
  pending: "text-yellow-400",
  skipped: "text-muted-foreground",
  failed: "text-red-400",
};

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const { data: scan, isLoading, refetch } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => apiClient.get(`/scans/${scanId}`).then(r => r.data),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return ["running", "queued", "pending"].includes(status) ? 10_000 : false;
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!scan) {
    return <div className="p-6 text-sm text-muted-foreground">Scan not found</div>;
  }

  const progress = Math.max(0, Math.min(100, Math.round(scan.progress_pct ?? 0)));
  const targetSummary = scan.target_summary || {};
  const phaseRuns = scan.phase_runs || [];
  const targetSelections = scan.target_selections || [];
  const whyNoFindings = scan.why_no_findings || [];

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center gap-4">
        <button
          onClick={() => router.push("/dashboard/scans")}
          className="p-2 rounded-lg hover:bg-surface-700 text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold text-foreground capitalize">{scan.scan_type} scan</h1>
            <StatusBadge status={scan.status} />
            {scan.scan_profile && (
              <span className="text-xs bg-surface-700 text-muted-foreground border border-surface-600 px-2 py-0.5 rounded">
                {scan.scan_profile}
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground font-mono mt-1">{scan.id}</p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground"
        >
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <SummaryCard label="Progress" value={`${progress}%`} sub={`${scan.completed_tasks ?? 0}/${scan.total_tasks ?? 0} tasks`} />
        <SummaryCard label="Assets" value={scan.assets_found ?? 0} sub={`${scan.new_assets ?? 0} new`} />
        <SummaryCard label="Findings" value={scan.findings_found ?? 0} sub={`${scan.new_findings ?? 0} new`} danger={(scan.findings_found ?? 0) > 0} />
        <SummaryCard label="Duration" value={formatDuration(scan.duration_seconds)} sub={scan.started_at ? `started ${formatRelative(scan.started_at)}` : "not started"} />
      </div>

      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-foreground">Phase Timeline</h2>
          <span className="text-xs text-muted-foreground">{phaseRuns.length} phases</span>
        </div>
        {phaseRuns.length > 0 ? (
          <div className="space-y-2">
            {phaseRuns.map((phase: any) => (
              <PhaseRow key={phase.phase} phase={phase} />
            ))}
          </div>
        ) : (
          <EmptyState icon={ListChecks} text="No durable phase records yet" />
        )}
      </div>

      {whyNoFindings.length > 0 && (
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-3">Why No Findings</h2>
          <div className="space-y-2">
            {whyNoFindings.map((reason: any) => (
              <div key={reason.code} className="rounded-lg border border-surface-700 bg-surface-800/60 px-3 py-2">
                <p className="text-sm text-foreground">{reason.label}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{reason.detail}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 lg:col-span-4 glass-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-3">Target Coverage</h2>
          <div className="space-y-2">
            <MetricLine label="Total records" value={targetSummary.total ?? 0} />
            <MetricLine label="Selected" value={targetSummary.selected ?? 0} />
            <MetricLine label="Skipped" value={targetSummary.skipped ?? 0} />
            {Object.entries(targetSummary.by_type || {}).map(([type, count]) => (
              <MetricLine key={type} label={type} value={count as number} />
            ))}
          </div>
        </div>

        <div className="col-span-12 lg:col-span-8 glass-card p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-foreground">Target Selections</h2>
            <span className="text-xs text-muted-foreground">showing {targetSelections.length}</span>
          </div>
          {targetSelections.length > 0 ? (
            <div className="space-y-2 max-h-[520px] overflow-y-auto pr-1">
              {targetSelections.map((target: any) => (
                <TargetRow key={target.id} target={target} />
              ))}
            </div>
          ) : (
            <EmptyState icon={Target} text="No target selections recorded yet" />
          )}
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn(
      "text-xs px-2 py-0.5 rounded-full border font-medium capitalize",
      status === "completed" && "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
      status === "running" && "bg-brand-500/10 text-brand-400 border-brand-500/20",
      status === "failed" && "bg-red-500/10 text-red-400 border-red-500/20",
      ["queued", "pending"].includes(status) && "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
      status === "cancelled" && "bg-surface-700 text-muted-foreground border-border",
    )}>
      {status}
    </span>
  );
}

function SummaryCard({ label, value, sub, danger = false }: { label: string; value: any; sub: string; danger?: boolean }) {
  return (
    <div className="col-span-6 lg:col-span-3 glass-card p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={cn("text-2xl font-semibold tabular-nums mt-1", danger ? "text-red-400" : "text-foreground")}>{value}</p>
      <p className="text-xs text-muted-foreground mt-1">{sub}</p>
    </div>
  );
}

function PhaseRow({ phase }: { phase: any }) {
  const Icon = STATUS_ICON[phase.status] || Clock;
  return (
    <div className="rounded-lg border border-surface-700 bg-surface-800/50 px-3 py-2">
      <div className="flex items-start gap-3">
        <Icon className={cn("w-4 h-4 mt-0.5", STATUS_CLASS[phase.status] || "text-muted-foreground", phase.status === "running" && "animate-spin")} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-foreground capitalize">{phase.phase.replace("_", " ")}</p>
            <span className="text-xs text-muted-foreground whitespace-nowrap">{formatDuration(phase.duration_seconds)}</span>
          </div>
          <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span>{phase.status}</span>
            {(phase.expected_tasks || phase.completed_tasks) && <span>{phase.completed_tasks}/{phase.expected_tasks} tasks</span>}
            {!!phase.targets_total && <span>{phase.targets_total} targets</span>}
            {!!phase.targets_selected && <span>{phase.targets_selected} selected</span>}
            {!!phase.errors && <span className="text-red-400">{phase.errors} errors</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

function TargetRow({ target }: { target: any }) {
  const isUrl = target.target?.startsWith("http://") || target.target?.startsWith("https://");
  return (
    <div className="rounded-lg border border-surface-700 bg-surface-800/50 px-3 py-2">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-xs bg-surface-700 text-muted-foreground border border-surface-600 px-1.5 py-0.5 rounded">{target.phase}</span>
            <span className="text-xs bg-surface-700 text-muted-foreground border border-surface-600 px-1.5 py-0.5 rounded">{target.target_type}</span>
            {target.score != null && <span className="text-xs text-brand-400">score {target.score}</span>}
          </div>
          <div className="mt-1 flex items-center gap-1.5">
            <p className="text-xs font-mono text-foreground break-all">{target.target}</p>
            {isUrl && (
              <a href={target.target} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground">
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
          {target.reasons?.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {target.reasons.slice(0, 6).filter(Boolean).map((reason: string) => (
                <span key={reason} className="text-[10px] text-muted-foreground bg-surface-900 px-1.5 py-0.5 rounded">
                  {reason}
                </span>
              ))}
            </div>
          )}
        </div>
        <span className={cn("text-xs whitespace-nowrap", target.selected ? "text-emerald-400" : "text-muted-foreground")}>
          {target.selected ? "selected" : "skipped"}
        </span>
      </div>
    </div>
  );
}

function MetricLine({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs text-muted-foreground capitalize">{label.replace("_", " ")}</span>
      <span className="text-sm text-foreground tabular-nums">{value.toLocaleString()}</span>
    </div>
  );
}

function EmptyState({ icon: Icon, text }: { icon: any; text: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
      <Icon className="w-8 h-8 mb-2 opacity-40" />
      <p className="text-sm">{text}</p>
    </div>
  );
}

function formatDuration(seconds?: number | null): string {
  if (!seconds) return "0s";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
