"use client";

import { useMemo, useState } from "react";
import { Flame } from "lucide-react";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/utils";
import type { NetworkCluster, NetworkClustersResponse, Severity, StandaloneHost } from "@/types";

// Same weighting the risk engine uses conceptually (critical > high > medium
// > low), just collapsed to a single per-cell number for the heatmap -- this
// is a presentation-only score, not the authoritative risk_engine.py score.
const SEVERITY_WEIGHT: Partial<Record<Severity, number>> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0.25,
};

function weightedRisk(counts: Partial<Record<Severity, number>>): number {
  return (Object.entries(counts) as [Severity, number][]).reduce(
    (sum, [sev, n]) => sum + (SEVERITY_WEIGHT[sev] ?? 0) * (n ?? 0),
    0,
  );
}

// Traffic-light hue ramp matching the app's existing severity hues (emerald
// ~160deg for grade-a, amber ~48deg for medium, red 0deg for critical) so the
// gradient reads consistently with badges elsewhere, not a new color language.
function riskHsl(normalized: number): { hue: number; sat: number } {
  const t = Math.max(0, Math.min(1, normalized));
  const hue = t <= 0.5 ? 160 - (160 - 48) * (t / 0.5) : 48 - 48 * ((t - 0.5) / 0.5);
  const sat = 70 + t * 15;
  return { hue, sat };
}

interface HeatCell {
  key: string;
  label: string;
  sublabel: string;
  hostCount: number;
  risk: number;
  counts: Partial<Record<Severity, number>>;
  source: NetworkCluster | StandaloneHost;
  kind: "cluster" | "standalone";
}

export function RiskHeatmap({
  data,
  onSelectFinding,
}: {
  data: NetworkClustersResponse;
  onSelectFinding?: (f: any) => void;
}) {
  const [selected, setSelected] = useState<HeatCell | null>(null);

  const cells = useMemo<HeatCell[]>(() => {
    const clusterCells: HeatCell[] = data.clusters.map((c) => ({
      key: `cluster-${c.ip}`,
      label: c.ip,
      sublabel: `${c.host_count} host${c.host_count === 1 ? "" : "s"}`,
      hostCount: c.host_count,
      risk: weightedRisk(c.severity_counts),
      counts: c.severity_counts,
      source: c,
      kind: "cluster",
    }));
    const standaloneCells: HeatCell[] = data.standalone.map((h) => ({
      key: `host-${h.id}`,
      label: h.value,
      sublabel: "standalone",
      hostCount: 1,
      risk: weightedRisk(h.severity_counts),
      counts: h.severity_counts,
      source: h,
      kind: "standalone",
    }));
    return [...clusterCells, ...standaloneCells].sort((a, b) => b.risk - a.risk);
  }, [data]);

  const maxRisk = Math.max(1, ...cells.map((c) => c.risk));

  if (cells.length === 0) {
    return (
      <div className="glass-card p-6 text-center text-sm text-muted-foreground">
        <Flame className="w-6 h-6 mx-auto mb-2 opacity-40" />
        No clusters or hosts to plot yet.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Legend */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>Cool</span>
          <div
            className="w-32 h-2 rounded-full"
            style={{ background: "linear-gradient(90deg, hsl(160 70% 45%), hsl(48 78% 45%), hsl(0 85% 45%))" }}
          />
          <span>Hot</span>
          <span className="ml-2 text-muted-foreground/70">— weighted by open finding severity</span>
        </div>
      </div>

      {/* Heatmap grid, subtle grid-pattern backdrop (defined in
          tailwind.config.ts, previously unused anywhere in the app) */}
      <div className="relative rounded-xl border border-border overflow-hidden bg-surface-900/40 bg-grid-pattern bg-grid p-4">
        <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(96px, 1fr))" }}>
          {cells.map((cell) => {
            const normalized = cell.risk / maxRisk;
            const isCold = cell.risk === 0;
            const { hue, sat } = riskHsl(normalized);
            const alpha = 0.12 + normalized * 0.38;
            const isSelected = selected?.key === cell.key;

            return (
              <button
                key={cell.key}
                onClick={() => setSelected(isSelected ? null : cell)}
                title={`${cell.label} — ${cell.sublabel}, risk score ${cell.risk.toFixed(1)}`}
                className={cn(
                  "hud-corners relative flex flex-col justify-between rounded-lg border p-2.5 text-left transition-transform hover:scale-[1.03] focus:outline-none focus:ring-1 focus:ring-brand-500",
                  isSelected && "ring-1 ring-brand-400",
                )}
                style={
                  isCold
                    ? undefined
                    : {
                        backgroundColor: `hsl(${hue.toFixed(0)} ${sat.toFixed(0)}% 50% / ${alpha.toFixed(2)})`,
                        borderColor: `hsl(${hue.toFixed(0)} ${sat.toFixed(0)}% 50% / ${(alpha * 1.8).toFixed(2)})`,
                      }
                }
              >
                {isCold && <span className="absolute inset-0 rounded-lg bg-surface-700/30 border border-border -m-px" />}
                <span className="relative text-[11px] font-mono font-medium text-foreground truncate">
                  {cell.label}
                </span>
                <span className="relative text-[10px] text-muted-foreground truncate">{cell.sublabel}</span>
                <span className="relative text-[10px] font-bold text-foreground/80 tabular-nums mt-1">
                  {cell.risk > 0 ? cell.risk.toFixed(1) : "—"}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected cell detail */}
      {selected && (
        <div className="glass-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              {selected.kind === "cluster" ? "Cluster" : "Standalone host"}: {selected.label}
            </h3>
            <button onClick={() => setSelected(null)} className="text-xs text-muted-foreground hover:text-foreground">
              Close
            </button>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap mb-3">
            {(Object.entries(selected.counts) as [Severity, number][])
              .filter(([, n]) => n > 0)
              .map(([sev, n]) => (
                <span key={sev} className="flex items-center gap-1 text-xs">
                  <SeverityBadge severity={sev} compact />
                  <span className="text-muted-foreground tabular-nums">{n}</span>
                </span>
              ))}
            {Object.values(selected.counts).every((n) => !n) && (
              <span className="text-xs text-muted-foreground">no open findings</span>
            )}
          </div>
          {selected.kind === "cluster" && (selected.source as NetworkCluster).top_findings.length > 0 && (
            <div className="space-y-1">
              {(selected.source as NetworkCluster).top_findings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-center gap-2 py-1 text-xs cursor-pointer hover:bg-surface-800/40 rounded px-1"
                  onClick={() => onSelectFinding?.(f)}
                >
                  <SeverityBadge severity={f.severity} compact />
                  <span className="text-foreground truncate flex-1">{f.title}</span>
                  <span className="text-muted-foreground shrink-0 font-mono text-[10px]">{f.affected_host}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
