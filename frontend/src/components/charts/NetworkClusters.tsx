"use client";

import { useState } from "react";
import { ChevronRight, Layers, Network } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/Collapsible";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/utils";
import type { NetworkCluster, NetworkClustersResponse, Severity, StandaloneHost } from "@/types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function SeverityCounts({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const entries = SEVERITY_ORDER.filter((sev) => (counts[sev] ?? 0) > 0);
  if (entries.length === 0) {
    return <span className="text-xs text-muted-foreground">no open findings</span>;
  }
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {entries.map((sev) => (
        <span key={sev} className="flex items-center gap-1 text-xs">
          <SeverityBadge severity={sev} compact />
          <span className="text-muted-foreground tabular-nums">{counts[sev]}</span>
        </span>
      ))}
    </div>
  );
}

function ClusterRow({ cluster, onSelectFinding }: { cluster: NetworkCluster; onSelectFinding?: (f: any) => void }) {
  const [open, setOpen] = useState(false);

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div className="glass-card overflow-hidden">
        <CollapsibleTrigger asChild>
          <button className="w-full flex items-center gap-3 px-4 py-3 hover:bg-surface-800/40 text-left">
            <ChevronRight className={cn("w-4 h-4 text-muted-foreground transition-transform shrink-0", open && "rotate-90")} />
            <div className="flex flex-col shrink-0 w-40">
              <span className="text-sm font-mono font-medium text-foreground">{cluster.ip}</span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide">shared ipv4</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0 w-24">
              <Network className="w-3.5 h-3.5" />
              {cluster.host_count} hosts
            </div>
            <div className="flex-1 min-w-0 flex items-center gap-1.5 flex-wrap">
              {cluster.technologies.slice(0, 4).map((tech) => (
                <span key={tech} className="text-[10px] px-2 py-0.5 rounded-full bg-surface-800 border border-border text-muted-foreground whitespace-nowrap">
                  {tech}
                </span>
              ))}
              {cluster.technologies.length > 4 && (
                <span className="text-[10px] text-muted-foreground">+{cluster.technologies.length - 4}</span>
              )}
            </div>
            <div className="shrink-0">
              <SeverityCounts counts={cluster.severity_counts} />
            </div>
          </button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="px-4 pb-4 pt-1 border-t border-border/50 grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <h4 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-2">
                Hosts on this IP
              </h4>
              <div className="space-y-0.5">
                {cluster.hosts.map((host) => (
                  <div key={host.id} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-surface-800/40 text-xs">
                    <span className="font-mono text-brand-400 truncate">{host.value}</span>
                    <span className="text-muted-foreground shrink-0 ml-2">
                      {host.http_status ?? "—"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-2">
                Top findings in cluster
              </h4>
              {cluster.top_findings.length === 0 ? (
                <p className="text-xs text-muted-foreground">No open findings in this cluster.</p>
              ) : (
                <div className="space-y-1 mb-3">
                  {cluster.top_findings.map((f) => (
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
              <h4 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-2 mt-3">
                Shared technology
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {cluster.technologies.map((tech) => (
                  <span key={tech} className="text-[10px] px-2 py-0.5 rounded-full bg-surface-800 border border-border text-muted-foreground">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

function StandaloneRow({ host }: { host: StandaloneHost }) {
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border/30 last:border-0 text-xs">
      <span className="font-mono text-brand-400 flex-1 truncate">{host.value}</span>
      <span className="font-mono text-muted-foreground w-32 shrink-0">{host.ip ?? "—"}</span>
      <div className="w-40 shrink-0">
        <SeverityCounts counts={host.severity_counts} />
      </div>
    </div>
  );
}

export function NetworkClusters({
  data,
  onSelectFinding,
}: {
  data: NetworkClustersResponse;
  onSelectFinding?: (f: any) => void;
}) {
  const [standaloneOpen, setStandaloneOpen] = useState(false);
  const visibleStandalone = standaloneOpen ? data.standalone : data.standalone.slice(0, 8);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="glass-card p-3">
          <p className="text-lg font-bold text-brand-400 tabular-nums">{data.summary.clusters_found}</p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Clusters found</p>
        </div>
        <div className="glass-card p-3">
          <p className="text-lg font-bold text-foreground tabular-nums">{data.summary.hosts_clustered}</p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Hosts clustered</p>
        </div>
        <div className="glass-card p-3">
          <p className="text-lg font-bold text-foreground tabular-nums">{data.summary.standalone_hosts}</p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Standalone hosts</p>
        </div>
        <div className="glass-card p-3">
          <p className="text-lg font-bold text-foreground tabular-nums">{data.summary.total_ips}</p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Total IPs</p>
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-foreground">Shared-infrastructure clusters</h3>
          <span className="text-xs text-muted-foreground">sorted by host count</span>
        </div>
        {data.clusters.length === 0 ? (
          <div className="glass-card p-6 text-center text-sm text-muted-foreground">
            <Layers className="w-6 h-6 mx-auto mb-2 opacity-40" />
            No shared-IP clusters found — every resolved host is on its own IP.
          </div>
        ) : (
          <div className="space-y-2">
            {data.clusters.map((cluster) => (
              <ClusterRow key={cluster.ip} cluster={cluster} onSelectFinding={onSelectFinding} />
            ))}
          </div>
        )}
      </div>

      {data.standalone.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-foreground">Standalone hosts</h3>
            <span className="text-xs text-muted-foreground">
              {data.standalone.length} hosts, no shared infrastructure
            </span>
          </div>
          <div className="glass-card overflow-hidden">
            {visibleStandalone.map((host) => (
              <StandaloneRow key={host.id} host={host} />
            ))}
          </div>
          {data.standalone.length > 8 && (
            <button
              onClick={() => setStandaloneOpen((o) => !o)}
              className="mt-2 text-xs text-brand-400 hover:text-brand-300"
            >
              {standaloneOpen ? "Show fewer" : `Show all ${data.standalone.length}`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
