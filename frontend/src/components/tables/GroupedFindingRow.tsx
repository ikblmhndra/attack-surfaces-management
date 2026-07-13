"use client";

import { useState } from "react";
import { ChevronRight, Layers } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { apiClient } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Collapsible, CollapsibleContent } from "@/components/ui/Collapsible";
import { SeverityBadge, CVEBadge } from "@/components/ui/SeverityBadge";
import type { Finding, FindingGroup } from "@/types";

export function GroupedFindingRow({
  group,
  filterParams,
  onSelectFinding,
}: {
  group: FindingGroup;
  filterParams: string;
  onSelectFinding: (finding: Finding | Record<string, any>) => void;
}) {
  const [open, setOpen] = useState(false);
  const isSingleton = !group.template_id;

  const { data, isFetching } = useQuery({
    queryKey: ["findings-by-template", group.template_id, filterParams],
    queryFn: () =>
      apiClient
        .get(
          `/findings?template_id=${encodeURIComponent(group.template_id!)}&${filterParams}&page=1&page_size=500`
        )
        .then((r) => r.data),
    enabled: open && !isSingleton,
    staleTime: 30_000,
  });

  const handleHeaderClick = () => {
    if (isSingleton) {
      onSelectFinding({
        id: group.sample_finding_id,
        title: group.sample_title,
        severity: group.severity,
        category: group.category,
        status: group.sample_status,
        affected_url: group.sample_affected_url,
        cve_ids: group.cve_ids,
        first_seen: group.first_seen,
        last_seen: group.last_seen,
        references: [],
        cwe_ids: [],
        org_id: "",
        source: "",
        is_false_positive: false,
        is_risk_accepted: false,
      });
    } else {
      setOpen((o) => !o);
    }
  };

  return (
    <Collapsible open={open}>
      <div
        className="group flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-surface-800/40"
        onClick={handleHeaderClick}
      >
        {!isSingleton ? (
          <ChevronRight
            className={cn(
              "w-4 h-4 text-muted-foreground transition-transform shrink-0",
              open && "rotate-90"
            )}
          />
        ) : (
          <span className="w-4 shrink-0" />
        )}
        <SeverityBadge severity={group.severity} />
        {group.heading_kind === "cve" && <CVEBadge cveId={group.heading} />}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-foreground truncate">{group.heading}</p>
          {group.subheading && (
            <p className="text-xs text-muted-foreground truncate mt-0.5">{group.subheading}</p>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0 w-40">
          <Layers className="w-3.5 h-3.5" />
          {group.finding_count} finding{group.finding_count !== 1 ? "s" : ""} · {group.asset_count} host
          {group.asset_count !== 1 ? "s" : ""}
        </div>
        <span className="text-xs text-muted-foreground w-28 text-right shrink-0">
          {group.last_seen ? formatDistanceToNow(new Date(group.last_seen), { addSuffix: true }) : "—"}
        </span>
      </div>
      {!isSingleton && (
        <CollapsibleContent>
          <div className="pl-11 pr-4 pb-2 border-t border-border/50 bg-surface-900/30">
            {isFetching ? (
              <div className="py-3 text-xs text-muted-foreground">Loading members…</div>
            ) : (
              (data?.items ?? []).map((f: Finding) => (
                <div
                  key={f.id}
                  className="flex items-center gap-3 py-2 border-b border-border/30 last:border-0 cursor-pointer hover:bg-surface-800/40"
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectFinding(f);
                  }}
                >
                  <span className="text-xs font-mono text-brand-400 truncate flex-1">
                    {f.affected_url || "—"}
                  </span>
                  <span className="text-xs text-muted-foreground">{f.status}</span>
                  <span className="text-xs text-muted-foreground w-28 text-right shrink-0">
                    {f.last_seen ? formatDistanceToNow(new Date(f.last_seen), { addSuffix: true }) : "—"}
                  </span>
                </div>
              ))
            )}
          </div>
        </CollapsibleContent>
      )}
    </Collapsible>
  );
}
