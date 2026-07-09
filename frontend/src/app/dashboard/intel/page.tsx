"use client";

import { useState } from "react";
import {
  Shield, RefreshCw, Search, ExternalLink,
  ChevronLeft, ChevronRight, Filter
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

// Renamed from "Threat Intelligence": the enrichment pipeline behind /intel is
// no-key ASN/RDAP/network-baseline data only (see CLAUDE.md) — there's no live
// malware/reputation feed, so this page no longer claims to be one.
export default function IntelPage() {
  const { activeOrg } = useWorkspaceStore();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 20;

  const params = new URLSearchParams({
    page: String(page),
    page_size: String(PAGE_SIZE),
  });
  if (activeOrg?.id) params.set("org_id", activeOrg.id);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["network-intel", params.toString()],
    queryFn: () => apiClient.get(`/intel?${params}`).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 60_000,
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Network Intelligence</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total ?? 0} network records · {activeOrg?.name || "All organizations"}
          </p>
        </div>
        <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      {!activeOrg ? (
        <div className="glass-card flex items-center justify-center h-64">
          <div className="text-center text-muted-foreground">
            <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select an organization to view network intelligence</p>
          </div>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative max-w-md flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search records..."
                className="w-full pl-9 pr-4 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
          </div>

          <div className="glass-card overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center h-48">
                <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : data?.items?.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full data-table">
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Risk Score</th>
                      <th>Tags</th>
                      <th>Categories</th>
                      <th>Enriched</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((item: any) => (
                      <tr key={item.id}>
                        <td>
                          <span className="text-sm font-medium text-foreground">{item.source}</span>
                        </td>
                        <td>
                          {item.risk_score != null ? (
                            <span className={cn(
                              "text-sm font-bold tabular-nums",
                              item.risk_score >= 70 ? "text-red-400" :
                              item.risk_score >= 40 ? "text-yellow-400" : "text-muted-foreground"
                            )}>
                              {item.risk_score}
                            </span>
                          ) : <span className="text-xs text-muted-foreground">—</span>}
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1 max-w-[180px]">
                            {(item.tags || []).slice(0, 3).map((tag: string) => (
                              <span key={tag} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded">{tag}</span>
                            ))}
                            {(item.tags || []).length > 3 && (
                              <span className="text-xs text-muted-foreground">+{item.tags.length - 3}</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1 max-w-[160px]">
                            {(item.categories || []).slice(0, 2).map((cat: string) => (
                              <span key={cat} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded">{cat}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className="text-xs text-muted-foreground">
                            {item.enriched_at ? formatDistanceToNow(new Date(item.enriched_at), { addSuffix: true }) : "—"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Shield className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">No network intelligence data</p>
                <p className="text-xs mt-1">Enriched from no-key ASN/RDAP/network-ownership lookups during scans</p>
              </div>
            )}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">Page {page} of {totalPages}</p>
              <div className="flex items-center gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50">
                  <ChevronLeft className="w-3 h-3" /> Previous
                </button>
                <button onClick={() => setPage(p => p + 1)} disabled={page >= totalPages}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50">
                  Next <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
