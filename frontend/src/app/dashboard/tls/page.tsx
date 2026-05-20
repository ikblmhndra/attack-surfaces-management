"use client";

import { useState } from "react";
import {
  Lock, RefreshCw, Search, AlertTriangle, CheckCircle,
  ChevronLeft, ChevronRight, Globe, Clock
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow, format } from "date-fns";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

export default function TlsPage() {
  const { activeOrg } = useWorkspaceStore();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState<"all" | "expiring" | "expired">("all");
  const PAGE_SIZE = 25;

  const params = new URLSearchParams({
    page: String(page),
    page_size: String(PAGE_SIZE),
  });
  if (activeOrg?.id) params.set("org_id", activeOrg.id);
  if (search) params.set("search", search);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["tls-intel", params.toString(), filter],
    queryFn: () => apiClient.get(`/assets?${params}&expand=tls`).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 60_000,
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  const assetsWithTls = (data?.items || []).filter((a: any) => {
    const tlsExpiry = a.subdomain?.tls_expiry;
    if (!tlsExpiry) return filter === "all";
    if (filter === "expired") return new Date(tlsExpiry) < new Date();
    if (filter === "expiring") {
      const days = Math.ceil((new Date(tlsExpiry).getTime() - Date.now()) / 86400000);
      return days <= 30 && days > 0;
    }
    return true;
  });

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">TLS/SSL Analysis</h1>
          <p className="text-sm text-muted-foreground">
            Certificate status and expiration · {activeOrg?.name || "All organizations"}
          </p>
        </div>
        <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      {!activeOrg ? (
        <div className="glass-card flex items-center justify-center h-64">
          <div className="text-center text-muted-foreground">
            <Lock className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select an organization to view TLS data</p>
          </div>
        </div>
      ) : (
        <>
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search domain..."
                className="w-full pl-9 pr-4 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div className="flex items-center gap-1">
              {(["all", "expiring", "expired"] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={cn(
                    "px-3 py-1.5 text-xs rounded-lg border transition-colors capitalize",
                    filter === f
                      ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                      : "bg-surface-800 border-surface-600 text-muted-foreground"
                  )}
                >
                  {f === "all" ? "All" : f === "expiring" ? "Expiring Soon" : "Expired"}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div className="glass-card overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center h-48">
                <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : assetsWithTls.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full data-table">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Status</th>
                      <th>Issuer</th>
                      <th>Version</th>
                      <th>Expires</th>
                      <th>Days Left</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assetsWithTls.map((asset: any) => {
                      const tls = asset.subdomain || {};
                      const expiry = tls.tls_expiry;
                      let daysLeft = null;
                      let status: { label: string; color: string; dot: string } = { label: "No TLS", color: "text-muted-foreground", dot: "bg-gray-400" };
                      if (expiry) {
                        daysLeft = Math.ceil((new Date(expiry).getTime() - Date.now()) / 86400000);
                        if (daysLeft <= 0) status = { label: "Expired", color: "text-red-400", dot: "bg-red-400" };
                        else if (daysLeft <= 7) status = { label: "Critical", color: "text-red-400", dot: "bg-red-400" };
                        else if (daysLeft <= 30) status = { label: "Expiring", color: "text-yellow-400", dot: "bg-yellow-400" };
                        else status = { label: "Valid", color: "text-emerald-400", dot: "bg-emerald-400" };
                      }
                      return (
                        <tr key={asset.id}>
                          <td>
                            <div className="flex items-center gap-2">
                              <Lock className="w-4 h-4 text-brand-400" />
                              <span className="text-sm font-mono text-foreground">{asset.value}</span>
                            </div>
                          </td>
                          <td>
                            <div className="flex items-center gap-1.5">
                              <span className={cn("w-1.5 h-1.5 rounded-full", status.dot)} />
                              <span className={cn("text-xs font-medium", status.color)}>{status.label}</span>
                            </div>
                          </td>
                          <td>
                            <span className="text-xs text-muted-foreground truncate max-w-[180px] block">
                              {tls.tls_issuer || "—"}
                            </span>
                          </td>
                          <td>
                            <span className="text-xs font-mono text-foreground">{tls.tls_version || "—"}</span>
                          </td>
                          <td>
                            <span className={cn(
                              "text-xs font-mono",
                              daysLeft != null && daysLeft <= 0 ? "text-red-400" :
                              daysLeft != null && daysLeft <= 30 ? "text-yellow-400" : "text-muted-foreground"
                            )}>
                              {expiry ? format(new Date(expiry), "MMM d, yyyy") : "—"}
                            </span>
                          </td>
                          <td>
                            {daysLeft != null ? (
                              <span className={cn(
                                "text-xs font-bold tabular-nums",
                                daysLeft <= 0 ? "text-red-400" :
                                daysLeft <= 7 ? "text-red-400" :
                                daysLeft <= 30 ? "text-yellow-400" : "text-emerald-400"
                              )}>
                                {daysLeft <= 0 ? "Expired" : `${daysLeft}d`}
                              </span>
                            ) : (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Lock className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">No TLS data found</p>
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
