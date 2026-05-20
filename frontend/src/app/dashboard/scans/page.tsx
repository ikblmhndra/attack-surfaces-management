"use client";

import { useState, useMemo, useCallback } from "react";
import {
  Scan, RefreshCw, AlertTriangle, Activity,
  ChevronLeft, ChevronRight, XCircle, Search,
  Clock, CheckCircle, Play, Filter
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn, formatRelative } from "@/lib/utils";

const STATUS_CONFIG: Record<string, { color: string; icon: any }> = {
  completed: { color: "text-emerald-400", icon: CheckCircle },
  running:   { color: "text-brand-400", icon: Play },
  failed:    { color: "text-red-400", icon: AlertTriangle },
  cancelled: { color: "text-muted-foreground", icon: XCircle },
  pending:   { color: "text-yellow-400", icon: Clock },
  queued:    { color: "text-yellow-400", icon: Clock },
};

const PHASE_LABELS: Record<string, string> = {
  "0":     "Queued",
  "10":    "Discovery",
  "25":    "Port scanning",
  "50":    "Vulnerability scan",
  "75":    "Screenshots",
  "90":    "Finalizing",
  "100":   "Complete",
};

function getPhaseLabel(progress: number, status: string): string {
  if (status === "completed") return "Complete";
  if (status === "failed") return "Failed";
  if (status === "cancelled") return "Cancelled";
  if (progress === 0) return "Queued";
  if (progress < 10) return "Starting...";
  if (progress < 25) return "Discovery";
  if (progress < 50) return "Port scanning";
  if (progress < 75) return "Vulnerability scan";
  if (progress < 90) return "Screenshots";
  return "Finalizing";
}

export default function ScansPage() {
  const { activeOrg } = useWorkspaceStore();
  const queryClient = useQueryClient();

  const [statusFilter, setStatusFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 20;

  const params = useMemo(() => {
    const p = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (activeOrg?.id) p.set("org_id", activeOrg.id);
    if (statusFilter)  p.set("status", statusFilter);
    if (search)        p.set("search", search);
    return p.toString();
  }, [page, statusFilter, search, activeOrg?.id]);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["scans", params],
    queryFn: () => apiClient.get(`/scans?${params}`).then(r => r.data),
    refetchInterval: 15_000,
  });

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => apiClient.post(`/scans/${scanId}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Scans</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total ?? 0} total · {activeOrg?.name || "All organizations"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search scans..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            className="w-full pl-9 pr-4 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-48">
            <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : data?.items?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Type</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Status</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Progress</th>
                  <th className="text-right text-xs font-medium text-muted-foreground px-4 py-3">Assets</th>
                  <th className="text-right text-xs font-medium text-muted-foreground px-4 py-3">Findings</th>
                  <th className="text-right text-xs font-medium text-muted-foreground px-4 py-3">Started</th>
                  <th className="text-right text-xs font-medium text-muted-foreground px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((scan: any) => {
                  const cfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending;
                  const StatusIcon = cfg.icon;
                  return (
                    <tr key={scan.id} className="border-b border-border/30 hover:bg-surface-700/20 transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-sm text-foreground capitalize">{scan.scan_type}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <StatusIcon className={cn("w-3.5 h-3.5", cfg.color,
                            scan.status === "running" && "animate-pulse")} />
                          <span className={cn("text-sm capitalize", cfg.color)}>
                            {scan.status}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 max-w-[140px]">
                          <div className="flex-1 h-1.5 bg-surface-700 rounded-full overflow-hidden">
                            <div
                              className={cn("h-full rounded-full transition-all duration-500", cfg.color.replace("text", "bg"))}
                              style={{ width: `${scan.progress_pct}%` }}
                            />
                          </div>
                          <span className="text-xs text-muted-foreground w-8 text-right">
                            {scan.progress_pct}%
                          </span>
                        </div>
                        {scan.status === "running" && (
                          <span className="text-[10px] text-muted-foreground/70 mt-0.5 block">
                            {getPhaseLabel(scan.progress_pct, scan.status)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right text-sm text-foreground">
                        {scan.assets_found ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-right text-sm text-foreground">
                        {scan.findings_found ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-right text-xs text-muted-foreground whitespace-nowrap">
                        {scan.created_at ? formatRelative(scan.created_at) : "—"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {["pending", "running", "queued"].includes(scan.status) && (
                          <button
                            onClick={() => cancelMutation.mutate(scan.id)}
                            disabled={cancelMutation.isPending}
                            className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded hover:bg-red-500/10 transition-colors"
                          >
                            Cancel
                          </button>
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
            <Scan className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-sm">No scans found</p>
            <p className="text-xs mt-1">Run a scan from the organization page to get started</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-3 h-3" /> Previous
            </button>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={page >= totalPages}
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
