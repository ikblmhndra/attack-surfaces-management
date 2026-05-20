"use client";

import { useState, useMemo } from "react";
import {
  Building2, Plus, Search, RefreshCw, Trash2, Edit,
  ChevronLeft, ChevronRight, MoreHorizontal
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import { formatDistanceToNow } from "date-fns";
import { apiClient, organizationsAPI } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn, scoreToGrade, scoreToColor } from "@/lib/utils";
import Link from "next/link";

export default function OrganizationsPage() {
  const router = useRouter();
  const qc = useQueryClient();
  const { canWrite, canAdmin } = useWorkspaceStore();

  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const PAGE_SIZE = 20;

  const params = useMemo(() => {
    const p = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (search) p.set("search", search);
    return p.toString();
  }, [page, search]);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["organizations", params],
    queryFn: () => organizationsAPI.list({ page, page_size: PAGE_SIZE, search: search || undefined }).then(r => r.data),
    refetchInterval: 60_000,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => organizationsAPI.delete(id),
    onSuccess: () => {
      toast.success("Organization deleted");
      qc.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: () => toast.error("Failed to delete organization"),
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Organizations</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total ?? 0} organizations monitored
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          {canWrite() && (
            <Link
              href="/dashboard/organizations/new"
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors"
            >
              <Plus className="w-4 h-4" />
              New Organization
            </Link>
          )}
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1); }}
          placeholder="Search organizations..."
          className="w-full pl-9 pr-4 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
      </div>

      {/* Table */}
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
                  <th>Organization</th>
                  <th>Domains</th>
                  <th>Score</th>
                  <th>Assets</th>
                  <th>Findings</th>
                  <th>Monitoring</th>
                  <th>Last Scan</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((org: any) => {
                  const score = org.current_score || org.risk_score;
                  const grade = score?.grade || scoreToGrade(score?.overall || 0);
                  const color = scoreToColor(score?.overall || 0);
                  return (
                    <tr
                      key={org.id}
                      className="group cursor-pointer"
                      onClick={() => router.push(`/dashboard/organizations/${org.id}`)}
                    >
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-lg bg-brand-600/20 flex items-center justify-center">
                            <Building2 className="w-4 h-4 text-brand-400" />
                          </div>
                          <div>
                            <p className="text-sm font-medium text-foreground">{org.name}</p>
                            {org.description && (
                              <p className="text-xs text-muted-foreground truncate max-w-[200px]">{org.description}</p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="text-xs text-muted-foreground">
                          {org.domains?.length || 0} domains
                        </span>
                      </td>
                      <td>
                        {score ? (
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold" style={{ color }}>{grade}</span>
                            <span className="text-xs text-muted-foreground">{score.overall}/100</span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">Not scanned</span>
                        )}
                      </td>
                      <td>
                        <span className="text-sm tabular-nums text-foreground">
                          {org.total_assets?.toLocaleString() || 0}
                        </span>
                      </td>
                      <td>
                        {org.total_findings > 0 ? (
                          <span className="text-sm font-bold text-red-400 tabular-nums">
                            {org.total_findings}
                          </span>
                        ) : (
                          <span className="text-xs text-emerald-400">Clean</span>
                        )}
                      </td>
                      <td>
                        <span className={cn(
                          "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border",
                          org.is_monitoring_active
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-gray-500/10 text-gray-400 border-gray-500/20"
                        )}>
                          <span className={cn(
                            "w-1.5 h-1.5 rounded-full",
                            org.is_monitoring_active ? "bg-emerald-400" : "bg-gray-400"
                          )} />
                          {org.is_monitoring_active ? "Active" : "Paused"}
                        </span>
                      </td>
                      <td>
                        <span className="text-xs text-muted-foreground">
                          {org.last_scan_at
                            ? formatDistanceToNow(new Date(org.last_scan_at), { addSuffix: true })
                            : "Never"}
                        </span>
                      </td>
                      <td>
                        <div className="relative" onClick={e => e.stopPropagation()}>
                          <button
                            onClick={() => setMenuOpen(menuOpen === org.id ? null : org.id)}
                            className="p-1 rounded hover:bg-surface-700 text-muted-foreground hover:text-foreground opacity-0 group-hover:opacity-100 transition-opacity"
                          >
                            <MoreHorizontal className="w-4 h-4" />
                          </button>
                          {menuOpen === org.id && (
                            <motion.div
                              initial={{ opacity: 0, scale: 0.95 }}
                              animate={{ opacity: 1, scale: 1 }}
                              className="absolute right-0 top-full mt-1 w-40 bg-surface-800 border border-border rounded-lg shadow-xl z-50 py-1"
                            >
                              <button
                                onClick={() => { router.push(`/dashboard/organizations/${org.id}`); setMenuOpen(null); }}
                                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-surface-700"
                              >
                                <Building2 className="w-3.5 h-3.5" />
                                View Details
                              </button>
                              {canAdmin() && (
                                <button
                                  onClick={() => {
                                    if (confirm(`Delete ${org.name}? This cannot be undone.`)) {
                                      deleteMutation.mutate(org.id);
                                    }
                                    setMenuOpen(null);
                                  }}
                                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400 hover:bg-red-500/10"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                  Delete
                                </button>
                              )}
                            </motion.div>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
            <Building2 className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-sm">No organizations yet</p>
            <p className="text-xs mt-1">Create your first organization to get started</p>
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
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50"
            >
              <ChevronLeft className="w-3 h-3" /> Previous
            </button>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={page >= totalPages}
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50"
            >
              Next <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
