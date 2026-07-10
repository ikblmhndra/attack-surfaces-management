"use client";

import { useState, useMemo } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  createColumnHelper,
  flexRender,
  SortingState,
  ColumnFiltersState,
} from "@tanstack/react-table";
import {
  AlertTriangle, ChevronUp, ChevronDown, ChevronsUpDown,
  Filter, Download, ExternalLink, CheckCircle, XCircle,
  ChevronLeft, ChevronRight, Search, RefreshCw, Eye
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow, format } from "date-fns";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { SeverityBadge, KEVBadge, EPSSBadge, ConfidenceIndicator } from "@/components/ui/SeverityBadge";
import { FindingDetailModal } from "@/components/modals/FindingDetailModal";

const columnHelper = createColumnHelper<any>();

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  accepted: "Risk Accepted",
  false_positive: "False Positive",
  resolved: "Resolved",
};

export default function FindingsPage() {
  const { activeOrg } = useWorkspaceStore();
  const qc = useQueryClient();

  const [sorting, setSorting] = useState<SortingState>([
    { id: "severity", desc: false },
  ]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [globalFilter, setGlobalFilter] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  // Filter state
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("open");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  // Build query params
  const queryParams = useMemo(() => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(PAGE_SIZE),
      status: statusFilter || "open",
    });
    if (activeOrg?.id) params.set("org_id", activeOrg.id);
    if (severityFilter.length) params.set("severity", severityFilter.join(","));
    if (categoryFilter) params.set("category", categoryFilter);
    if (globalFilter) params.set("search", globalFilter);
    return params.toString();
  }, [page, statusFilter, severityFilter, categoryFilter, globalFilter, activeOrg?.id]);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["findings", queryParams],
    queryFn: () => apiClient.get(`/findings?${queryParams}`).then(r => r.data),
    refetchInterval: 30_000,
  });

  const exportFindings = async () => {
    const params = new URLSearchParams();
    params.set("format", "csv");
    if (activeOrg?.id) params.set("org_id", activeOrg.id);
    if (severityFilter.length) params.set("severity", severityFilter.join(","));
    if (statusFilter) params.set("status", statusFilter);
    if (categoryFilter) params.set("category", categoryFilter);

    const response = await apiClient.get(`/findings/export?${params.toString()}`, {
      responseType: "blob",
    });
    const url = URL.createObjectURL(response.data);
    const link = document.createElement("a");
    link.href = url;
    link.download = "findings.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  // Mutations
  const markFalsePositive = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiClient.post(`/findings/${id}/false-positive`, { reason }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  const acceptRisk = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiClient.post(`/findings/${id}/accept-risk`, { reason }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  const columns = useMemo(() => [
    columnHelper.accessor("severity", {
      header: "Severity",
      size: 100,
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
      sortingFn: (a, b) => {
        const aOrder = SEVERITY_ORDER[a.original.severity as keyof typeof SEVERITY_ORDER] ?? 99;
        const bOrder = SEVERITY_ORDER[b.original.severity as keyof typeof SEVERITY_ORDER] ?? 99;
        return aOrder - bOrder;
      },
    }),
    columnHelper.accessor("title", {
      header: "Finding",
      size: 320,
      cell: (info) => (
        <div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <p className="text-sm font-medium text-foreground truncate max-w-[280px]">
              {info.getValue()}
            </p>
            {info.row.original.is_kev && (
              <KEVBadge compact knownRansomware={info.row.original.kev_known_ransomware} />
            )}
          </div>
          <p className="text-xs text-muted-foreground truncate max-w-[280px] mt-0.5">
            {info.row.original.template_id}
          </p>
        </div>
      ),
    }),
    columnHelper.accessor("affected_url", {
      header: "Asset",
      size: 220,
      cell: (info) => (
        <span className="text-xs font-mono text-brand-400 truncate block max-w-[200px]">
          {info.getValue() || "—"}
        </span>
      ),
    }),
    columnHelper.accessor("category", {
      header: "Category",
      size: 150,
      cell: (info) => (
        <span className="text-xs text-muted-foreground capitalize">
          {info.getValue()?.replace(/_/g, " ")}
        </span>
      ),
    }),
    columnHelper.accessor("status", {
      header: "Status",
      size: 120,
      cell: (info) => {
        const s = info.getValue();
        return (
          <span className={cn(
            "text-xs px-2 py-0.5 rounded-full border font-medium",
            s === "open" && "bg-red-500/10 text-red-400 border-red-500/20",
            s === "accepted" && "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
            s === "false_positive" && "bg-gray-500/10 text-gray-400 border-gray-500/20",
            s === "resolved" && "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
          )}>
            {STATUS_LABELS[s] || s}
          </span>
        );
      },
    }),
    columnHelper.accessor("cvss_score", {
      header: "CVSS / Exploit Intel",
      size: 130,
      cell: (info) => {
        const v = info.getValue();
        const f = info.row.original;
        const color = v ? (v >= 9 ? "#ef4444" : v >= 7 ? "#f97316" : v >= 4 ? "#eab308" : "#3b82f6") : undefined;
        return (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-1.5">
              {v ? (
                <span className="text-xs font-mono font-bold" style={{ color }}>
                  {v.toFixed(1)}
                </span>
              ) : (
                <span className="text-xs text-muted-foreground">—</span>
              )}
              <ConfidenceIndicator confidence={f.confidence} />
            </div>
            {typeof f.epss_score === "number" && f.epss_score > 0 && (
              <EPSSBadge score={f.epss_score} />
            )}
          </div>
        );
      },
    }),
    columnHelper.accessor("first_seen", {
      header: "First Seen",
      size: 130,
      cell: (info) => (
        <span className="text-xs text-muted-foreground">
          {formatDistanceToNow(new Date(info.getValue()), { addSuffix: true })}
        </span>
      ),
    }),
    columnHelper.display({
      id: "actions",
      header: "",
      size: 80,
      cell: (info) => (
        <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={(e) => { e.stopPropagation(); setSelectedFinding(info.row.original); }}
            className="p-1 rounded hover:bg-surface-600 text-muted-foreground hover:text-foreground"
            title="View details"
          >
            <Eye className="w-3.5 h-3.5" />
          </button>
          {info.row.original.status === "open" && (
            <>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  if (confirm("Mark as false positive?")) {
                    markFalsePositive.mutate({ id: info.row.original.id, reason: "Manually marked" });
                  }
                }}
                className="p-1 rounded hover:bg-surface-600 text-muted-foreground hover:text-foreground"
                title="Mark false positive"
              >
                <XCircle className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  if (confirm("Accept risk for this finding?")) {
                    acceptRisk.mutate({ id: info.row.original.id, reason: "Risk accepted" });
                  }
                }}
                className="p-1 rounded hover:bg-surface-600 text-muted-foreground hover:text-foreground"
                title="Accept risk"
              >
                <CheckCircle className="w-3.5 h-3.5" />
              </button>
            </>
          )}
        </div>
      ),
    }),
  ], [markFalsePositive, acceptRisk]);

  const table = useReactTable({
    data: data?.items ?? [],
    columns,
    state: { sorting, columnFilters, globalFilter },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    manualPagination: true,
    pageCount: data?.pages ?? 1,
  });

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Findings</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total?.toLocaleString() ?? 0} findings · {activeOrg?.name || "All organizations"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground"
          >
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          <button
            onClick={exportFindings}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground"
          >
            <Download className="w-3 h-3" /> Export
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: "Critical", count: data?.severity_counts?.critical ?? 0, color: "#ef4444", sev: "critical" },
          { label: "High", count: data?.severity_counts?.high ?? 0, color: "#f97316", sev: "high" },
          { label: "Medium", count: data?.severity_counts?.medium ?? 0, color: "#eab308", sev: "medium" },
          { label: "Low", count: data?.severity_counts?.low ?? 0, color: "#3b82f6", sev: "low" },
          { label: "Info", count: data?.severity_counts?.info ?? 0, color: "#6b7280", sev: "info" },
        ].map((s) => (
          <button
            key={s.sev}
            onClick={() => setSeverityFilter(
              severityFilter.includes(s.sev)
                ? severityFilter.filter(x => x !== s.sev)
                : [...severityFilter, s.sev]
            )}
            className={cn(
              "glass-card p-3 text-left transition-all",
              severityFilter.includes(s.sev) && "ring-1",
            )}
            style={severityFilter.includes(s.sev) ? { "--tw-ring-color": s.color } as any : {}}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">{s.label}</span>
              <span className="text-lg font-bold tabular-nums" style={{ color: s.color }}>
                {s.count.toLocaleString()}
              </span>
            </div>
            <div className="mt-1.5 h-1 bg-surface-700 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${data?.total ? (s.count / data.total) * 100 : 0}%`,
                  backgroundColor: s.color,
                  opacity: 0.7,
                }}
              />
            </div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            placeholder="Search findings..."
            className="pl-9 pr-3 py-1.5 text-sm bg-surface-800 border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-brand-500 w-60"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 text-sm bg-surface-800 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-brand-500"
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="accepted">Risk Accepted</option>
          <option value="false_positive">False Positive</option>
          <option value="resolved">Resolved</option>
        </select>

        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="px-3 py-1.5 text-sm bg-surface-800 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-brand-500"
        >
          <option value="">All categories</option>
          <option value="known_cve">CVE</option>
          <option value="exposed_admin_panel">Exposed Panels</option>
          <option value="missing_spf">DNS Issues</option>
          <option value="expired_certificate">TLS Issues</option>
          <option value="cors_misconfiguration">Misconfigurations</option>
          <option value="exposed_git">Information Leakage</option>
          <option value="default_credentials">Default Credentials</option>
        </select>

        {(severityFilter.length > 0 || statusFilter || categoryFilter || globalFilter) && (
          <button
            onClick={() => {
              setSeverityFilter([]);
              setStatusFilter("open");
              setCategoryFilter("");
              setGlobalFilter("");
            }}
            className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
          >
            <XCircle className="w-3 h-3" /> Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full data-table">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      style={{ width: header.column.getSize() }}
                      className={cn(header.column.getCanSort() && "cursor-pointer select-none")}
                      onClick={header.column.getToggleSortingHandler()}
                    >
                      <div className="flex items-center gap-1">
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {header.column.getCanSort() && (
                          <span className="text-muted-foreground">
                            {header.column.getIsSorted() === "asc" ? (
                              <ChevronUp className="w-3 h-3" />
                            ) : header.column.getIsSorted() === "desc" ? (
                              <ChevronDown className="w-3 h-3" />
                            ) : (
                              <ChevronsUpDown className="w-3 h-3 opacity-40" />
                            )}
                          </span>
                        )}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i}>
                    {columns.map((_, j) => (
                      <td key={j}>
                        <div className="skeleton h-4 rounded" style={{ width: `${60 + Math.random() * 40}%` }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : table.getRowModel().rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length} className="text-center py-16 text-muted-foreground">
                    <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No findings match your filters</p>
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <motion.tr
                    key={row.id}
                    className="group cursor-pointer"
                    onClick={() => setSelectedFinding(row.original)}
                    whileHover={{ backgroundColor: "rgba(30,41,59,0.4)" }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </motion.tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-xs text-muted-foreground">
              Page {page} of {data.pages} · {data.total.toLocaleString()} total
            </span>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1.5 rounded hover:bg-surface-700 disabled:opacity-40 text-muted-foreground hover:text-foreground"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              {Array.from({ length: Math.min(5, data.pages) }, (_, i) => {
                const pageNum = Math.max(1, Math.min(page - 2, data.pages - 4)) + i;
                return (
                  <button
                    key={pageNum}
                    onClick={() => setPage(pageNum)}
                    className={cn(
                      "w-7 h-7 rounded text-xs font-medium transition-colors",
                      pageNum === page
                        ? "bg-brand-600 text-white"
                        : "text-muted-foreground hover:text-foreground hover:bg-surface-700"
                    )}
                  >
                    {pageNum}
                  </button>
                );
              })}
              <button
                onClick={() => setPage(p => Math.min(data.pages, p + 1))}
                disabled={page === data.pages}
                className="p-1.5 rounded hover:bg-surface-700 disabled:opacity-40 text-muted-foreground hover:text-foreground"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Finding detail modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
