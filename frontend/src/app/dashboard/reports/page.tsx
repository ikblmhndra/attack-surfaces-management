"use client";

import { useState } from "react";
import {
  FileText, RefreshCw, Download, Calendar, Building2,
  CheckCircle, AlertTriangle, Clock, Globe
} from "lucide-react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { format } from "date-fns";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { apiClient, reportsAPI } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

type ReportType = "executive" | "technical" | "compliance" | "custom";

const REPORT_TYPES: { id: ReportType; label: string; description: string }[] = [
  { id: "executive", label: "Executive Summary", description: "High-level overview for management" },
  { id: "technical", label: "Technical Report", description: "Detailed findings with evidence" },
  { id: "compliance", label: "Compliance Report", description: "PCI-DSS, SOC2, ISO 27001 mapping" },
  { id: "custom", label: "Custom Report", description: "Select specific sections and data" },
];

export default function ReportsPage() {
  const { activeOrg } = useWorkspaceStore();
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [dateRange, setDateRange] = useState<"7" | "30" | "90">("30");
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeEvidence, setIncludeEvidence] = useState(true);

  const generateMutation = useMutation({
    mutationFn: () =>
      reportsAPI.generate({
        org_id: activeOrg?.id,
        report_type: reportType,
        date_range_days: parseInt(dateRange),
        include_charts: includeCharts,
        include_evidence: includeEvidence,
      }),
    onSuccess: () => {
      toast.success("Report generation started");
    },
    onError: () => toast.error("Failed to generate report"),
  });

  const { data: recentReports } = useQuery({
    queryKey: ["recent-reports", activeOrg?.id],
    queryFn: () => apiClient.get("/reports", { params: { org_id: activeOrg?.id, page_size: 10 } }).then(r => r.data),
    enabled: !!activeOrg?.id,
  });

  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const handleDownload = async (report: any) => {
    setDownloadingId(report.id);
    try {
      const res = await reportsAPI.download(report.id);
      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${report.id.slice(0, 8)}.${report.format || "pdf"}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error("Failed to download report");
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Reports</h1>
          <p className="text-sm text-muted-foreground">
            Generate and download security reports
          </p>
        </div>
      </div>

      {!activeOrg ? (
        <div className="glass-card flex items-center justify-center h-64">
          <div className="text-center text-muted-foreground">
            <FileText className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select an organization to generate reports</p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-12 gap-6">
          {/* Report config */}
          <div className="col-span-12 lg:col-span-7 space-y-4">
            <div className="glass-card p-5 space-y-4">
              <h2 className="text-sm font-semibold text-foreground">Generate Report</h2>

              {/* Report type */}
              <div className="grid grid-cols-2 gap-3">
                {REPORT_TYPES.map(rt => (
                  <button
                    key={rt.id}
                    onClick={() => setReportType(rt.id)}
                    className={cn(
                      "p-4 rounded-xl border text-left transition-all",
                      reportType === rt.id
                        ? "bg-brand-500/10 border-brand-500/30"
                        : "bg-surface-800 border-surface-600 hover:border-surface-500"
                    )}
                  >
                    <p className="text-sm font-medium text-foreground">{rt.label}</p>
                    <p className="text-xs text-muted-foreground mt-1">{rt.description}</p>
                  </button>
                ))}
              </div>

              {/* Options */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-muted-foreground mb-1">Date Range</label>
                  <div className="flex items-center gap-1">
                    {(["7", "30", "90"] as const).map(d => (
                      <button
                        key={d}
                        onClick={() => setDateRange(d)}
                        className={cn(
                          "px-3 py-1.5 text-xs rounded border transition-colors",
                          dateRange === d
                            ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                            : "bg-surface-800 border-surface-600 text-muted-foreground"
                        )}
                      >
                        {d} days
                      </button>
                    ))}
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={includeCharts} onChange={e => setIncludeCharts(e.target.checked)}
                      className="rounded border-border bg-surface-800 text-brand-500 focus:ring-brand-500" />
                    <span className="text-sm text-foreground">Include charts</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={includeEvidence} onChange={e => setIncludeEvidence(e.target.checked)}
                      className="rounded border-border bg-surface-800 text-brand-500 focus:ring-brand-500" />
                    <span className="text-sm text-foreground">Include evidence</span>
                  </label>
                </div>
              </div>

              <button
                onClick={() => generateMutation.mutate()}
                disabled={generateMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
              >
                {generateMutation.isPending ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <FileText className="w-4 h-4" />
                )}
                Generate Report
              </button>
            </div>
          </div>

          {/* Recent reports sidebar */}
          <div className="col-span-12 lg:col-span-5">
            <div className="glass-card p-5">
              <h2 className="text-sm font-semibold text-foreground mb-4">Recent Reports</h2>
              {recentReports?.items?.length > 0 ? (
                <div className="space-y-2">
                  {recentReports.items.map((report: any) => (
                    <div key={report.id} className="flex items-center gap-3 p-3 rounded-lg bg-surface-800/50 hover:bg-surface-700/30 transition-colors">
                      <div className="w-8 h-8 rounded-lg bg-brand-500/10 flex items-center justify-center">
                        <FileText className="w-4 h-4 text-brand-400" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-foreground truncate capitalize">
                          {report.report_type || report.type} Report
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {report.created_at ? format(new Date(report.created_at), "MMM d, yyyy") : "—"}
                        </p>
                      </div>
                      {report.status === "completed" ? (
                        <button
                          onClick={() => handleDownload(report)}
                          disabled={downloadingId === report.id}
                          className="p-2 rounded hover:bg-surface-700 text-muted-foreground hover:text-foreground disabled:opacity-50"
                        >
                          {downloadingId === report.id ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                          ) : (
                            <Download className="w-4 h-4" />
                          )}
                        </button>
                      ) : report.status === "generating" ? (
                        <RefreshCw className="w-4 h-4 animate-spin text-muted-foreground" />
                      ) : (
                        <Clock className="w-4 h-4 text-muted-foreground" />
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No reports generated yet
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
