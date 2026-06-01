"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Building2, ArrowLeft, RefreshCw, Scan, Edit, AlertTriangle,
  Layers, Globe, Clock, Activity, TrendingUp, TrendingDown,
  ChevronRight, X, Save, Loader2, Timer
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import Link from "next/link";
import {
  AreaChart, Area, ResponsiveContainer, XAxis, YAxis,
  CartesianGrid, Tooltip
} from "recharts";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import {
  SeverityBadge, GradeRing, StatusBadge
} from "@/components/ui/SeverityBadge";
import { cn, formatNumber } from "@/lib/utils";
import { ScanModal } from "@/components/modals/ScanModal";

export default function OrganizationDetailPage() {
  const params = useParams();
  const router = useRouter();
  const qc = useQueryClient();
  const { canWrite } = useWorkspaceStore();
  const orgId = params.id as string;

  const [editing, setEditing] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [editForm, setEditForm] = useState({
    name: "", description: "", domains: "", ip_ranges: "", asns: "",
    company_name: "", industry: "", criticality: 3, environment: "production",
    auto_scan_enabled: true,
  });

  const updateOrg = useMutation({
    mutationFn: (data: any) => apiClient.put(`/organizations/${orgId}`, data),
    onSuccess: () => {
      toast.success("Organization updated");
      qc.invalidateQueries({ queryKey: ["organization", orgId] });
      setEditing(false);
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || "Failed to update"),
  });

  const openEditor = () => {
    setEditForm({
      name: org?.name || "",
      description: org?.description || "",
      domains: (org?.domains || []).join("\n"),
      ip_ranges: (org?.ip_ranges || []).join("\n"),
      asns: (org?.asns || []).join("\n"),
      company_name: org?.company_name || "",
      industry: org?.industry || "",
      criticality: org?.criticality || 3,
      environment: org?.environment || "production",
      auto_scan_enabled: org?.auto_scan_enabled ?? true,
    });
    setEditing(true);
  };

  const { data: org, isLoading } = useQuery({
    queryKey: ["organization", orgId],
    queryFn: () => apiClient.get(`/organizations/${orgId}`).then(r => r.data),
    enabled: !!orgId,
    refetchInterval: 30_000,
  });

  const { data: scoreHistory } = useQuery({
    queryKey: ["org-score-history", orgId],
    queryFn: () => apiClient.get(`/organizations/${orgId}/score-history?days=90`).then(r => r.data),
    enabled: !!orgId,
  });

  const { data: timeline } = useQuery({
    queryKey: ["org-timeline", orgId],
    queryFn: () => apiClient.get(`/organizations/${orgId}/timeline?days=30`).then(r => r.data),
    enabled: !!orgId,
  });

  const { data: recentScans } = useQuery({
    queryKey: ["org-scans", orgId],
    queryFn: () => apiClient.get(`/organizations/${orgId}/scans?page_size=5`).then(r => r.data),
    enabled: !!orgId,
    refetchInterval: 15_000,
  });

  const riskScore = org?.risk_score;
  const scoreTrend = scoreHistory?.history || [];
  const timelineEvents = timeline?.events || [];

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!org) {
    return (
      <div className="p-6 text-center text-muted-foreground">
        Organization not found
      </div>
    );
  }

  return (
    <>
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => router.push("/dashboard/organizations")} className="p-2 rounded-lg hover:bg-surface-700 text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-semibold text-foreground">{org.name}</h1>
              {org.description && (
                <span className="text-sm text-muted-foreground">· {org.description}</span>
              )}
              {riskScore && (
                <span className={cn("text-sm font-bold", `grade-${riskScore.grade?.toLowerCase()}`)}>
                  {riskScore.grade}
                </span>
              )}
            </div>
            <div className="flex items-center gap-3 mt-1 text-sm text-muted-foreground">
              <span>{org.domains?.length || 0} domains</span>
              <span>{org.total_assets?.toLocaleString() || 0} assets</span>
              <span>{org.total_findings} findings</span>
              <span>{org.auto_scan_enabled ? "Auto scan on" : "Auto scan off"}</span>
              {org.last_scan_at && (
                <span>Last scan {formatDistanceToNow(new Date(org.last_scan_at), { addSuffix: true })}</span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {canWrite() && (
            <>
              <button
                onClick={() => setShowScanModal(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-brand-600 hover:bg-brand-500 text-white font-medium transition-colors"
              >
                <Scan className="w-3.5 h-3.5" />
                Run Scan
              </button>
              <button
                onClick={openEditor}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground"
              >
                <Edit className="w-3.5 h-3.5" />
                Edit
              </button>
            </>
          )}
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="metric-card">
          <div className="flex items-center justify-between mb-2">
            <Layers className="w-4 h-4 text-brand-400" />
            <span className="text-xs text-muted-foreground">Total Assets</span>
          </div>
          <p className="text-2xl font-bold text-foreground tabular-nums">
            {formatNumber(org.total_assets)}
          </p>
        </div>
        <div className="metric-card">
          <div className="flex items-center justify-between mb-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-xs text-muted-foreground">Open Findings</span>
          </div>
          <p className="text-2xl font-bold text-red-400 tabular-nums">
            {org.total_findings || 0}
          </p>
        </div>
        <div className="metric-card">
          <div className="flex items-center justify-between mb-2">
            <Globe className="w-4 h-4 text-purple-400" />
            <span className="text-xs text-muted-foreground">Domains</span>
          </div>
          <p className="text-2xl font-bold text-foreground tabular-nums">
            {org.domains?.length || 0}
          </p>
        </div>
        <div className="metric-card">
          <div className="flex items-center justify-between mb-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span className="text-xs text-muted-foreground">Criticality</span>
          </div>
          <p className="text-2xl font-bold text-foreground tabular-nums">
            {org.criticality || "—"}/5
          </p>
        </div>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-12 gap-4">
        {/* Score trend */}
        <div className="col-span-12 lg:col-span-8 glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-foreground">Score History (90 days)</h2>
          </div>
          {scoreTrend.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={scoreTrend}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }}
                  tickFormatter={(v) => new Date(v).toLocaleDateString("en", { month: "short", day: "numeric" })} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(222 47% 6%)",
                    border: "1px solid hsl(217 33% 14%)",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Area type="monotone" dataKey="overall_score" stroke="#0ea5e9" strokeWidth={2} fill="url(#scoreGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-muted-foreground text-sm">
              No score data yet. Run a scan to see trends.
            </div>
          )}
        </div>

        {/* Grade ring */}
        <div className="col-span-12 lg:col-span-4 glass-card p-5 flex flex-col items-center justify-center">
          {riskScore ? (
            <>
              <GradeRing score={riskScore.overall} grade={riskScore.grade} size={140} />
              <div className="grid grid-cols-2 gap-3 mt-4 w-full">
                {["critical", "high", "medium", "low"].map(sev => (
                  <div key={sev} className="text-center">
                    <p className="text-xs text-muted-foreground capitalize">{sev}</p>
                    <p className={cn(
                      "text-lg font-bold tabular-nums",
                      sev === "critical" && "text-red-400",
                      sev === "high" && "text-orange-400",
                      sev === "medium" && "text-yellow-400",
                      sev === "low" && "text-blue-400",
                    )}>
                      {riskScore[sev] || 0}
                    </p>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="text-center text-muted-foreground text-sm">
              No score computed yet
            </div>
          )}
        </div>

        {/* Timeline */}
        <div className="col-span-12 lg:col-span-6 glass-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">Recent Activity</h2>
          {timelineEvents.length > 0 ? (
            <div className="space-y-3">
              {timelineEvents.slice(0, 10).map((event: any, i: number) => (
                <div key={i} className="flex items-start gap-3">
                  <div className={cn(
                    "w-2 h-2 rounded-full mt-1.5 flex-shrink-0",
                    event.type === "finding" ? "bg-red-400" :
                    event.type === "asset" ? "bg-brand-400" : "bg-muted-foreground"
                  )} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-foreground truncate">{event.description || event.message}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatDistanceToNow(new Date(event.timestamp || event.created_at), { addSuffix: true })}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
              No recent activity
            </div>
          )}
        </div>

        {/* Recent scans */}
        <div className="col-span-12 lg:col-span-6 glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-foreground">Recent Scans</h2>
            <Link href="/dashboard/scans" className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-1">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          {recentScans?.items?.length > 0 ? (
            <div className="space-y-2">
              {recentScans.items.map((scan: any) => (
                <div key={scan.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-surface-900/50">
                  <div className={cn(
                    "w-2 h-2 rounded-full flex-shrink-0",
                    scan.status === "completed" && "bg-emerald-400",
                    scan.status === "running" && "bg-brand-400 animate-pulse",
                    scan.status === "failed" && "bg-red-400",
                    scan.status === "pending" && "bg-yellow-400",
                  )} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-foreground capitalize">{scan.scan_type}</span>
                      <span className="text-xs text-muted-foreground capitalize">{scan.status}</span>
                    </div>
                    {scan.status === "running" && (
                      <div className="mt-1 h-1 bg-surface-700 rounded-full overflow-hidden">
                        <div className="h-full bg-brand-400 rounded-full transition-all" style={{ width: `${scan.progress_pct}%` }} />
                      </div>
                    )}
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
              No scans yet. Click &ldquo;Run Scan&rdquo; to start.
            </div>
          )}
        </div>
      </div>
    </div>

    {showScanModal && (
      <ScanModal orgId={orgId} onClose={() => setShowScanModal(false)} />
    )}

    <AnimatePresence>
      {editing && (
        <>
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={() => setEditing(false)}
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 8 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div className="w-full max-w-lg bg-surface-900 border border-border rounded-2xl shadow-2xl overflow-hidden">
              <div className="flex items-center justify-between p-5 border-b border-border">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-brand-500/10 flex items-center justify-center">
                    <Edit className="w-4.5 h-4.5 text-brand-400" />
                  </div>
                  <h2 className="text-sm font-semibold text-foreground">Edit Organization</h2>
                </div>
                <button onClick={() => setEditing(false)} className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-surface-700 text-muted-foreground">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <form
                onSubmit={(e) => { e.preventDefault(); updateOrg.mutate({
                  name: editForm.name,
                  description: editForm.description || null,
                  domains: editForm.domains.split("\n").map(s => s.trim()).filter(Boolean),
                  ip_ranges: editForm.ip_ranges.split("\n").map(s => s.trim()).filter(Boolean),
                  asns: editForm.asns.split("\n").map(s => s.trim()).filter(Boolean),
                  company_name: editForm.company_name || null,
                  industry: editForm.industry || null,
                  criticality: editForm.criticality,
                  environment: editForm.environment,
                  auto_scan_enabled: editForm.auto_scan_enabled,
                })}}
                className="p-5 space-y-4 max-h-[60vh] overflow-y-auto"
              >
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Name</label>
                  <input
                    value={editForm.name} onChange={(e) => setEditForm(f => ({...f, name: e.target.value}))}
                    className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-brand-500/50"
                    required
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Description</label>
                  <input
                    value={editForm.description} onChange={(e) => setEditForm(f => ({...f, description: e.target.value}))}
                    className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-brand-500/50"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Company</label>
                    <input
                      value={editForm.company_name} onChange={(e) => setEditForm(f => ({...f, company_name: e.target.value}))}
                      className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-brand-500/50"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Industry</label>
                    <input
                      value={editForm.industry} onChange={(e) => setEditForm(f => ({...f, industry: e.target.value}))}
                      className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-brand-500/50"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Domains (one per line)</label>
                  <textarea
                    value={editForm.domains} onChange={(e) => setEditForm(f => ({...f, domains: e.target.value}))}
                    rows={3}
                    className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground font-mono focus:outline-none focus:border-brand-500/50 resize-none"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">IP Ranges</label>
                    <textarea
                      value={editForm.ip_ranges} onChange={(e) => setEditForm(f => ({...f, ip_ranges: e.target.value}))}
                      rows={2}
                      className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground font-mono focus:outline-none focus:border-brand-500/50 resize-none"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">ASNs</label>
                    <textarea
                      value={editForm.asns} onChange={(e) => setEditForm(f => ({...f, asns: e.target.value}))}
                      rows={2}
                      className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground font-mono focus:outline-none focus:border-brand-500/50 resize-none"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Criticality (1-5)</label>
                    <select
                      value={editForm.criticality} onChange={(e) => setEditForm(f => ({...f, criticality: parseInt(e.target.value)}))}
                      className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-brand-500/50"
                    >
                      {[1,2,3,4,5].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5 block">Environment</label>
                    <select
                      value={editForm.environment} onChange={(e) => setEditForm(f => ({...f, environment: e.target.value}))}
                      className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-brand-500/50"
                    >
                      {["production", "staging", "development", "testing"].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                </div>
                <label className="flex items-center justify-between gap-4 rounded-lg border border-surface-700 bg-surface-800/60 px-3 py-3">
                  <div className="flex items-start gap-3">
                    <Timer className="mt-0.5 h-4 w-4 text-emerald-400" />
                    <div>
                      <p className="text-sm font-medium text-foreground">Automatic scheduled scans</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        Include this organization in default scheduler runs.
                      </p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={editForm.auto_scan_enabled}
                    onChange={(e) => setEditForm(f => ({...f, auto_scan_enabled: e.target.checked}))}
                    className="h-4 w-4 rounded border-border bg-surface-900 text-brand-500 focus:ring-brand-500"
                  />
                </label>

                <div className="flex items-center gap-3 pt-2">
                  <button type="button" onClick={() => setEditing(false)}
                    className="flex-1 px-3 py-2 rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground text-sm font-medium transition-colors"
                  >Cancel</button>
                  <button type="submit" disabled={updateOrg.isPending}
                    className="flex-1 px-3 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {updateOrg.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                    {updateOrg.isPending ? "Saving..." : "Save Changes"}
                  </button>
                </div>
              </form>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
    </>
  );
}
