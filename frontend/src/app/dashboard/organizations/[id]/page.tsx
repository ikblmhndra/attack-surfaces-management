"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Building2, ArrowLeft, RefreshCw, Scan, Edit, AlertTriangle,
  Layers, Globe, Clock, Activity, TrendingUp, TrendingDown,
  ChevronRight
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
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

export default function OrganizationDetailPage() {
  const params = useParams();
  const router = useRouter();
  const qc = useQueryClient();
  const { canWrite } = useWorkspaceStore();
  const orgId = params.id as string;

  const [editing, setEditing] = useState(false);

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

  const triggerScan = useMutation({
    mutationFn: () => apiClient.post(`/organizations/${orgId}/scans`, { scan_type: "full" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["org-scans"] });
    },
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
                onClick={() => triggerScan.mutate()}
                disabled={triggerScan.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-brand-600 hover:bg-brand-500 text-white font-medium transition-colors disabled:opacity-50"
              >
                <Scan className="w-3.5 h-3.5" />
                Run Scan
              </button>
              <button
                onClick={() => setEditing(!editing)}
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
  );
}
