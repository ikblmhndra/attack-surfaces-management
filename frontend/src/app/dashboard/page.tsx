"use client";

import { useEffect, useState, useCallback } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Shield, AlertTriangle, Globe, Cpu, TrendingDown, TrendingUp,
  RefreshCw, Scan, Bell, ChevronRight, Activity, Layers,
  Network, Lock, Eye, Server, Target, Zap
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, RadarChart, Radar,
  PolarGrid, PolarAngleAxis, ResponsiveContainer,
  XAxis, YAxis, CartesianGrid, Tooltip, Cell, PieChart, Pie
} from "recharts";
import { motion } from "framer-motion";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { apiClient } from "@/lib/api";
import { useRealtimeEvents } from "@/lib/useRealtimeEvents";
import { useWorkspaceStore } from "@/store/workspace";
import { SeverityBadge, GradeRing } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/utils";

const STAGGER = 0.05;

const fadeUp = {
  hidden: { opacity: 0, y: 12 },
  show: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * STAGGER, duration: 0.35, ease: "easeOut" },
  }),
};

// ── Score category radar data ─────────────────────────────────
const CATEGORY_LABELS: Record<string, string> = {
  network_security: "Network",
  dns_health: "DNS",
  web_security: "Web",
  tls_security: "TLS",
  exposure_mgmt: "Exposure",
  patch_hygiene: "Patches",
  info_leakage: "Info Leak",
  reputation: "Reputation",
  misconfiguration: "Misconfig",
};

export default function DashboardPage() {
  const { activeOrg } = useWorkspaceStore();
  const queryClient = useQueryClient();
  useRealtimeEvents(activeOrg?.id);
  const [refreshing, setRefreshing] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanOrgId, setScanOrgId] = useState("");
  const [scanType, setScanType] = useState("full");
  const [scanProfile, setScanProfile] = useState("deep_authorized");

  const triggerScan = useMutation({
    mutationFn: (data: { org_id: string; scan_type: string; scan_profile?: string }) =>
      apiClient.post(`/organizations/${data.org_id}/scans`, {
        scan_type: data.scan_type,
        scan_profile: data.scan_type === "quick" ? "safe" : (data.scan_profile || "deep_authorized"),
      }),
    onSuccess: () => {
      setShowScanModal(false);
      queryClient.invalidateQueries({ queryKey: ["recent-scans"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  // ── Data fetching ─────────────────────────────────────────
  const { data: orgs, refetch: refetchOrgs } = useQuery({
    queryKey: ["organizations"],
    queryFn: () => apiClient.get("/organizations?page_size=10").then(r => r.data),
    refetchInterval: 60_000,
  });

  const { data: scoreData, refetch: refetchScore } = useQuery({
    queryKey: ["org-score", activeOrg?.id],
    queryFn: () => apiClient.get(`/organizations/${activeOrg?.id}`).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 30_000,
  });

  const { data: scoreHistory } = useQuery({
    queryKey: ["score-history", activeOrg?.id],
    queryFn: () => apiClient.get(`/organizations/${activeOrg?.id}/score-history?days=30`).then(r => r.data),
    enabled: !!activeOrg?.id,
  });

  const { data: findings } = useQuery({
    queryKey: ["findings-summary", activeOrg?.id],
    queryFn: () => apiClient.get(`/findings?org_id=${activeOrg?.id}&page_size=5&sort_by=severity&status=open`).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 30_000,
  });

  const { data: recentScans } = useQuery({
    queryKey: ["recent-scans", activeOrg?.id],
    queryFn: () => apiClient.get(`/organizations/${activeOrg?.id}/scans?page_size=5`).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 15_000,
  });

  const { data: notifications } = useQuery({
    queryKey: ["notifications"],
    queryFn: () => apiClient.get("/notifications?page_size=5&is_read=false").then(r => r.data),
    refetchInterval: 30_000,
  });

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    await Promise.all([refetchOrgs(), refetchScore()]);
    setRefreshing(false);
  }, [refetchOrgs, refetchScore]);

  // Derived data
  const score = scoreData?.risk_score;
  const categoryScores = score?.category_scores
    ? Object.entries(score.category_scores).map(([key, val]: [string, any]) => ({
        category: CATEGORY_LABELS[key] || key,
        score: val.score,
        fullMark: 100,
      }))
    : [];

  const trendData = scoreHistory?.history?.map((h: any) => ({
    date: new Date(h.date).toLocaleDateString("en", { month: "short", day: "numeric" }),
    score: h.overall_score,
    critical: h.critical,
    high: h.high,
  })) || [];

  const severityDistribution = score ? [
    { name: "Critical", value: score.critical, color: "#ef4444" },
    { name: "High", value: score.high, color: "#f97316" },
    { name: "Medium", value: score.medium, color: "#eab308" },
    { name: "Low", value: score.low, color: "#3b82f6" },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="min-h-screen bg-background">
      {/* ── Background grid ──────────────────────────────── */}
      <div
        className="fixed inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: "linear-gradient(rgba(14,165,233,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.05) 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      />
      <div className="fixed top-0 left-0 right-0 h-96 pointer-events-none"
        style={{ background: "radial-gradient(ellipse at top, rgba(14,165,233,0.08) 0%, transparent 70%)" }}
      />

      <div className="relative px-6 py-6 max-w-[1600px] mx-auto space-y-6">

        {/* ── Header ───────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between"
        >
          <div>
            <h1 className="text-2xl font-semibold text-foreground tracking-tight">
              Security Posture Overview
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              {activeOrg?.name || "Select an organization"} ·{" "}
              {score?.computed_at
                ? `Updated ${formatDistanceToNow(new Date(score.computed_at), { addSuffix: true })}`
                : "No score data"}
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* Unread notifications badge */}
            {notifications?.total > 0 && (
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium"
              >
                <Bell className="w-3.5 h-3.5" />
                {notifications.total} unread
              </motion.div>
            )}

            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-sm text-foreground transition-colors"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", refreshing && "animate-spin")} />
              Refresh
            </button>

            <button
              onClick={() => { setScanOrgId(activeOrg?.id || ""); setShowScanModal(true); }}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-sm text-white font-medium transition-colors"
            >
              <Scan className="w-3.5 h-3.5" />
              New Scan
            </button>
          </div>
        </motion.div>

        {/* ── Top KPI row ───────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              label: "Overall Score",
              value: score?.overall ?? "—",
              sub: `Grade ${score?.grade ?? "—"}`,
              icon: Shield,
              color: "brand",
              trend: null,
              special: "score",
            },
            {
              label: "Total Assets",
              value: scoreData?.total_assets?.toLocaleString() ?? "—",
              sub: "Active assets",
              icon: Layers,
              color: "cyan",
              trend: "+12 this week",
              up: true,
            },
            {
              label: "Open Findings",
              // total_findings is a live count on the org response itself, not
              // nested under risk_score (which has no such field) — this was
              // silently reading undefined forever.
              value: scoreData?.total_findings?.toLocaleString() ?? "—",
              sub: `${score?.critical ?? 0} critical`,
              icon: AlertTriangle,
              color: score?.critical > 0 ? "red" : "orange",
              trend: score?.critical > 0 ? `${score.critical} need immediate action` : "No critical issues",
              up: false,
            },
            {
              label: "Attack Surface",
              value: orgs?.total?.toLocaleString() ?? "—",
              sub: "Organizations monitored",
              icon: Globe,
              color: "purple",
              trend: "Continuous monitoring active",
              up: true,
            },
          ].map((kpi, i) => (
            <motion.div
              key={kpi.label}
              custom={i}
              variants={fadeUp}
              initial="hidden"
              animate="show"
              className="metric-card"
            >
              <div className="flex items-start justify-between mb-3">
                <div className={cn(
                  "w-9 h-9 rounded-lg flex items-center justify-center",
                  kpi.color === "brand" && "bg-brand-500/10 text-brand-400",
                  kpi.color === "cyan" && "bg-cyan-500/10 text-cyan-400",
                  kpi.color === "red" && "bg-red-500/10 text-red-400",
                  kpi.color === "orange" && "bg-orange-500/10 text-orange-400",
                  kpi.color === "purple" && "bg-purple-500/10 text-purple-400",
                )}>
                  <kpi.icon className="w-4.5 h-4.5" />
                </div>
                <span className="text-xs text-muted-foreground">{kpi.label}</span>
              </div>

              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold tabular-nums text-foreground">
                  {kpi.value}
                </span>
                {kpi.special === "score" && score?.grade && (
                  <span className={cn(
                    "text-lg font-bold mb-0.5",
                    `grade-${score.grade.toLowerCase()}`
                  )}>
                    {score.grade}
                  </span>
                )}
              </div>

              <div className="mt-1 flex items-center gap-1.5">
                <span className="text-xs text-muted-foreground">{kpi.sub}</span>
              </div>

              {kpi.trend && (
                <div className={cn(
                  "mt-2 flex items-center gap-1 text-xs",
                  kpi.up ? "text-emerald-400" : kpi.color === "red" ? "text-red-400" : "text-muted-foreground"
                )}>
                  {kpi.up ? <TrendingUp className="w-3 h-3" /> : kpi.color === "red" ? <TrendingDown className="w-3 h-3" /> : null}
                  {kpi.trend}
                </div>
              )}
            </motion.div>
          ))}
        </div>

        {/* ── Main content grid ─────────────────────────────── */}
        <div className="grid grid-cols-12 gap-4">

          {/* Score trend + category radar (8 cols) */}
          <motion.div
            custom={4}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="col-span-12 lg:col-span-8 glass-card p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-foreground">Risk Score Trend</h2>
                <p className="text-xs text-muted-foreground">30-day historical view</p>
              </div>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-brand-400 inline-block" />
                  Score
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-400 inline-block" />
                  Critical
                </span>
              </div>
            </div>

            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={trendData} margin={{ left: -20, right: 0 }}>
                  <defs>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="date" tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(222 47% 6%)",
                      border: "1px solid hsl(217 33% 14%)",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="#0ea5e9"
                    strokeWidth={2}
                    fill="url(#scoreGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[220px] flex items-center justify-center text-muted-foreground text-sm">
                No score history yet. Run your first scan to see trends.
              </div>
            )}
          </motion.div>

          {/* Score breakdown ring (4 cols) */}
          <motion.div
            custom={5}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="col-span-12 lg:col-span-4 glass-card p-5 flex flex-col"
          >
            <h2 className="text-sm font-semibold text-foreground mb-1">Security Score</h2>
            <p className="text-xs text-muted-foreground mb-4">Current posture by category</p>

            {score ? (
              <>
                <div className="flex items-center justify-center mb-4">
                  <GradeRing score={score.overall} grade={score.grade} size={140} />
                </div>

                {categoryScores.length > 0 && (
                  <ResponsiveContainer width="100%" height={160}>
                    <RadarChart data={categoryScores}>
                      <PolarGrid stroke="hsl(217 33% 14%)" />
                      <PolarAngleAxis
                        dataKey="category"
                        tick={{ fontSize: 9, fill: "hsl(215 20% 55%)" }}
                      />
                      <Radar
                        dataKey="score"
                        stroke="#0ea5e9"
                        fill="#0ea5e9"
                        fillOpacity={0.15}
                        strokeWidth={1.5}
                      />
                    </RadarChart>
                  </ResponsiveContainer>
                )}
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
                No score computed yet
              </div>
            )}
          </motion.div>

          {/* Findings by severity (4 cols) */}
          <motion.div
            custom={6}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="col-span-12 lg:col-span-4 glass-card p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-foreground">Findings Distribution</h2>
                <p className="text-xs text-muted-foreground">By severity</p>
              </div>
            </div>

            {severityDistribution.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={140}>
                  <PieChart>
                    <Pie
                      data={severityDistribution}
                      cx="50%"
                      cy="50%"
                      innerRadius={42}
                      outerRadius={62}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {severityDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} fillOpacity={0.85} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(222 47% 6%)",
                        border: "1px solid hsl(217 33% 14%)",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>

                <div className="grid grid-cols-2 gap-2 mt-2">
                  {severityDistribution.map((s) => (
                    <div key={s.name} className="flex items-center gap-2">
                      <span
                        className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{ backgroundColor: s.color }}
                      />
                      <span className="text-xs text-muted-foreground">{s.name}</span>
                      <span className="text-xs font-medium text-foreground ml-auto tabular-nums">
                        {s.value}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-[140px] flex items-center justify-center">
                <div className="text-center">
                  <Shield className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                  <p className="text-xs text-muted-foreground">No open findings</p>
                </div>
              </div>
            )}
          </motion.div>

          {/* Category scores (8 cols) */}
          <motion.div
            custom={7}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="col-span-12 lg:col-span-8 glass-card p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-foreground">Category Breakdown</h2>
                <p className="text-xs text-muted-foreground">Score per security domain</p>
              </div>
            </div>

            <div className="space-y-3">
              {score ? Object.entries(score.category_scores || {}).map(([key, val]: [string, any]) => {
                const s = val.score;
                const color = s >= 90 ? "#10b981" : s >= 75 ? "#3b82f6" : s >= 60 ? "#eab308" : s >= 40 ? "#f97316" : "#ef4444";
                return (
                  <div key={key}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-muted-foreground">
                        {CATEGORY_LABELS[key] || key}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium tabular-nums" style={{ color }}>
                          {s}/100
                        </span>
                        <span className={cn("text-xs font-bold", `grade-${val.grade?.toLowerCase()}`)}>
                          {val.grade}
                        </span>
                      </div>
                    </div>
                    <div className="h-1.5 bg-surface-700 rounded-full overflow-hidden">
                      <motion.div
                        className="h-full rounded-full"
                        style={{ backgroundColor: color }}
                        initial={{ width: 0 }}
                        animate={{ width: `${s}%` }}
                        transition={{ duration: 0.8, ease: "easeOut", delay: 0.1 }}
                      />
                    </div>
                  </div>
                );
              }) : (
                <p className="text-sm text-muted-foreground text-center py-4">
                  Run a scan to see category scores
                </p>
              )}
            </div>
          </motion.div>

          {/* Recent findings (6 cols) */}
          <motion.div
            custom={8}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="col-span-12 lg:col-span-6 glass-card p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-foreground">Recent Critical Findings</h2>
              <a href="/dashboard/findings" className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-1">
                View all <ChevronRight className="w-3 h-3" />
              </a>
            </div>

            <div className="space-y-2">
              {findings?.items?.length > 0 ? (
                findings.items.slice(0, 5).map((f: any) => (
                  <div key={f.id} className="flex items-start gap-3 p-3 rounded-lg bg-surface-900/50 hover:bg-surface-700/30 transition-colors cursor-pointer">
                    <SeverityBadge severity={f.severity} compact />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-foreground truncate font-medium">{f.title}</p>
                      <p className="text-xs text-muted-foreground truncate mt-0.5">{f.affected_url}</p>
                    </div>
                    <span className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatDistanceToNow(new Date(f.first_seen), { addSuffix: true })}
                    </span>
                  </div>
                ))
              ) : (
                <div className="flex items-center justify-center h-24 text-muted-foreground text-sm">
                  No findings yet
                </div>
              )}
            </div>
          </motion.div>

          {/* Scan activity feed (6 cols) */}
          <motion.div
            custom={9}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="col-span-12 lg:col-span-6 glass-card p-5"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-foreground">Scan Activity</h2>
              <a href="/dashboard/scans" className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-1">
                View all <ChevronRight className="w-3 h-3" />
              </a>
            </div>

            <div className="space-y-2">
              {recentScans?.items?.length > 0 ? (
                recentScans.items.map((scan: any) => (
                  <ScanActivityRow key={scan.id} scan={scan} />
                ))
              ) : (
                <div className="flex items-center justify-center h-24 text-muted-foreground text-sm">
                  No scans yet. Start your first scan above.
                </div>
              )}
            </div>
          </motion.div>

          {/* Organization scorecard grid */}
          {orgs?.items?.length > 0 && (
            <motion.div
              custom={10}
              variants={fadeUp}
              initial="hidden"
              animate="show"
              className="col-span-12 glass-card p-5"
            >
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-foreground">Organization Scorecards</h2>
                <a href="/dashboard/organizations" className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-1">
                  Manage <ChevronRight className="w-3 h-3" />
                </a>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                {orgs.items.slice(0, 10).map((org: any, i: number) => (
                  <OrgScoreCard key={org.id} org={org} index={i} />
                ))}
              </div>
            </motion.div>
          )}
        </div>
      </div>

      {/* Scan Modal */}
      {showScanModal && (
        <Dialog.Root open onOpenChange={(open) => { if (!open) setShowScanModal(false); }}>
          <Dialog.Portal>
            <Dialog.Overlay asChild>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
              />
            </Dialog.Overlay>
            <Dialog.Content asChild>
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 bg-surface-800 border border-border rounded-xl p-5 space-y-4 shadow-2xl focus:outline-none"
              >
            <Dialog.Title asChild>
              <h2 className="text-base font-semibold text-foreground">New Scan</h2>
            </Dialog.Title>
            <Dialog.Description asChild>
              <span className="sr-only">Configure and launch a new scan for an organization</span>
            </Dialog.Description>

            <div className="space-y-3">
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Organization</label>
                <select
                  value={scanOrgId}
                  onChange={e => setScanOrgId(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-900 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  <option value="">Select organization</option>
                  {orgs?.items?.map((org: any) => (
                    <option key={org.id} value={org.id}>{org.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs text-muted-foreground mb-1">Scan Type</label>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { value: "full", label: "Full Scan", desc: "Discovery, ports, vulns, screenshots" },
                    { value: "quick", label: "Quick Scan", desc: "DNS, TLS, HTTP headers only" },
                    { value: "discovery", label: "Discovery", desc: "Subdomains & DNS only" },
                    { value: "vuln", label: "Vulnerability", desc: "Nuclei scan only" },
                  ].map(opt => (
                    <button
                      key={opt.value}
                      onClick={() => setScanType(opt.value)}
                      className={`text-left p-3 rounded-lg border transition-colors ${
                        scanType === opt.value
                          ? "border-brand-500 bg-brand-500/10 text-brand-400"
                          : "border-border bg-surface-900 text-muted-foreground hover:border-brand-500/50"
                      }`}
                    >
                      <div className="text-sm font-medium">{opt.label}</div>
                      <div className="text-[10px] opacity-70 mt-0.5">{opt.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {(scanType === "full" || scanType === "vuln") && (
                <div>
                  <label className="block text-xs text-muted-foreground mb-1">Scan Profile</label>
                  <select
                    value={scanProfile}
                    onChange={e => setScanProfile(e.target.value)}
                    className="w-full px-3 py-2 bg-surface-900 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                  >
                    <option value="deep_authorized">Deep Authorized - broad safe coverage</option>
                    <option value="default">Default - balanced coverage</option>
                    <option value="safe">Safe - critical/high only</option>
                  </select>
                </div>
              )}
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={() => setShowScanModal(false)}
                className="flex-1 px-4 py-2 rounded-lg bg-surface-700 hover:bg-surface-600 border border-border text-sm text-foreground transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => scanOrgId && triggerScan.mutate({ org_id: scanOrgId, scan_type: scanType, scan_profile: scanProfile })}
                disabled={!scanOrgId || triggerScan.isPending}
                className="flex-1 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-sm text-white font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {triggerScan.isPending ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Zap className="w-3.5 h-3.5" />
                )}
                Start Scan
              </button>
            </div>
              </motion.div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────

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

function getScanProgressLabel(scan: any): string {
  const nuclei = scan.phase_status?.nuclei;
  if (scan.status === "running" && nuclei?.expected_batches) {
    return `nuclei ${nuclei.completed_batches ?? 0}/${nuclei.expected_batches} batches`;
  }
  if (scan.total_tasks) {
    return `${scan.completed_tasks ?? 0}/${scan.total_tasks} tasks`;
  }
  return getPhaseLabel(scan.progress_pct, scan.status);
}

function ScanActivityRow({ scan }: { scan: any }) {
  const statusColors: Record<string, string> = {
    completed: "text-emerald-400",
    running: "text-brand-400",
    failed: "text-red-400",
    pending: "text-yellow-400",
    queued: "text-yellow-400",
  };

  const statusIconMap: Record<string, typeof Activity> = {
    completed: Activity,
    running: Scan,
    failed: AlertTriangle,
    pending: RefreshCw,
    queued: RefreshCw,
  };
  const StatusIcon = statusIconMap[scan.status] || Activity;

  return (
    <div className="flex items-center gap-3 p-2.5 rounded-lg bg-surface-900/50 hover:bg-surface-700/30 transition-colors">
      <StatusIcon className={cn("w-4 h-4 flex-shrink-0", statusColors[scan.status] || "text-muted-foreground",
        scan.status === "running" && "animate-spin")} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-foreground capitalize">{scan.scan_type} scan</span>
          <span className={cn("text-xs capitalize", statusColors[scan.status] || "text-muted-foreground")}>
            {scan.status}
          </span>
        </div>
        {scan.status === "running" && (
          <div className="mt-1.5 space-y-0.5">
            <div className="h-1 bg-surface-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-brand-400 rounded-full transition-all duration-500"
                style={{ width: `${scan.progress_pct}%` }}
              />
            </div>
            <span className="text-[10px] text-muted-foreground/70">
              {getScanProgressLabel(scan)}
            </span>
          </div>
        )}
      </div>
      <span className="text-xs text-muted-foreground whitespace-nowrap">
        {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
      </span>
    </div>
  );
}

function OrgScoreCard({ org, index }: { org: any; index: number }) {
  const score = org.current_score;
  const grade = score?.grade ?? "—";
  const gradeColorMap: Record<string, string> = {
    A: "#10b981", B: "#3b82f6", C: "#eab308", D: "#f97316", F: "#ef4444", "—": "#6b7280",
  };
  const gradeColor = gradeColorMap[grade] || "#6b7280";

  return (
    <motion.a
      href={`/dashboard/organizations/${org.id}`}
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay: index * 0.05 }}
      className="p-3.5 rounded-xl bg-surface-900/50 border border-surface-700/50 hover:border-surface-600 hover:bg-surface-700/30 transition-all cursor-pointer block"
    >
      <div className="flex items-center justify-between mb-2">
        <span
          className="text-2xl font-bold"
          style={{ color: gradeColor }}
        >
          {grade}
        </span>
        {score?.critical > 0 && (
          <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded font-medium">
            {score.critical} crit
          </span>
        )}
      </div>
      <p className="text-xs font-medium text-foreground truncate">{org.name}</p>
      <p className="text-xs text-muted-foreground mt-0.5">
        {score ? `${score.overall}/100` : "Not scanned"}
      </p>
      <div className="mt-2 h-1 bg-surface-700 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{
            width: `${score?.overall ?? 0}%`,
            backgroundColor: gradeColor,
          }}
        />
      </div>
    </motion.a>
  );
}
