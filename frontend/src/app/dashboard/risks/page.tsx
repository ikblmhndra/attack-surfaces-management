"use client";

import { useState } from "react";
import {
  BarChart3, TrendingUp, TrendingDown, RefreshCw, Shield,
  AlertTriangle, Layers, ChevronLeft, ChevronRight
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, BarChart, Bar, ResponsiveContainer,
  XAxis, YAxis, CartesianGrid, Tooltip, Cell
} from "recharts";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { GradeRing, SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn, scoreToColor, scoreToGrade } from "@/lib/utils";
import { format } from "date-fns";

const CATEGORY_LABELS: Record<string, string> = {
  network_security: "Network Security",
  dns_health: "DNS Health",
  web_security: "Web Security",
  tls_security: "TLS Security",
  exposure_mgmt: "Exposure Management",
  patch_hygiene: "Patch Hygiene",
  info_leakage: "Information Leakage",
  reputation: "Reputation",
  misconfiguration: "Misconfiguration",
};

export default function RisksPage() {
  const { activeOrg } = useWorkspaceStore();
  const [days, setDays] = useState(30);

  const { data: scoreData, isLoading } = useQuery({
    queryKey: ["risk-scores", activeOrg?.id],
    queryFn: () => apiClient.get("/scores", { params: { org_id: activeOrg?.id, page_size: 1 } }).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 30_000,
  });

  const { data: history } = useQuery({
    queryKey: ["score-history-all", activeOrg?.id, days],
    queryFn: () => apiClient.get("/scores/history", { params: { org_id: activeOrg?.id, days } }).then(r => r.data),
    enabled: !!activeOrg?.id,
  });

  const { data: breakdown } = useQuery({
    queryKey: ["score-breakdown", activeOrg?.id],
    queryFn: () => apiClient.get("/scores/breakdown", { params: { org_id: activeOrg?.id } }).then(r => r.data),
    enabled: !!activeOrg?.id,
  });

  const latest = scoreData?.items?.[0] || scoreData;
  const historyData = history?.history || history?.items || [];
  // GET /scores/breakdown's real shape is { breakdown: {category: {...}, ...},
  // factors: [...], overall, grade } — "category_scores" doesn't exist on it.
  // breakdown.breakdown is keyed by category name (all 9 categories); the old
  // fallback to breakdown.factors (a sparse array, only categories with a
  // deduction, no category name as its own key) rendered as array indices
  // once run through Object.entries below.
  const breakdownData = breakdown?.breakdown || {};

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Risk Scores</h1>
          <p className="text-sm text-muted-foreground">
            {activeOrg?.name || "Select an organization"} · Score history and breakdown
          </p>
        </div>
      </div>

      {!activeOrg ? (
        <div className="glass-card flex items-center justify-center h-64">
          <div className="text-center text-muted-foreground">
            <BarChart3 className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select an organization to view risk scores</p>
          </div>
        </div>
      ) : (
        <>
          {/* KPI row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Overall Score", value: latest?.overall_score ?? latest?.overall ?? "—", sub: latest?.grade ? `Grade ${latest.grade}` : "—" },
              { label: "Critical", value: latest?.critical ?? 0, color: "text-red-400" },
              { label: "High", value: latest?.high ?? 0, color: "text-orange-400" },
              { label: "Total Findings", value: latest?.total_findings ?? "—" },
            ].map((kpi, i) => (
              <motion.div
                key={kpi.label}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="metric-card"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground">{kpi.label}</span>
                </div>
                <p className={cn("text-2xl font-bold tabular-nums", kpi.color || "text-foreground")}>
                  {typeof kpi.value === "number" ? kpi.value.toLocaleString() : kpi.value}
                </p>
                {kpi.sub && <p className="text-xs text-muted-foreground mt-1">{kpi.sub}</p>}
              </motion.div>
            ))}
          </div>

          {/* Main grid */}
          <div className="grid grid-cols-12 gap-4">
            {/* Score history */}
            <div className="col-span-12 lg:col-span-8 glass-card p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-foreground">Score History</h2>
                <div className="flex items-center gap-1">
                  {[7, 30, 90].map(d => (
                    <button
                      key={d}
                      onClick={() => setDays(d)}
                      className={cn(
                        "px-2 py-1 text-xs rounded border transition-colors",
                        days === d
                          ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                          : "bg-surface-800 border-surface-600 text-muted-foreground"
                      )}
                    >
                      {d}d
                    </button>
                  ))}
                </div>
              </div>
              {historyData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={historyData}>
                    <defs>
                      <linearGradient id="histGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="date" tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }}
                      tickFormatter={(v) => format(new Date(v), "MMM d")} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(222 47% 6%)",
                        border: "1px solid hsl(217 33% 14%)",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                    <Area type="monotone" dataKey="score" stroke="#0ea5e9" strokeWidth={2} fill="url(#histGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] flex items-center justify-center text-muted-foreground text-sm">
                  No score history available
                </div>
              )}
            </div>

            {/* Current grade */}
            <div className="col-span-12 lg:col-span-4 glass-card p-5 flex flex-col items-center justify-center">
              {latest ? (
                <>
                  <GradeRing score={latest.overall_score ?? latest.overall ?? 0} grade={latest.grade || scoreToGrade(latest.overall_score ?? 0)} size={140} />
                  <p className="text-xs text-muted-foreground mt-3">
                    Last computed: {latest.computed_at ? format(new Date(latest.computed_at), "MMM d, HH:mm") : "—"}
                  </p>
                </>
              ) : (
                <div className="text-center text-muted-foreground text-sm">
                  No score data yet
                </div>
              )}
            </div>

            {/* Category breakdown */}
            <div className="col-span-12 glass-card p-5">
              <h2 className="text-sm font-semibold text-foreground mb-4">Category Breakdown</h2>
              {Object.keys(breakdownData).length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {Object.entries(breakdownData).map(([key, val]: [string, any]) => {
                    const score = val.score ?? val;
                    const grade = val.grade || scoreToGrade(score);
                    const color = scoreToColor(score);
                    return (
                      <div key={key} className="bg-surface-800 rounded-xl p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs text-muted-foreground">
                            {CATEGORY_LABELS[key] || key.replace(/_/g, " ")}
                          </span>
                          <span className={cn("text-xs font-bold", `grade-${grade.toLowerCase()}`)}>{grade}</span>
                        </div>
                        <p className="text-2xl font-bold tabular-nums" style={{ color }}>
                          {typeof score === "number" ? `${Math.round(score)}` : score}
                        </p>
                        <div className="mt-2 h-1.5 bg-surface-700 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
                        </div>
                        {val.finding_count != null && (
                          <p className="text-xs text-muted-foreground mt-2">{val.finding_count} findings</p>
                        )}
                        {val.factors?.length > 0 && (
                          <div className="mt-2 space-y-1">
                            {val.factors.map((f: string, i: number) => (
                              <p key={i} className="text-xs text-muted-foreground">• {f}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-center text-muted-foreground text-sm py-8">
                  No breakdown data available. Run a scan to see category scores.
                </p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
