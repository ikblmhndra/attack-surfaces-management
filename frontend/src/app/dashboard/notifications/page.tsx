"use client";

import { useState } from "react";
import {
  Bell, RefreshCw, CheckCheck, Settings, Plus, Trash2,
  ChevronLeft, ChevronRight, Filter, AlertTriangle
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { apiClient, notificationsAPI } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/utils";

export default function NotificationsPage() {
  const qc = useQueryClient();
  const { canWrite } = useWorkspaceStore();

  const [activeTab, setActiveTab] = useState<"notifications" | "rules">("notifications");
  const [page, setPage] = useState(1);
  const [readFilter, setReadFilter] = useState<"all" | "unread" | "read">("all");
  const [showCreateRule, setShowCreateRule] = useState(false);

  const params = new URLSearchParams({ page: String(page), page_size: "20" });
  if (readFilter === "unread") params.set("is_read", "false");
  if (readFilter === "read") params.set("is_read", "true");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["notifications", params.toString()],
    queryFn: () => notificationsAPI.list(Object.fromEntries(params)).then(r => r.data),
    refetchInterval: 30_000,
  });

  const { data: rules } = useQuery({
    queryKey: ["notification-rules"],
    queryFn: () => notificationsAPI.getRules().then(r => r.data),
    enabled: activeTab === "rules",
  });

  const markAllRead = useMutation({
    mutationFn: () => notificationsAPI.markAllRead(),
    onSuccess: () => {
      toast.success("All notifications marked as read");
      qc.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  const totalPages = data ? Math.ceil(data.total / 20) : 0;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Notifications</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total ?? 0} total · {data?.items?.filter((n: any) => !n.is_read).length || 0} unread
          </p>
        </div>
        <div className="flex items-center gap-2">
          {markAllRead.isPending ? (
            <RefreshCw className="w-4 h-4 animate-spin text-muted-foreground" />
          ) : (
            <button
              onClick={() => markAllRead.mutate()}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              Mark All Read
            </button>
          )}
          <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border">
        <button
          onClick={() => setActiveTab("notifications")}
          className={cn(
            "px-4 py-2.5 text-sm font-medium border-b-2 transition-colors flex items-center gap-2",
            activeTab === "notifications" ? "border-brand-400 text-brand-400" : "border-transparent text-muted-foreground hover:text-foreground"
          )}
        >
          <Bell className="w-4 h-4" />
          Notifications
        </button>
        <button
          onClick={() => setActiveTab("rules")}
          className={cn(
            "px-4 py-2.5 text-sm font-medium border-b-2 transition-colors flex items-center gap-2",
            activeTab === "rules" ? "border-brand-400 text-brand-400" : "border-transparent text-muted-foreground hover:text-foreground"
          )}
        >
          <Settings className="w-4 h-4" />
          Rules
        </button>
      </div>

      {activeTab === "notifications" ? (
        <>
          {/* Read filter */}
          <div className="flex items-center gap-1">
            {(["all", "unread", "read"] as const).map(f => (
              <button
                key={f}
                onClick={() => { setReadFilter(f); setPage(1); }}
                className={cn(
                  "px-3 py-1.5 text-xs rounded-lg border transition-colors capitalize",
                  readFilter === f
                    ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                    : "bg-surface-800 border-surface-600 text-muted-foreground"
                )}
              >
                {f}
              </button>
            ))}
          </div>

          {/* List */}
          <div className="glass-card overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center h-48">
                <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : data?.items?.length > 0 ? (
              <div>
                {data.items.map((n: any) => (
                  <div
                    key={n.id}
                    className={cn(
                      "flex items-start gap-4 px-5 py-4 border-b border-border/50 last:border-0 hover:bg-surface-700/20 transition-colors",
                      !n.is_read && "bg-brand-500/[0.02]"
                    )}
                  >
                    <SeverityBadge severity={n.severity} compact className="mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium text-foreground">{n.title}</p>
                        {!n.is_read && <span className="w-1.5 h-1.5 rounded-full bg-brand-400 flex-shrink-0" />}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{n.message}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {formatDistanceToNow(new Date(n.created_at), { addSuffix: true })}
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground capitalize">{n.event_type?.replace(/_/g, " ")}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Bell className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">No notifications</p>
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
      ) : (
        /* Rules tab */
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Configure notification rules for alerting channels
            </p>
            {canWrite() && (
              <button
                onClick={() => setShowCreateRule(!showCreateRule)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-brand-600 hover:bg-brand-500 text-white font-medium transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                New Rule
              </button>
            )}
          </div>

          {/* Create rule form */}
          {showCreateRule && (
            <CreateRuleForm onClose={() => setShowCreateRule(false)} />
          )}

          <div className="glass-card overflow-hidden">
            {rules?.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full data-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Events</th>
                      <th>Channels</th>
                      <th>Min Severity</th>
                      <th>Status</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((rule: any) => (
                      <tr key={rule.id}>
                        <td>
                          <span className="text-sm font-medium text-foreground">{rule.name}</span>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1 max-w-[200px]">
                            {(rule.event_types || []).map((et: string) => (
                              <span key={et} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded">{et}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {(rule.channels || []).map((ch: string) => (
                              <span key={ch} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded capitalize">{ch}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <SeverityBadge severity={rule.min_severity} compact />
                        </td>
                        <td>
                          <span className={cn(
                            "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border",
                            rule.is_active
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                              : "bg-gray-500/10 text-gray-400 border-gray-500/20"
                          )}>
                            <span className={cn("w-1.5 h-1.5 rounded-full", rule.is_active ? "bg-emerald-400" : "bg-gray-400")} />
                            {rule.is_active ? "Active" : "Disabled"}
                          </span>
                        </td>
                        <td>
                          <button
                            onClick={() => {
                              if (confirm("Delete this notification rule?")) {
                                notificationsAPI.deleteRule(rule.id).then(() => {
                                  toast.success("Rule deleted");
                                  qc.invalidateQueries({ queryKey: ["notification-rules"] });
                                });
                              }
                            }}
                            className="p-1 rounded hover:bg-red-500/10 text-muted-foreground hover:text-red-400"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-40 text-muted-foreground">
                <Settings className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">No notification rules configured</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function CreateRuleForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [eventTypes, setEventTypes] = useState<string[]>(["finding.new"]);
  const [channels, setChannels] = useState<string[]>(["in_app"]);
  const [minSeverity, setMinSeverity] = useState("medium");
  const [isActive, setIsActive] = useState(true);

  const createMutation = useMutation({
    mutationFn: () =>
      notificationsAPI.createRule({ name, event_types: eventTypes, channels, min_severity: minSeverity, is_active: isActive }),
    onSuccess: () => {
      toast.success("Rule created");
      qc.invalidateQueries({ queryKey: ["notification-rules"] });
      onClose();
    },
    onError: () => toast.error("Failed to create rule"),
  });

  const toggleEvent = (e: string) => {
    setEventTypes(prev => prev.includes(e) ? prev.filter(x => x !== e) : [...prev, e]);
  };

  const toggleChannel = (ch: string) => {
    setChannels(prev => prev.includes(ch) ? prev.filter(x => x !== ch) : [...prev, ch]);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card p-5 space-y-4"
    >
      <h3 className="text-sm font-semibold text-foreground">New Notification Rule</h3>
      <div>
        <label className="block text-sm text-muted-foreground mb-1">Name</label>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g., Critical findings alert"
          className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
      </div>
      <div>
        <label className="block text-sm text-muted-foreground mb-2">Event Types</label>
        <div className="flex flex-wrap gap-2">
          {["finding.new", "scan.completed", "scan.failed", "score.updated", "asset.new"].map(et => (
            <button
              key={et}
              onClick={() => toggleEvent(et)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors",
                eventTypes.includes(et)
                  ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                  : "bg-surface-800 border-surface-600 text-muted-foreground"
              )}
            >
              {et.replace(/_/g, " ").replace(/\./g, ": ")}
            </button>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-sm text-muted-foreground mb-2">Channels</label>
        <div className="flex flex-wrap gap-2">
          {["in_app", "email", "slack", "webhook"].map(ch => (
            <button
              key={ch}
              onClick={() => toggleChannel(ch)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors capitalize",
                channels.includes(ch)
                  ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                  : "bg-surface-800 border-surface-600 text-muted-foreground"
              )}
            >
              {ch === "in_app" ? "In-App" : ch}
            </button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm text-muted-foreground mb-1">Minimum Severity</label>
          <select
            value={minSeverity}
            onChange={e => setMinSeverity(e.target.value)}
            className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {["info", "low", "medium", "high", "critical"].map(s => (
              <option key={s} value={s} className="capitalize">{s}</option>
            ))}
          </select>
        </div>
        <div className="flex items-end pb-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={isActive} onChange={e => setIsActive(e.target.checked)}
              className="rounded border-border bg-surface-800 text-brand-500 focus:ring-brand-500" />
            <span className="text-sm text-foreground">Active</span>
          </label>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={() => createMutation.mutate()}
          disabled={createMutation.isPending || !name.trim()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
        >
          {createMutation.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Create Rule
        </button>
        <button onClick={onClose} className="text-sm text-muted-foreground hover:text-foreground">Cancel</button>
      </div>
    </motion.div>
  );
}
