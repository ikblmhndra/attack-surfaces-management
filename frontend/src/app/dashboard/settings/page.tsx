"use client";

import { useState, useEffect, useRef } from "react";
import {
  Settings, Save, Building2, Globe, AlertTriangle,
  CheckCircle, RefreshCw
} from "lucide-react";
import { motion } from "framer-motion";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { user, workspaceId, canAdmin } = useWorkspaceStore();
  const qc = useQueryClient();

  const [workspaceName, setWorkspaceName] = useState("");
  const [scanInterval, setScanInterval] = useState("24");
  const [maxConcurrent, setMaxConcurrent] = useState("3");
  const [autoResolve, setAutoResolve] = useState(false);
  const [autoScanEnabled, setAutoScanEnabled] = useState(true);
  const initialized = useRef(false);

  const { data: workspace } = useQuery({
    queryKey: ["workspace-settings"],
    queryFn: () => apiClient.get("/workspaces").then(r => r.data),
    enabled: !!workspaceId,
  });

  const saveMutation = useMutation({
    mutationFn: (data: any) => apiClient.put(`/workspaces`, data),
    onSuccess: () => {
      toast.success("Settings saved");
      qc.invalidateQueries({ queryKey: ["workspace-settings"] });
    },
    onError: () => toast.error("Failed to save settings"),
  });

  useEffect(() => {
    if (workspace?.name && !initialized.current) {
      setWorkspaceName(workspace.name);
      if (workspace.settings?.auto_scan_enabled !== undefined) {
        setAutoScanEnabled(workspace.settings.auto_scan_enabled);
      }
      if (workspace.settings?.scan_interval_hours) {
        setScanInterval(String(workspace.settings.scan_interval_hours));
      }
      if (workspace.settings?.max_concurrent_scans) {
        setMaxConcurrent(String(workspace.settings.max_concurrent_scans));
      }
      if (workspace.settings?.auto_resolve_findings !== undefined) {
        setAutoResolve(workspace.settings.auto_resolve_findings);
      }
      initialized.current = true;
    }
  }, [workspace?.name, workspace?.settings]);

  const handleSave = () => {
    saveMutation.mutate({
      name: workspaceName,
      scan_interval_hours: parseInt(scanInterval),
      max_concurrent_scans: parseInt(maxConcurrent),
      auto_resolve_findings: autoResolve,
      auto_scan_enabled: autoScanEnabled,
    });
  };

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Workspace Settings</h1>
        <p className="text-sm text-muted-foreground">
          Manage your workspace configuration
        </p>
      </div>

      <div className="space-y-6">
        {/* General */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Building2 className="w-4 h-4 text-brand-400" />
            General
          </h2>
          <div>
            <label className="block text-sm text-muted-foreground mb-1">Workspace Name</label>
            <input
              value={workspaceName}
              onChange={e => setWorkspaceName(e.target.value)}
              className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              disabled={!canAdmin()}
            />
          </div>
          {workspace && (
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-surface-800 rounded-lg p-3">
                <p className="text-xs text-muted-foreground">Plan</p>
                <p className="text-sm font-medium text-foreground capitalize">{workspace.plan || "free"}</p>
              </div>
              <div className="bg-surface-800 rounded-lg p-3">
                <p className="text-xs text-muted-foreground">Max Organizations</p>
                <p className="text-sm font-medium text-foreground">{workspace.max_organizations ?? "—"}</p>
              </div>
            </div>
          )}
        </div>

        {/* Scan Configuration */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <RefreshCw className="w-4 h-4 text-brand-400" />
            Scan Configuration
          </h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Scan Interval (hours)</label>
              <input
                type="number"
                value={scanInterval}
                onChange={e => setScanInterval(e.target.value)}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                disabled={!canAdmin()}
              />
            </div>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Max Concurrent Scans</label>
              <input
                type="number"
                value={maxConcurrent}
                onChange={e => setMaxConcurrent(e.target.value)}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                disabled={!canAdmin()}
              />
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoResolve}
              onChange={e => setAutoResolve(e.target.checked)}
              className="rounded border-border bg-surface-800 text-brand-500 focus:ring-brand-500"
              disabled={!canAdmin()}
            />
            <span className="text-sm text-foreground">Auto-resolve findings that no longer appear in scans</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScanEnabled}
              onChange={e => setAutoScanEnabled(e.target.checked)}
              className="rounded border-border bg-surface-800 text-brand-500 focus:ring-brand-500"
              disabled={!canAdmin()}
            />
            <span className="text-sm text-foreground">Enable automatic periodic scanning</span>
          </label>
        </div>

        {/* Security */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Globe className="w-4 h-4 text-brand-400" />
            Security
          </h2>
          <div>
            <label className="block text-sm text-muted-foreground mb-1">Session Timeout (minutes)</label>
            <input
              type="number"
              defaultValue={60}
              className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              disabled={!canAdmin()}
            />
          </div>
        </div>

        {canAdmin() && (
          <div className="flex items-center gap-3">
            <button
              onClick={handleSave}
              disabled={saveMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
            >
              {saveMutation.isPending ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              Save Settings
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
