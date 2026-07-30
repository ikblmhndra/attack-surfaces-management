"use client";

import { useState, useEffect, useRef } from "react";
import {
  Settings, Save, Building2, Globe, AlertTriangle,
  CheckCircle, RefreshCw, Users, UserPlus, Copy, Check
} from "lucide-react";
import { motion } from "framer-motion";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { apiClient, workspacesAPI } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

const INVITABLE_ROLES = [
  { value: "admin", label: "Admin" },
  { value: "analyst", label: "Analyst" },
  { value: "viewer", label: "Viewer" },
] as const;

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

  // ── Team members / invite ──────────────────────────────────
  const { data: members } = useQuery({
    queryKey: ["workspace-members"],
    queryFn: () => workspacesAPI.getMembers().then(r => r.data.items as Array<{ id: string; email: string; full_name: string; role: string }>),
    enabled: !!workspaceId,
  });

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "analyst" | "viewer">("analyst");
  const [inviteResult, setInviteResult] = useState<{ path: string; role: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const inviteMutation = useMutation({
    mutationFn: () => workspacesAPI.invite(inviteEmail, inviteRole),
    onSuccess: (res) => {
      setInviteResult({ path: res.data.invite_path, role: res.data.role });
      setInviteEmail("");
      toast.success("Invite link generated");
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || "Failed to create invite"),
  });

  const copyInviteLink = () => {
    if (!inviteResult) return;
    const fullUrl = `${window.location.origin}${inviteResult.path}`;
    navigator.clipboard.writeText(fullUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

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

        {/* Team Members */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Users className="w-4 h-4 text-brand-400" />
            Team Members
          </h2>

          <div className="space-y-2">
            {members?.map((m) => (
              <div key={m.id} className="flex items-center justify-between bg-surface-800 rounded-lg p-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{m.full_name}</p>
                  <p className="text-xs text-muted-foreground truncate">{m.email}</p>
                </div>
                <span className="text-xs font-medium text-muted-foreground capitalize px-2 py-0.5 rounded-full bg-surface-700 flex-shrink-0">
                  {m.role}
                </span>
              </div>
            ))}
          </div>

          {canAdmin() && (
            <div className="pt-2 border-t border-border space-y-3">
              <p className="text-xs text-muted-foreground">
                Generate an invite link to add a teammate. No email is sent — copy the link and share it
                yourself.
              </p>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="teammate@company.com"
                  className="flex-1 px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as typeof inviteRole)}
                  className="px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  {INVITABLE_ROLES.map((r) => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </select>
                <button
                  onClick={() => inviteMutation.mutate()}
                  disabled={!inviteEmail || inviteMutation.isPending}
                  className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                >
                  {inviteMutation.isPending ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <UserPlus className="w-4 h-4" />
                  )}
                  Invite
                </button>
              </div>

              {inviteResult && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-brand-500/10 border border-brand-500/20">
                  <input
                    readOnly
                    value={`${typeof window !== "undefined" ? window.location.origin : ""}${inviteResult.path}`}
                    className="flex-1 min-w-0 bg-transparent text-xs font-mono text-foreground focus:outline-none truncate"
                    onFocus={(e) => e.target.select()}
                  />
                  <button
                    onClick={copyInviteLink}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface-700 hover:bg-surface-600 text-xs font-medium text-foreground transition-colors flex-shrink-0"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? "Copied" : "Copy"}
                  </button>
                </div>
              )}
            </div>
          )}
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
