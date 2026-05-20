"use client";

import { useState } from "react";
import {
  Key, Plus, Trash2, Copy, CheckCircle, RefreshCw,
  AlertTriangle, Eye, EyeOff
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { keysAPI } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

const SCOPE_OPTIONS = [
  { value: "assets:read", label: "Assets (Read)" },
  { value: "assets:write", label: "Assets (Write)" },
  { value: "findings:read", label: "Findings (Read)" },
  { value: "findings:write", label: "Findings (Write)" },
  { value: "scans:read", label: "Scans (Read)" },
  { value: "scans:write", label: "Scans (Write)" },
  { value: "organizations:read", label: "Organizations (Read)" },
  { value: "organizations:write", label: "Organizations (Write)" },
  { value: "admin", label: "Admin (Full Access)" },
];

export default function ApiKeysPage() {
  const { canAdmin } = useWorkspaceStore();
  const qc = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["assets:read", "findings:read"]);
  const [expiresAt, setExpiresAt] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const { data: keys, isLoading } = useQuery({
    queryKey: ["api-keys"],
    queryFn: () => keysAPI.list().then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      keysAPI.create({
        name: keyName,
        scopes: selectedScopes,
        expires_at: expiresAt || undefined,
      }),
    onSuccess: (res) => {
      setCreatedKey(res.data.key || res.data.api_key);
      toast.success("API key created");
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: () => toast.error("Failed to create API key"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => keysAPI.delete(id),
    onSuccess: () => {
      toast.success("API key revoked");
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: () => toast.error("Failed to revoke API key"),
  });

  const handleCopy = async () => {
    if (createdKey) {
      await navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    }
  };

  const handleCreate = () => {
    if (!keyName.trim()) return;
    createMutation.mutate();
  };

  const toggleScope = (scope: string) => {
    if (scope === "admin") {
      setSelectedScopes(["admin"]);
      return;
    }
    setSelectedScopes(prev =>
      prev.includes(scope)
        ? prev.filter(s => s !== scope).filter(s => s !== "admin")
        : [...prev.filter(s => s !== "admin"), scope]
    );
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">API Keys</h1>
          <p className="text-sm text-muted-foreground">
            Manage API keys for programmatic access
          </p>
        </div>
        {canAdmin() && (
          <button
            onClick={() => { setShowCreate(true); setCreatedKey(null); }}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            Create Key
          </button>
        )}
      </div>

      {/* Create key form */}
      {showCreate && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-5 space-y-4"
        >
          {createdKey ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm font-medium">API Key Created</span>
              </div>
              <div className="bg-surface-900 rounded-lg p-4 border border-border">
                <p className="text-xs text-muted-foreground mb-2">
                  Copy this key now. You won&apos;t be able to see it again.
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm font-mono text-brand-300 bg-surface-800 rounded px-3 py-2 break-all">
                    {createdKey}
                  </code>
                  <button
                    onClick={handleCopy}
                    className="p-2 rounded hover:bg-surface-700 text-muted-foreground hover:text-foreground"
                  >
                    {copied ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <button
                onClick={() => { setShowCreate(false); setCreatedKey(null); setKeyName(""); setSelectedScopes(["assets:read", "findings:read"]); setExpiresAt(""); }}
                className="text-sm text-muted-foreground hover:text-foreground"
              >
                Close
              </button>
            </div>
          ) : (
            <>
              <h3 className="text-sm font-semibold text-foreground">New API Key</h3>
              <div>
                <label className="block text-sm text-muted-foreground mb-1">Name</label>
                <input
                  value={keyName}
                  onChange={e => setKeyName(e.target.value)}
                  placeholder="e.g., CI/CD Pipeline"
                  className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
              <div>
                <label className="block text-sm text-muted-foreground mb-2">Scopes</label>
                <div className="flex flex-wrap gap-2">
                  {SCOPE_OPTIONS.map(scope => (
                    <button
                      key={scope.value}
                      onClick={() => toggleScope(scope.value)}
                      className={cn(
                        "px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors",
                        selectedScopes.includes(scope.value)
                          ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                          : "bg-surface-800 border-surface-600 text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {scope.label}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm text-muted-foreground mb-1">Expires (optional)</label>
                <input
                  type="date"
                  value={expiresAt}
                  onChange={e => setExpiresAt(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleCreate}
                  disabled={createMutation.isPending || !keyName.trim()}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Key className="w-4 h-4" />
                  )}
                  Generate Key
                </button>
                <button
                  onClick={() => setShowCreate(false)}
                  className="text-sm text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
              </div>
            </>
          )}
        </motion.div>
      )}

      {/* Keys list */}
      <div className="glass-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <RefreshCw className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : keys?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th>Scopes</th>
                  <th>Usage</th>
                  <th>Expires</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key: any) => (
                  <tr key={key.id}>
                    <td>
                      <span className="text-sm font-medium text-foreground">{key.name}</span>
                    </td>
                    <td>
                      <code className="text-xs font-mono text-muted-foreground bg-surface-800 px-2 py-1 rounded">
                        {key.key_prefix}...
                      </code>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {(key.scopes || []).slice(0, 3).map((s: string) => (
                          <span key={s} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded">{s}</span>
                        ))}
                        {(key.scopes || []).length > 3 && (
                          <span className="text-xs text-muted-foreground">+{key.scopes.length - 3}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="text-sm text-muted-foreground tabular-nums">{key.usage_count?.toLocaleString() || 0}</span>
                    </td>
                    <td>
                      <span className={cn(
                        "text-xs",
                        key.expires_at && new Date(key.expires_at) < new Date() ? "text-red-400" : "text-muted-foreground"
                      )}>
                        {key.expires_at ? format(new Date(key.expires_at), "MMM d, yyyy") : "Never"}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-muted-foreground">
                        {format(new Date(key.created_at), "MMM d, yyyy")}
                      </span>
                    </td>
                    <td>
                      {canAdmin() && (
                        <button
                          onClick={() => { if (confirm("Revoke this API key?")) deleteMutation.mutate(key.id); }}
                          className="p-1 rounded hover:bg-red-500/10 text-muted-foreground hover:text-red-400"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-40 text-muted-foreground">
            <Key className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-sm">No API keys yet</p>
            <p className="text-xs mt-1">Create a key for programmatic access</p>
          </div>
        )}
      </div>
    </div>
  );
}
