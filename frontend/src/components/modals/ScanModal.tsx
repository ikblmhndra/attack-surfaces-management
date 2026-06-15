"use client";

import { useState } from "react";
import {
  X, Scan, Globe, Search, Settings, AlertTriangle,
  ChevronDown, ChevronRight, Zap, Camera, FileSearch,
  Loader2, Target
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { apiClient } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ScanModalProps {
  orgId: string;
  onClose: () => void;
}

type ScanType = "full" | "quick" | "discovery" | "vuln" | "nuclei_assets";
type Tab = "automated" | "manual";
type ScanProfile = "safe" | "default" | "deep_authorized";

const SCAN_TYPES: { value: ScanType; label: string; desc: string }[] = [
  { value: "full", label: "Full Scan", desc: "Discovery + port + crawl + vuln + enrich" },
  { value: "quick", label: "Quick Scan", desc: "Discovery + vuln scan (critical/high only)" },
  { value: "discovery", label: "Discovery Only", desc: "Subdomains + DNS + HTTP probe only" },
  { value: "vuln", label: "Vulnerability Only", desc: "Skip discovery, scan existing assets" },
  { value: "nuclei_assets", label: "Nuclei Assets", desc: "Scan discovered assets only" },
];

const SCAN_PROFILES: { value: ScanProfile; label: string; desc: string }[] = [
  { value: "deep_authorized", label: "Deep Authorized", desc: "Broad safe coverage" },
  { value: "default", label: "Default", desc: "Balanced coverage" },
  { value: "safe", label: "Safe", desc: "Critical/high only" },
];

export function ScanModal({ orgId, onClose }: ScanModalProps) {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<Tab>("automated");
  const [scanType, setScanType] = useState<ScanType>("full");
  const [scanProfile, setScanProfile] = useState<ScanProfile>("deep_authorized");
  const [crawl, setCrawl] = useState(true);
  const [fuzz, setFuzz] = useState(false);
  const [manualTargets, setManualTargets] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  const triggerScan = useMutation({
    mutationFn: () => {
      if (scanType === "nuclei_assets") {
        return apiClient.post(`/organizations/${orgId}/scans/nuclei-assets`, {
          scan_profile: scanProfile,
          include_hosts: true,
          include_endpoints: true,
          include_limited: true,
          max_hosts: 200,
          max_endpoints: 50,
          config: {
            nuclei_batch_size: 4,
            crawl_nuclei_batch_size: 1,
            crawl_nuclei_scan_timeout: 600,
            scan_timeout: 900,
            template_timeout: 8,
            retries: 0,
            concurrency: 6,
            bulk_size: 6,
            automatic_scan: true,
            use_tech_tags: true,
          },
        });
      }

      return apiClient.post(`/organizations/${orgId}/scans`, {
        scan_type: scanType,
        scan_profile: scanType === "quick" ? "safe" : scanProfile,
        config: {
          crawl,
          fuzz,
          nuclei_batch_size: scanType === "full" ? 4 : 8,
          crawl_nuclei_batch_size: scanType === "full" ? 1 : 5,
          crawl_nuclei_scan_timeout: scanType === "full" ? 600 : 300,
          scan_timeout: scanType === "full" ? 900 : 300,
          template_timeout: 8,
          retries: 0,
          concurrency: scanType === "full" ? 6 : 8,
          bulk_size: scanType === "full" ? 6 : 8,
          automatic_scan: scanType !== "quick",
          use_tech_tags: scanType !== "quick",
        },
      });
    },
    onSuccess: () => {
      toast.success("Scan queued successfully");
      qc.invalidateQueries({ queryKey: ["org-scans"] });
      onClose();
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to queue scan");
    },
  });

  const triggerManualScan = useMutation({
    mutationFn: () => apiClient.post(`/scans/manual`, {
      org_id: orgId,
      targets: manualTargets.split("\n").map(t => t.trim()).filter(Boolean),
      scan_profile: scanProfile,
    }),
    onSuccess: (res: any) => {
      toast.success(`Nuclei scan queued against ${res.data?.message || "targets"}`);
      qc.invalidateQueries({ queryKey: ["org-scans"] });
      onClose();
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to queue manual scan");
    },
  });

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          onClick={onClose}
        />

        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 8 }}
          transition={{ duration: 0.2 }}
          className="relative w-full max-w-lg bg-surface-900 border border-border rounded-2xl shadow-2xl overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between p-5 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-brand-500/10 flex items-center justify-center">
                {activeTab === "manual" ? <Target className="w-4.5 h-4.5 text-brand-400" /> : <Scan className="w-4.5 h-4.5 text-brand-400" />}
              </div>
              <div>
                <h2 className="text-sm font-semibold text-foreground">Run Scan</h2>
                <p className="text-xs text-muted-foreground">Configure scan parameters</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-surface-700 text-muted-foreground hover:text-foreground"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-border px-5">
            <button
              onClick={() => setActiveTab("automated")}
              className={cn(
                "px-3 py-2.5 text-sm font-medium border-b-2 transition-colors",
                activeTab === "automated" ? "border-brand-400 text-brand-400" : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              <Scan className="w-3.5 h-3.5 inline mr-1.5" />
              Automated
            </button>
            <button
              onClick={() => setActiveTab("manual")}
              className={cn(
                "px-3 py-2.5 text-sm font-medium border-b-2 transition-colors",
                activeTab === "manual" ? "border-brand-400 text-brand-400" : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              <Target className="w-3.5 h-3.5 inline mr-1.5" />
              Manual Nuclei
            </button>
          </div>

          {/* Body */}
          <div className="p-5 space-y-5 max-h-[60vh] overflow-y-auto">
            {activeTab === "manual" ? (
              <>
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 block">
                    Targets (one per line)
                  </label>
                  <textarea
                    value={manualTargets}
                    onChange={(e) => setManualTargets(e.target.value)}
                    placeholder={"example.com\nhttps://admin.example.com/login\n192.168.1.1:8443"}
                    rows={8}
                    className="w-full bg-surface-800 border border-surface-700 rounded-xl p-3 text-sm font-mono text-foreground placeholder:text-muted-foreground/50 resize-none focus:outline-none focus:border-brand-500/50 transition-colors"
                  />
                  <p className="text-[11px] text-muted-foreground mt-1.5">
                    Enter domains, URLs with paths, or IP:port pairs. One target per line.
                  </p>
                </div>

                <div className="bg-surface-800 rounded-xl p-3.5">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center">
                      <Zap className="w-4 h-4 text-red-400" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">Nuclei Vulnerability Scan</p>
                      <p className="text-xs text-muted-foreground">Runs nuclei directly against targets, no discovery phase</p>
                    </div>
                  </div>
                </div>

                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2.5 block">
                    Scan Profile
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    {SCAN_PROFILES.map((profile) => (
                      <button
                        key={profile.value}
                        onClick={() => setScanProfile(profile.value)}
                        className={cn(
                          "p-2.5 rounded-xl border text-left transition-all",
                          scanProfile === profile.value
                            ? "bg-red-500/10 border-red-500/30 text-red-300"
                            : "bg-surface-800 border-surface-700 text-muted-foreground hover:border-surface-600"
                        )}
                      >
                        <p className="text-xs font-medium">{profile.label}</p>
                        <p className="text-[10px] mt-0.5 opacity-70">{profile.desc}</p>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <>
                {/* Scan Type */}
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2.5 block">
                    Scan Type
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {SCAN_TYPES.map((st) => (
                      <button
                        key={st.value}
                        onClick={() => setScanType(st.value)}
                        className={cn(
                          "p-3 rounded-xl border text-left transition-all",
                          scanType === st.value
                            ? "bg-brand-500/10 border-brand-500/30 text-brand-400"
                            : "bg-surface-800 border-surface-700 text-muted-foreground hover:border-surface-600"
                        )}
                      >
                        <p className="text-sm font-medium">{st.label}</p>
                        <p className="text-[11px] mt-0.5 opacity-70">{st.desc}</p>
                      </button>
                    ))}
                  </div>
                </div>

                {(scanType === "full" || scanType === "vuln" || scanType === "nuclei_assets") && (
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2.5 block">
                      Scan Profile
                    </label>
                    <div className="grid grid-cols-3 gap-2">
                      {SCAN_PROFILES.map((profile) => (
                        <button
                          key={profile.value}
                          onClick={() => setScanProfile(profile.value)}
                          className={cn(
                            "p-2.5 rounded-xl border text-left transition-all",
                            scanProfile === profile.value
                              ? "bg-red-500/10 border-red-500/30 text-red-300"
                              : "bg-surface-800 border-surface-700 text-muted-foreground hover:border-surface-600"
                          )}
                        >
                          <p className="text-xs font-medium">{profile.label}</p>
                          <p className="text-[10px] mt-0.5 opacity-70">{profile.desc}</p>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Pipeline stages preview */}
                <div className="bg-surface-800 rounded-xl p-3.5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      Pipeline
                    </span>
                    <span className="text-[11px] text-muted-foreground">
                      {scanType === "full" ? "7 stages" :
                       scanType === "quick" ? "2 stages" :
                       scanType === "discovery" ? "1 stage" :
                       scanType === "nuclei_assets" ? "1 stage" : "1 stage"}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {(scanType === "full" || scanType === "quick" || scanType === "discovery") && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-brand-500/10 text-brand-400">Discovery</span>
                    )}
                    {scanType === "nuclei_assets" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-brand-500/10 text-brand-400">Existing Assets</span>
                    )}
                    {scanType === "full" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-purple-500/10 text-purple-400">Port Scan</span>
                    )}
                    {(scanType === "full" || scanType === "quick" || scanType === "vuln" || scanType === "nuclei_assets") && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-red-500/10 text-red-400">Vuln Scan</span>
                    )}
                    {scanType === "full" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-orange-500/10 text-orange-400">Scanner Coverage</span>
                    )}
                    {scanType === "full" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-emerald-500/10 text-emerald-400">Screenshot</span>
                    )}
                    {scanType === "full" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-yellow-500/10 text-yellow-400">Enrich</span>
                    )}
                    {crawl && scanType !== "vuln" && scanType !== "nuclei_assets" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-cyan-500/10 text-cyan-400">Crawl</span>
                    )}
                    {fuzz && scanType !== "vuln" && scanType !== "nuclei_assets" && (
                      <span className="text-[11px] px-2 py-1 rounded-md bg-orange-500/10 text-orange-400">Fuzz</span>
                    )}
                  </div>
                </div>

                {/* Toggles */}
                {scanType !== "nuclei_assets" && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 rounded-xl bg-surface-800">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                        <Globe className="w-4 h-4 text-cyan-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">Endpoint Crawling</p>
                        <p className="text-xs text-muted-foreground">Discover JS files, API paths via Katana</p>
                      </div>
                    </div>
                    <button
                      onClick={() => setCrawl(!crawl)}
                      className={cn(
                        "w-10 h-5 rounded-full transition-colors relative flex-shrink-0",
                        crawl ? "bg-brand-500" : "bg-surface-600"
                      )}
                    >
                      <div className={cn(
                        "w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-all",
                        crawl ? "left-5.5" : "left-0.5"
                      )} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-xl bg-surface-800">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-orange-500/10 flex items-center justify-center">
                        <Search className="w-4 h-4 text-orange-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">Directory Fuzzing</p>
                        <p className="text-xs text-muted-foreground">Brute-force hidden paths with FFUF</p>
                      </div>
                    </div>
                    <button
                      onClick={() => setFuzz(!fuzz)}
                      className={cn(
                        "w-10 h-5 rounded-full transition-colors relative flex-shrink-0",
                        fuzz ? "bg-brand-500" : "bg-surface-600"
                      )}
                    >
                      <div className={cn(
                        "w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-all",
                        fuzz ? "left-5.5" : "left-0.5"
                      )} />
                    </button>
                  </div>
                </div>
                )}

                {/* Advanced */}
                <div>
                  <button
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                  >
                    {showAdvanced ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Advanced Options
                  </button>
                  {showAdvanced && (
                    <div className="mt-3 p-3 rounded-xl bg-surface-800 space-y-2.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-muted-foreground">Amass (deep DNS)</span>
                        <span className="text-[11px] text-muted-foreground bg-surface-700 px-2 py-0.5 rounded">Slow</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-muted-foreground">Nuclei Rate Limit</span>
                        <span className="text-xs font-mono text-muted-foreground">150/s</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-muted-foreground">Fuzz Wordlist</span>
                        <span className="text-xs font-mono text-muted-foreground">built-in (50 entries)</span>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center gap-3 px-5 py-4 border-t border-border bg-surface-900">
            <button
              onClick={onClose}
              className="flex-1 px-3 py-2 rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground text-sm font-medium transition-colors"
            >
              Cancel
            </button>

            {activeTab === "manual" ? (
              <button
                onClick={() => triggerManualScan.mutate()}
                disabled={triggerManualScan.isPending || !manualTargets.trim()}
                className="flex-1 px-3 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {triggerManualScan.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Zap className="w-4 h-4" />
                )}
                {triggerManualScan.isPending ? "Queuing..." : "Run Nuclei"}
              </button>
            ) : (
              <button
                onClick={() => triggerScan.mutate()}
                disabled={triggerScan.isPending}
                className="flex-1 px-3 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {triggerScan.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Scan className="w-4 h-4" />
                )}
                {triggerScan.isPending ? "Queuing..." : "Start Scan"}
              </button>
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
