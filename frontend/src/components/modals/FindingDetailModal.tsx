"use client";

import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  X, ExternalLink, Copy, CheckCircle, XCircle, AlertTriangle,
  ChevronDown, ChevronRight, Clock, Shield, Code, Globe, Link2
} from "lucide-react";
import { motion } from "framer-motion";
import { formatDistanceToNow, format } from "date-fns";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { findingsAPI } from "@/lib/api";
import { SeverityBadge, StatusBadge, CVEBadge, KEVBadge, EPSSBadge, ConfidenceIndicator } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/utils";

interface FindingDetailModalProps {
  finding: any;
  onClose: () => void;
}

export function FindingDetailModal({ finding, onClose }: FindingDetailModalProps) {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<"overview" | "evidence" | "remediation" | "history">("overview");
  const [requestExpanded, setRequestExpanded] = useState(false);
  const [responseExpanded, setResponseExpanded] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const markFP = useMutation({
    mutationFn: () => findingsAPI.markFalsePositive(finding.id, "Manually marked via UI"),
    onSuccess: () => {
      toast.success("Marked as false positive");
      qc.invalidateQueries({ queryKey: ["findings"] });
      onClose();
    },
  });

  const acceptRisk = useMutation({
    mutationFn: () => findingsAPI.acceptRisk(finding.id, "Risk accepted via UI"),
    onSuccess: () => {
      toast.success("Risk accepted for 90 days");
      qc.invalidateQueries({ queryKey: ["findings"] });
      onClose();
    },
  });

  const copyToClipboard = async (text: string, key: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const TABS = [
    { id: "overview", label: "Overview" },
    { id: "evidence", label: "Evidence" },
    { id: "remediation", label: "Remediation" },
  ];

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        {/* Backdrop */}
        <Dialog.Overlay asChild>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
          />
        </Dialog.Overlay>

        {/* Modal */}
        <Dialog.Content asChild>
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-3xl max-h-[90vh] -translate-x-1/2 -translate-y-1/2 flex flex-col bg-surface-900 border border-border rounded-2xl shadow-2xl overflow-hidden focus:outline-none"
          >
          {/* Header */}
          <div className="flex items-start justify-between p-5 border-b border-border flex-shrink-0">
            <div className="flex-1 min-w-0 pr-4">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.status} />
                {finding.is_kev && <KEVBadge knownRansomware={finding.kev_known_ransomware} />}
                {typeof finding.epss_score === "number" && finding.epss_score > 0 && (
                  <EPSSBadge score={finding.epss_score} />
                )}
                <ConfidenceIndicator confidence={finding.confidence} />
                {finding.cve_ids?.map((cve: string) => (
                  <CVEBadge key={cve} cveId={cve} />
                ))}
              </div>
              <Dialog.Title asChild>
                <h2 className="text-base font-semibold text-foreground leading-tight">
                  {finding.title}
                </h2>
              </Dialog.Title>
              <Dialog.Description asChild>
                <span className="sr-only">Finding details</span>
              </Dialog.Description>
              {finding.affected_url && (
                <div className="flex items-center gap-1.5 mt-1.5">
                  <Globe className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                  <span className="text-xs font-mono text-brand-400 truncate">
                    {finding.affected_url}
                  </span>
                  <a
                    href={finding.affected_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-muted-foreground hover:text-foreground"
                  >
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              )}
            </div>
            <Dialog.Close asChild>
              <button
                aria-label="Close"
                className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-surface-700 text-muted-foreground hover:text-foreground flex-shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </Dialog.Close>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-border px-5 flex-shrink-0">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  "px-3 py-2.5 text-sm font-medium border-b-2 transition-colors",
                  activeTab === tab.id
                    ? "border-brand-400 text-brand-400"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-5">
            {activeTab === "overview" && (
              <div className="space-y-5">
                {/* Meta grid */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {[
                    { label: "Template", value: finding.template_id, mono: true },
                    { label: "Category", value: finding.category?.replace(/_/g, " "), capitalize: true },
                    { label: "CVSS Score", value: finding.cvss_score?.toFixed(1) || "—" },
                    ...(typeof finding.epss_percentile === "number"
                      ? [{ label: "EPSS Percentile", value: `${Math.round(finding.epss_percentile * 100)}th` }]
                      : []),
                    ...(finding.confidence && finding.confidence !== "unknown"
                      ? [{ label: "Match Confidence", value: finding.confidence, capitalize: true }]
                      : []),
                    { label: "First Seen", value: finding.first_seen ? formatDistanceToNow(new Date(finding.first_seen), { addSuffix: true }) : "—" },
                    { label: "Last Seen", value: finding.last_seen ? formatDistanceToNow(new Date(finding.last_seen), { addSuffix: true }) : "—" },
                    { label: "Scanner", value: finding.scanner || finding.source || "—" },
                  ].map(meta => (
                    <div key={meta.label} className="bg-surface-800 rounded-lg p-3">
                      <p className="text-xs text-muted-foreground mb-1">{meta.label}</p>
                      <p className={cn(
                        "text-sm text-foreground truncate font-medium",
                        meta.mono && "font-mono text-xs",
                        meta.capitalize && "capitalize",
                      )}>
                        {meta.value || "—"}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Description */}
                {finding.description && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      Description
                    </h3>
                    <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">
                      {finding.description}
                    </p>
                  </div>
                )}

                {/* CVE details */}
                {finding.cve_ids?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      CVE References
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {finding.cve_ids.map((cve: string) => (
                        <CVEBadge key={cve} cveId={cve} />
                      ))}
                    </div>
                    {finding.cvss_vector && (
                      <p className="text-xs font-mono text-muted-foreground mt-2 bg-surface-800 rounded p-2 break-all">
                        {finding.cvss_vector}
                      </p>
                    )}
                  </div>
                )}

                {/* References */}
                {finding.references?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      References
                    </h3>
                    <ul className="space-y-1">
                      {finding.references.slice(0, 8).map((ref: string, i: number) => (
                        <li key={i}>
                          <a
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300 truncate"
                          >
                            <Link2 className="w-3 h-3 flex-shrink-0" />
                            {ref}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {activeTab === "evidence" && (
              <div className="space-y-4">
                {/* Evidence summary */}
                {finding.evidence && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      Evidence
                    </h3>
                    <pre className="terminal text-xs whitespace-pre-wrap break-all">
                      {finding.evidence}
                    </pre>
                  </div>
                )}

                {/* Proof/extraction */}
                {finding.proof?.extracted_results?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      Extracted Results
                    </h3>
                    <div className="space-y-1">
                      {finding.proof.extracted_results.map((r: string, i: number) => (
                        <div key={i} className="bg-surface-800 rounded px-3 py-1.5 text-xs font-mono text-brand-300">
                          {r}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* HTTP Request */}
                {finding.request_raw && (
                  <div>
                    <button
                      onClick={() => setRequestExpanded(!requestExpanded)}
                      className="flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 w-full"
                    >
                      {requestExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                      HTTP Request
                      <button
                        onClick={(e) => { e.stopPropagation(); copyToClipboard(finding.request_raw, "request"); }}
                        className="ml-auto text-muted-foreground hover:text-foreground"
                      >
                        {copied === "request" ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </button>
                    {requestExpanded && (
                      <pre className="terminal text-xs whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                        {finding.request_raw}
                      </pre>
                    )}
                  </div>
                )}

                {/* HTTP Response */}
                {finding.response_raw && (
                  <div>
                    <button
                      onClick={() => setResponseExpanded(!responseExpanded)}
                      className="flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 w-full"
                    >
                      {responseExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                      HTTP Response
                      <button
                        onClick={(e) => { e.stopPropagation(); copyToClipboard(finding.response_raw, "response"); }}
                        className="ml-auto text-muted-foreground hover:text-foreground"
                      >
                        {copied === "response" ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </button>
                    {responseExpanded && (
                      <pre className="terminal text-xs whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                        {finding.response_raw}
                      </pre>
                    )}
                  </div>
                )}

                {/* Curl command */}
                {finding.proof?.curl_command && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                        Curl Command
                      </h3>
                      <button onClick={() => copyToClipboard(finding.proof.curl_command, "curl")} className="text-muted-foreground hover:text-foreground">
                        {copied === "curl" ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                    <pre className="terminal text-xs whitespace-pre-wrap break-all">
                      {finding.proof.curl_command}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {activeTab === "remediation" && (
              <div className="space-y-5">
                {finding.remediation ? (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
                      Recommended Remediation
                    </h3>
                    <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4">
                      <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">
                        {finding.remediation}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
                    No remediation guidance available for this finding.
                  </div>
                )}

                {finding.template_url && (
                  <a
                    href={finding.template_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-brand-400 hover:text-brand-300"
                  >
                    <ExternalLink className="w-4 h-4" />
                    View nuclei template source
                  </a>
                )}
              </div>
            )}
          </div>

          {/* Footer actions */}
          {finding.status === "open" && (
            <div className="flex items-center gap-2 px-5 py-4 border-t border-border flex-shrink-0 bg-surface-900">
              <button
                onClick={() => acceptRisk.mutate()}
                disabled={acceptRisk.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/20 text-yellow-400 text-sm font-medium transition-colors disabled:opacity-50"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Accept Risk
              </button>
              <button
                onClick={() => markFP.mutate()}
                disabled={markFP.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-500/10 hover:bg-gray-500/20 border border-gray-500/20 text-gray-400 text-sm font-medium transition-colors disabled:opacity-50"
              >
                <XCircle className="w-3.5 h-3.5" />
                False Positive
              </button>
              <div className="ml-auto text-xs text-muted-foreground flex items-center gap-1.5">
                <Clock className="w-3 h-3" />
                {finding.first_seen && `First seen ${formatDistanceToNow(new Date(finding.first_seen), { addSuffix: true })}`}
              </div>
            </div>
          )}
          </motion.div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
