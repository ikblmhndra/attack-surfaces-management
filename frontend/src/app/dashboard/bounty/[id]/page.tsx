"use client";

import { useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft, ShieldCheck, PauseCircle, Play, Trash2, Plus, X, Loader2,
  Target, Radar, Bug, FileText, ScrollText, ArrowUpCircle, ExternalLink,
  CheckCircle2, XCircle, Clock, MinusCircle, AlertTriangle, Zap,
  ChevronDown, Search, Hash, Flag, KeyRound, Upload, CreditCard, Webhook,
  Braces, LayoutGrid, Rows3, BarChart3, ShieldAlert, SlidersHorizontal,
  SearchX, Inbox, Folder, Shield,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { bountyAPI } from "@/lib/api";
import { cn } from "@/lib/utils";

// A stage is treated as possibly-stuck if it's been "running" this long — the
// worker crashed/was killed without marking it failed. Purely a UI hint.
const STUCK_AFTER_MS = 10 * 60 * 1000;

function elapsedLabel(fromIso?: string, toIso?: string): string {
  if (!fromIso) return "";
  const from = new Date(fromIso).getTime();
  const to = toIso ? new Date(toIso).getTime() : Date.now();
  const s = Math.max(0, Math.round((to - from) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

function summaryLabel(summary: any): string {
  if (!summary || typeof summary !== "object") return "";
  const parts: string[] = [];
  if (summary.assets_found != null) parts.push(`${summary.assets_found} assets`);
  if (summary.alive != null) parts.push(`${summary.alive}/${summary.probed} alive`);
  if (summary.findings != null) parts.push(`${summary.findings} findings`);
  if (summary.reports_created != null) parts.push(`${summary.reports_created} reports`);
  return parts.join(", ");
}

// Renders the live status pill for one pipeline stage.
function StagePill({ entry }: { entry: any }) {
  if (!entry?.status) return null;
  const status = entry.status;
  const stuck = status === "running" && entry.started_at &&
    Date.now() - new Date(entry.started_at).getTime() > STUCK_AFTER_MS;

  let cls = "text-muted-foreground bg-surface-700/40 border-border";
  let Icon = MinusCircle;
  let label = status;

  if (status === "queued") { cls = "text-amber-400 bg-amber-500/10 border-amber-500/30"; Icon = Clock; label = "Queued"; }
  else if (status === "running" && !stuck) { cls = "text-brand-400 bg-brand-500/10 border-brand-500/30"; Icon = Loader2; label = `Running ${elapsedLabel(entry.started_at)}`; }
  else if (status === "running" && stuck) { cls = "text-amber-400 bg-amber-500/10 border-amber-500/40"; Icon = AlertTriangle; label = `Stuck? ${elapsedLabel(entry.started_at)}`; }
  else if (status === "completed") { cls = "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"; Icon = CheckCircle2; label = summaryLabel(entry.summary) || "Done"; }
  else if (status === "skipped") { cls = "text-muted-foreground bg-surface-700/40 border-border"; Icon = MinusCircle; label = `Skipped${entry.reason ? " · " + entry.reason : ""}`; }
  else if (status === "failed") { cls = "text-critical bg-critical/10 border-critical/30"; Icon = XCircle; label = "Failed"; }

  return (
    <span
      title={status === "failed" ? entry.error : (entry.finished_at ? `Finished in ${elapsedLabel(entry.started_at, entry.finished_at)}` : undefined)}
      className={cn("mt-1 inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border font-medium max-w-full tabular-nums", cls)}
    >
      <Icon className={cn("w-3 h-3 flex-shrink-0", status === "running" && !stuck && "animate-spin")} />
      <span className="truncate">{label}</span>
    </span>
  );
}

type Stage = "recon" | "probe" | "vulnscan" | "exploit" | "report";
const STAGES: { id: Stage; label: string; icon: typeof Radar; hint: string }[] = [
  { id: "recon", label: "Recon", icon: Radar, hint: "Subdomain / URL / JS / path discovery → suggestions" },
  { id: "probe", label: "Probe", icon: Target, hint: "httpx liveness against approved targets" },
  { id: "vulnscan", label: "Vuln Scan", icon: Bug, hint: "nuclei against approved targets" },
  { id: "exploit", label: "Exploit", icon: Bug, hint: "XSS/SQLi/SSRF/LFI/IDOR/CSRF (scope-gated)" },
  { id: "report", label: "Report", icon: FileText, hint: "Draft submissions from confirmed findings" },
];

const TABS = ["summary", "scope", "targets", "recon", "findings", "reports"] as const;
type Tab = (typeof TABS)[number];
const TAB_ICON: Record<Tab, typeof Radar> = {
  summary: BarChart3, scope: Shield, targets: Target, recon: Radar, findings: Bug, reports: FileText,
};

const SEV_CLS: Record<string, string> = {
  critical: "text-critical", high: "text-high", medium: "text-medium", low: "text-low", info: "text-info",
};
const SEV_BAR_CLS: Record<string, string> = {
  critical: "bg-critical", high: "bg-high", medium: "bg-medium", low: "bg-low", info: "bg-info",
};
const STATUS_CLS: Record<string, string> = {
  confirmed: "text-critical bg-critical/10 border-critical/30",
  inconclusive: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  not_vulnerable: "text-muted-foreground bg-surface-700/40 border-border",
  blocked: "text-muted-foreground bg-surface-700/40 border-border",
};

// Priority-bucket names are snake_case, prefix-matched to a representative
// icon so the Summary tab's bucket list reads at a glance instead of every
// row looking identical.
const BUCKET_ICON_RULES: [string, typeof Hash][] = [
  ["idor", Hash], ["bac", Flag], ["auth", KeyRound], ["upload", Upload],
  ["payment", CreditCard], ["webhook", Webhook], ["debug", Bug], ["graphql", Braces],
];
function bucketIcon(name: string) {
  const hit = BUCKET_ICON_RULES.find(([prefix]) => name.startsWith(prefix));
  return hit ? hit[1] : Target;
}

// Card lift-on-hover, reused across stat cards / finding cards / bucket rows
// / pipeline stage tiles so the whole page shares one "this is touchable"
// language instead of some rows being interactive-looking and others not.
const LIFT = "transition-all duration-150 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/5";

function EmptyState({ icon: Icon, label }: { icon: typeof Inbox; label: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-muted-foreground">
      <Icon className="w-7 h-7 opacity-40" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative flex-1 min-w-[200px]">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full pl-8 pr-3 py-2 text-sm bg-surface-800 border border-border rounded-lg text-foreground
                   placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-rose-500/40 focus:border-rose-500/50
                   transition-colors"
      />
    </div>
  );
}

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "text-xs font-semibold px-2.5 py-1.5 rounded-full border transition-colors whitespace-nowrap",
        active ? "bg-rose-500/10 text-rose-300 border-rose-500/30" : "bg-surface-800 text-muted-foreground border-border hover:text-foreground hover:border-rose-500/20",
      )}
    >
      {children}
    </button>
  );
}

function ViewToggle({ view, onChange }: { view: "grouped" | "table"; onChange: (v: "grouped" | "table") => void }) {
  return (
    <div className="inline-flex border border-border rounded-lg overflow-hidden flex-shrink-0">
      {([["grouped", LayoutGrid], ["table", Rows3]] as const).map(([v, Icon]) => (
        <button
          key={v}
          onClick={() => onChange(v)}
          className={cn(
            "flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1.5 capitalize transition-colors",
            view === v ? "bg-rose-600 text-white" : "bg-surface-800 text-muted-foreground hover:text-foreground",
          )}
        >
          <Icon className="w-3 h-3" /> {v}
        </button>
      ))}
    </div>
  );
}

// Groups a flat target/asset list by domain: any non-domain-type entry whose
// hostname exactly matches a domain-type entry's value nests under it.
// Entries with no matching domain in the list render as their own flat rows
// (a promoted URL target with no promoted parent domain is common and valid
// -- grouping is a display aid, never implies the ungrouped item is somehow
// less legitimate).
function hostOf(value: string): string {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).hostname;
  } catch {
    return value;
  }
}
function groupByDomain<T extends { value: string }>(items: T[], isDomainType: (item: T) => boolean) {
  const domainItems = items.filter(isDomainType);
  const childrenByDomain = new Map<string, T[]>();
  domainItems.forEach((d) => childrenByDomain.set(d.value, []));
  const ungrouped: T[] = [];
  for (const item of items) {
    if (isDomainType(item)) continue;
    const host = hostOf(item.value);
    if (childrenByDomain.has(host)) childrenByDomain.get(host)!.push(item);
    else ungrouped.push(item);
  }
  return { domainItems, childrenByDomain, ungrouped };
}

export default function BountyProgramDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("summary");

  const { data: program, isLoading } = useQuery({
    queryKey: ["bounty-program", id],
    queryFn: () => bountyAPI.getProgram(id).then((r) => r.data),
    // Poll while any stage is queued/running so status pills update live.
    refetchInterval: (query) => {
      const ss = (query.state.data as any)?.stage_status || {};
      const busy = Object.values(ss).some((s: any) => s?.status === "queued" || s?.status === "running");
      return busy ? 3000 : false;
    },
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["bounty-program", id] });

  const statusMutation = useMutation({
    mutationFn: (status: string) => bountyAPI.updateProgram(id, { status }),
    onSuccess: () => { invalidate(); toast.success("Status updated"); },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed"),
  });

  const runMutation = useMutation({
    mutationFn: (stage: Stage) => bountyAPI.runStage(id, stage),
    onSuccess: (_d, stage) => { invalidate(); toast.success(`${stage} queued — watch its status below`); },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to queue stage"),
  });

  const runPipelineMutation = useMutation({
    mutationFn: () => bountyAPI.runPipeline(id),
    onSuccess: () => { invalidate(); toast.success("Full pipeline started — stages run automatically, watch the status below"); },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start pipeline"),
  });

  const deleteMutation = useMutation({
    mutationFn: () => bountyAPI.deleteProgram(id),
    onSuccess: () => { toast.success("Program deleted"); router.push("/dashboard/bounty"); },
  });

  if (isLoading || !program) {
    return <div className="flex justify-center py-20"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>;
  }

  const isActive = program.status === "active";

  return (
    <div className="max-w-6xl mx-auto space-y-5">
      <button onClick={() => router.push("/dashboard/bounty")} className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="w-4 h-4" /> Programs
      </button>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-foreground tracking-tight">{program.name}</h1>
          <p className="text-sm text-muted-foreground mt-0.5 capitalize flex items-center gap-1.5">
            {isActive && <span className="relative flex w-1.5 h-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-emerald-500" />
            </span>}
            {program.platform} · {program.status}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => runPipelineMutation.mutate()}
            disabled={!isActive || runPipelineMutation.isPending}
            title={isActive ? "Run recon → probe → vulnscan → exploit → report automatically" : "Activate the program first"}
            className={cn(
              "flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all",
              isActive
                ? "bg-rose-600 hover:bg-rose-500 text-white shadow-sm shadow-rose-500/20 hover:shadow-md hover:shadow-rose-500/30 hover:-translate-y-px"
                : "bg-surface-800 border border-border text-muted-foreground cursor-not-allowed opacity-60",
            )}
          >
            {runPipelineMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            Run Full Pipeline
          </button>
          {isActive ? (
            <button
              onClick={() => statusMutation.mutate("paused")}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20 text-sm font-medium transition-colors"
            >
              <PauseCircle className="w-4 h-4" /> Pause
            </button>
          ) : (
            <button
              onClick={() => statusMutation.mutate("active")}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors"
            >
              <ShieldCheck className="w-4 h-4" /> Activate
            </button>
          )}
          <button
            onClick={() => { if (confirm("Delete this program and all its data?")) deleteMutation.mutate(); }}
            className="p-2 rounded-lg border border-border text-muted-foreground hover:text-critical hover:border-critical/40 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stage runner */}
      <div className="p-4 rounded-xl bg-surface-900 border border-border">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-foreground uppercase tracking-wide">Pipeline Stages</span>
          {!isActive && <span className="text-[11px] text-amber-400">Activate the program to run stages</span>}
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {STAGES.map((s) => {
            const entry = (program.stage_status || {})[s.id];
            return (
              <button
                key={s.id}
                disabled={!isActive || runMutation.isPending}
                onClick={() => runMutation.mutate(s.id)}
                title={s.hint}
                className={cn(
                  "flex flex-col items-center gap-1 p-3 rounded-lg border text-center min-w-0",
                  isActive
                    ? cn("border-rose-500/30 bg-rose-500/5 hover:bg-rose-500/15 text-foreground", LIFT)
                    : "border-border bg-surface-800/50 text-muted-foreground cursor-not-allowed opacity-60 transition-colors",
                )}
              >
                <s.icon className={cn("w-4 h-4", isActive ? "text-rose-400" : "text-muted-foreground")} />
                <span className="text-xs font-medium flex items-center gap-1"><Play className="w-3 h-3" />{s.label}</span>
                <StagePill entry={entry} />
              </button>
            );
          })}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map((t) => {
          const Icon = TAB_ICON[t];
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 text-sm font-medium capitalize border-b-2 -mb-px transition-colors",
                tab === t ? "border-rose-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="w-3.5 h-3.5" /> {t}
            </button>
          );
        })}
      </div>

      <motion.div key={tab} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}>
        {tab === "summary" && <SummaryTab programId={id} programName={program.name} />}
        {tab === "scope" && <ScopeTab program={program} onChange={invalidate} />}
        {tab === "targets" && <TargetsTab programId={id} onChange={invalidate} />}
        {tab === "recon" && <ReconTab programId={id} onChange={invalidate} />}
        {tab === "findings" && <FindingsTab programId={id} />}
        {tab === "reports" && <ReportsTab programId={id} />}
      </motion.div>
    </div>
  );
}

// ── Summary tab (classifier + HTML report) ────────────────────

const SEV_HEX: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280",
};

function SummaryTab({ programId, programName }: { programId: string; programName: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["bounty-summary", programId],
    queryFn: () => bountyAPI.getSummary(programId).then((r) => r.data),
  });
  const [downloading, setDownloading] = useState(false);

  const downloadReport = async () => {
    setDownloading(true);
    try {
      const res = await bountyAPI.getReportHtml(programId);
      const blob = new Blob([res.data], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch {
      toast.error("Failed to load report");
    } finally {
      setDownloading(false);
    }
  };

  if (isLoading || !data) {
    return <div className="flex justify-center py-16"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>;
  }

  const t = data.totals || {};
  const sev = data.severity_counts || {};
  const maxSev = Math.max(1, ...Object.values(sev).map((n) => Number(n)));
  const buckets = data.priority_buckets || {};

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          Smart-classifier view over all findings + recon URLs. Candidate (inconclusive) findings need manual confirmation.
        </p>
        <button onClick={downloadReport} disabled={downloading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-sm font-medium flex-shrink-0 transition-colors">
          {downloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ExternalLink className="w-4 h-4" />} Open HTML Report
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          ["Findings", t.findings, Bug], ["Confirmed", t.confirmed, ShieldCheck],
          ["Candidates", t.inconclusive, Folder], ["URLs analyzed", t.urls_analyzed, BarChart3],
        ].map(([k, v, Icon]: any) => (
          <div key={k as string} className={cn("p-4 rounded-xl bg-surface-900 border border-border flex items-start justify-between gap-2", LIFT)}>
            <div>
              <div className="text-2xl font-bold text-foreground tabular-nums">{Number(v) || 0}</div>
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{k}</div>
            </div>
            <Icon className="w-4 h-4 text-muted-foreground/50 flex-shrink-0 mt-0.5" />
          </div>
        ))}
      </div>

      <div>
        <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-1.5"><BarChart3 className="w-3.5 h-3.5 text-muted-foreground" /> Severity distribution</h3>
        <div className="space-y-1.5">
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <div key={s} className="flex items-center gap-3">
              <span className="w-16 text-xs capitalize text-muted-foreground">{s}</span>
              <span className="flex-1 h-2.5 rounded bg-surface-700/40 overflow-hidden">
                <span className={cn("block h-full rounded transition-[width] duration-500", SEV_BAR_CLS[s])} style={{ width: `${(Number(sev[s]) / maxSev) * 100}%` }} />
              </span>
              <span className="w-8 text-right text-xs tabular-nums text-foreground font-medium">{Number(sev[s]) || 0}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-1.5"><Flag className="w-3.5 h-3.5 text-muted-foreground" /> Priority targets to review</h3>
        {Object.keys(buckets).length === 0 ? (
          <EmptyState icon={Inbox} label="No priority-bucket matches yet — run recon + exploit." />
        ) : (
          <div className="space-y-1.5">
            {Object.entries(buckets).map(([name, d]: [string, any]) => {
              const Icon = bucketIcon(name);
              return (
                <div key={name} className={cn("flex items-center gap-3 p-2.5 rounded-lg bg-surface-900 border border-border hover:border-rose-500/25", LIFT)}>
                  <span className="w-6 h-6 rounded-md bg-rose-500/10 text-rose-400 flex items-center justify-center flex-shrink-0"><Icon className="w-3.5 h-3.5" /></span>
                  <span className="text-sm text-foreground capitalize w-40 flex-shrink-0">{name.replace(/_/g, " ")}</span>
                  <span className="text-xs text-rose-400 font-semibold w-8 tabular-nums">{d.count}</span>
                  <span className="text-[11px] text-muted-foreground font-mono truncate flex-1">{(d.sample || [])[0]}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Scope tab ─────────────────────────────────────────────────

function ScopeTab({ program, onChange }: { program: any; onChange: () => void }) {
  const [pattern, setPattern] = useState("");
  const [ptype, setPtype] = useState("domain");
  const [inScope, setInScope] = useState(true);

  const rules: any[] = program.scope_rules || [];

  const save = useMutation({
    mutationFn: (newRules: any[]) => bountyAPI.updateProgram(program.id, { scope_rules: newRules }),
    onSuccess: () => { onChange(); toast.success("Scope updated"); },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed"),
  });

  const addRule = () => {
    if (!pattern.trim()) return;
    save.mutate([...rules, { pattern: pattern.trim(), type: ptype, in_scope: inScope }]);
    setPattern("");
  };
  const removeRule = (idx: number) => save.mutate(rules.filter((_, i) => i !== idx));

  const roe = program.rules_of_engagement || {};

  return (
    <div className="space-y-5">
      <div>
        <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-1.5"><ShieldAlert className="w-3.5 h-3.5 text-muted-foreground" /> Scope Rules</h3>
        <p className="text-xs text-muted-foreground mb-3">
          Explicit out-of-scope rules always win over an in-scope match. Every stage re-validates targets
          against these rules at execution time — narrowing scope here immediately blocks anything that
          no longer matches.
        </p>
        <div className="space-y-1.5 mb-3">
          {rules.length === 0 && <EmptyState icon={ShieldAlert} label="No scope rules — nothing is testable yet." />}
          {rules.map((r, i) => (
            <div key={i} className={cn("flex items-center gap-3 p-2.5 rounded-lg bg-surface-900 border border-border", LIFT)}>
              <span className={cn(
                "text-[11px] px-1.5 py-0.5 rounded border font-medium",
                r.in_scope ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" : "text-critical bg-critical/10 border-critical/30",
              )}>
                {r.in_scope ? "IN SCOPE" : "OUT OF SCOPE"}
              </span>
              <span className="text-xs text-muted-foreground uppercase">{r.type}</span>
              <span className="text-sm text-foreground font-mono flex-1 truncate">{r.pattern}</span>
              <button onClick={() => removeRule(i)} className="text-muted-foreground hover:text-critical transition-colors"><X className="w-4 h-4" /></button>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={pattern} onChange={(e) => setPattern(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addRule()}
            placeholder="*.example.com  /  203.0.113.0/24  /  https://api.example.com/*"
            className="flex-1 min-w-[220px] bg-surface-800 border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:border-rose-500/50 transition-colors"
          />
          <select value={ptype} onChange={(e) => setPtype(e.target.value)} className="bg-surface-800 border border-border rounded-lg px-2 py-2 text-sm text-foreground">
            <option value="domain">domain</option>
            <option value="ip">ip</option>
            <option value="url">url</option>
          </select>
          <select value={inScope ? "in" : "out"} onChange={(e) => setInScope(e.target.value === "in")} className="bg-surface-800 border border-border rounded-lg px-2 py-2 text-sm text-foreground">
            <option value="in">in scope</option>
            <option value="out">out of scope</option>
          </select>
          <button onClick={addRule} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" /> Add
          </button>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-1.5"><SlidersHorizontal className="w-3.5 h-3.5 text-muted-foreground" /> Rules of Engagement</h3>
        <p className="text-xs text-muted-foreground mb-2">
          Per-program aggressiveness dials read by the workers. Conservative by default; escalation is
          always explicit. (Edit via API / config — shown here read-only.)
        </p>
        <pre className="text-xs text-muted-foreground bg-surface-900 border border-border rounded-lg p-3 overflow-x-auto">
          {JSON.stringify(Object.keys(roe).length ? roe : {
            exploit_modules: ["xss", "lfi", "csrf", "idor"],
            sqlmap_level: 1, sqlmap_risk: 1,
          }, null, 2)}
        </pre>
      </div>
    </div>
  );
}

// ── Targets tab ───────────────────────────────────────────────

function TargetsTab({ programId, onChange }: { programId: string; onChange: () => void }) {
  const qc = useQueryClient();
  const [value, setValue] = useState("");
  const [ttype, setTtype] = useState("domain");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "alive" | "dead">("all");
  const [view, setView] = useState<"grouped" | "table">("grouped");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const { data } = useQuery({
    queryKey: ["bounty-targets", programId],
    queryFn: () => bountyAPI.listTargets(programId).then((r) => r.data),
  });
  const targets: any[] = data?.items || [];
  const refresh = () => { qc.invalidateQueries({ queryKey: ["bounty-targets", programId] }); onChange(); };

  const add = useMutation({
    mutationFn: () => bountyAPI.createTarget(programId, { value: value.trim(), target_type: ttype }),
    onSuccess: () => { refresh(); setValue(""); toast.success("Target added"); },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Rejected — check scope rules"),
  });
  const del = useMutation({
    mutationFn: (tid: string) => bountyAPI.deleteTarget(programId, tid),
    onSuccess: refresh,
  });

  const aliveCount = targets.filter((t) => t.is_alive === true).length;
  const deadCount = targets.filter((t) => t.is_alive === false).length;

  const passesFilter = (t: any) => filter === "all" || (filter === "alive" ? t.is_alive === true : t.is_alive === false);
  const q = query.trim().toLowerCase();
  const matchesQuery = (t: any) => !q || t.value.toLowerCase().includes(q);

  const filtered = targets.filter((t) => passesFilter(t) && matchesQuery(t));
  const { domainItems, childrenByDomain, ungrouped } = useMemo(() => {
    const eligible = targets.filter((t) => filter === "all" || (filter === "alive" ? t.is_alive === true : t.is_alive === false));
    return groupByDomain(eligible, (t) => t.target_type === "domain");
  }, [targets, filter]);

  const row = (t: any, indented = false) => (
    <div key={t.id} className={cn("flex items-center gap-3 p-2.5 rounded-lg bg-surface-900 border border-border", indented && "ml-6 bg-surface-900/60", !indented && LIFT)}>
      <span className="text-xs text-muted-foreground uppercase w-14 flex-shrink-0">{t.target_type}</span>
      <span className="text-sm text-foreground font-mono flex-1 truncate">{t.value}</span>
      {t.is_alive === true && <span className="text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-medium">alive</span>}
      {t.is_alive === false && <span className="text-[11px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 font-medium">no response</span>}
      <button onClick={() => del.mutate(t.id)} className="text-muted-foreground hover:text-critical transition-colors"><X className="w-4 h-4" /></button>
    </div>
  );

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        The explicit, human-approved testable list. A target is rejected unless it passes the
        program&apos;s scope rules — so it can never exist here without also being in scope.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={value} onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add.mutate()}
          placeholder="app.example.com  /  https://api.example.com/v1?id=1"
          className="flex-1 min-w-[220px] bg-surface-800 border border-border rounded-lg px-3 py-2 text-sm font-mono text-foreground focus:outline-none focus:border-rose-500/50 transition-colors"
        />
        <select value={ttype} onChange={(e) => setTtype(e.target.value)} className="bg-surface-800 border border-border rounded-lg px-2 py-2 text-sm text-foreground">
          <option value="domain">domain</option>
          <option value="ip">ip</option>
          <option value="url">url</option>
        </select>
        <button onClick={() => add.mutate()} disabled={add.isPending} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" /> Add
        </button>
      </div>

      {targets.length === 0 ? (
        <EmptyState icon={Target} label="No approved targets yet." />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={query} onChange={setQuery} placeholder="Search domain or URL…" />
            <FilterChip active={filter === "all"} onClick={() => setFilter("all")}>All <span className="opacity-60 ml-0.5">{targets.length}</span></FilterChip>
            <FilterChip active={filter === "alive"} onClick={() => setFilter("alive")}>Alive <span className="opacity-60 ml-0.5">{aliveCount}</span></FilterChip>
            <FilterChip active={filter === "dead"} onClick={() => setFilter("dead")}>No response <span className="opacity-60 ml-0.5">{deadCount}</span></FilterChip>
            <ViewToggle view={view} onChange={setView} />
          </div>

          {view === "table" ? (
            <div className="border border-border rounded-lg overflow-auto max-h-[520px]">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-surface-900">
                  <tr className="text-[11px] uppercase tracking-wide text-muted-foreground text-left">
                    <th className="px-3 py-2 font-semibold">Type</th>
                    <th className="px-3 py-2 font-semibold">Value</th>
                    <th className="px-3 py-2 font-semibold">Status</th>
                    <th className="px-3 py-2 font-semibold"></th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr><td colSpan={4}><EmptyState icon={SearchX} label={`No matches for "${query}"`} /></td></tr>
                  ) : filtered.map((t) => (
                    <tr key={t.id} className="border-t border-border hover:bg-rose-500/5">
                      <td className="px-3 py-2 text-xs text-muted-foreground uppercase">{t.target_type}</td>
                      <td className="px-3 py-2 font-mono text-foreground truncate max-w-0">{t.value}</td>
                      <td className="px-3 py-2">
                        {t.is_alive === true && <span className="text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-medium">alive</span>}
                        {t.is_alive === false && <span className="text-[11px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 font-medium">no response</span>}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <button onClick={() => del.mutate(t.id)} className="text-muted-foreground hover:text-critical transition-colors"><X className="w-4 h-4" /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="space-y-1.5">
              {q && domainItems.every((d) => !d.value.toLowerCase().includes(q)) && childrenByDomain.size === 0 && ungrouped.length === 0 && (
                <EmptyState icon={SearchX} label={`No matches for "${query}"`} />
              )}
              {domainItems.map((d) => {
                if (q && !d.value.toLowerCase().includes(q) && !(childrenByDomain.get(d.value) || []).some((c) => c.value.toLowerCase().includes(q))) return null;
                const children = (childrenByDomain.get(d.value) || []).filter(matchesQuery);
                const isOpen = !collapsed.has(d.id);
                if (children.length === 0) return row(d);
                return (
                  <div key={d.id} className="border border-border rounded-lg overflow-hidden bg-surface-900">
                    <button
                      onClick={() => setCollapsed((prev) => { const n = new Set(prev); n.has(d.id) ? n.delete(d.id) : n.add(d.id); return n; })}
                      className="w-full flex items-center gap-2.5 px-3 py-2.5 bg-surface-800/60 hover:bg-surface-800 transition-colors text-left"
                    >
                      <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform flex-shrink-0", !isOpen && "-rotate-90")} />
                      {d.is_alive === true && <span className="text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-medium">alive</span>}
                      {d.is_alive === false && <span className="text-[11px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 font-medium">no response</span>}
                      <span className="text-sm text-foreground font-mono font-semibold">{d.value}</span>
                      <span className="text-[11px] text-muted-foreground ml-auto tabular-nums">{children.length} url{children.length === 1 ? "" : "s"}</span>
                      <button onClick={(e) => { e.stopPropagation(); del.mutate(d.id); }} className="text-muted-foreground hover:text-critical transition-colors"><X className="w-3.5 h-3.5" /></button>
                    </button>
                    <div className={cn("grid transition-[grid-template-rows] duration-200 ease-out", isOpen ? "grid-rows-[1fr]" : "grid-rows-[0fr]")}>
                      <div className="overflow-hidden">
                        {children.map((c) => (
                          <div key={c.id} className="flex items-center gap-3 pl-9 pr-3 py-2 text-sm border-t border-border hover:bg-rose-500/5 transition-colors">
                            <span className="text-foreground/90 font-mono flex-1 truncate">{c.value}</span>
                            <button onClick={() => del.mutate(c.id)} className="text-muted-foreground hover:text-critical transition-colors"><X className="w-3.5 h-3.5" /></button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
              {ungrouped.filter(matchesQuery).map((t) => row(t))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Recon tab ─────────────────────────────────────────────────

function ReconTab({ programId, onChange }: { programId: string; onChange: () => void }) {
  const qc = useQueryClient();
  // Two fetches, not one: the API caps page_size at 200 and sorts by most-
  // recently-discovered, so on a program with 200+ newer URL/js_endpoint
  // rows than subdomain rows (routine once katana/waybackurls run), a single
  // "most recent 200" fetch can come back with *zero* subdomain-type rows --
  // silently breaking the grouped view below (nothing left to group under).
  // Fetching subdomains on their own guarantees the domain groups always
  // have somewhere to attach, regardless of how recon's mix of asset types
  // shakes out on any given program.
  const { data: domainsData } = useQuery({
    queryKey: ["bounty-assets", programId, "subdomain"],
    queryFn: () => bountyAPI.listAssets(programId, { asset_type: "subdomain", page_size: 200 }).then((r) => r.data),
  });
  const { data } = useQuery({
    queryKey: ["bounty-assets", programId],
    queryFn: () => bountyAPI.listAssets(programId, { page_size: 200 }).then((r) => r.data),
  });
  const assets: any[] = useMemo(() => {
    const merged = new Map<string, any>();
    for (const a of domainsData?.items || []) merged.set(a.id, a);
    for (const a of data?.items || []) merged.set(a.id, a);
    return Array.from(merged.values());
  }, [domainsData, data]);
  const totalAssets: number = data?.total ?? assets.length;
  const isPromotable = (a: any) => ["subdomain", "url", "ip"].includes(a.asset_type) && !a.promoted;
  const promotableAssets = assets.filter(isPromotable);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "promoted" | "unpromoted">("all");
  const [view, setView] = useState<"grouped" | "table">("grouped");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  const allSelected = promotableAssets.length > 0 && promotableAssets.every((a) => selected.has(a.id));
  const toggleAll = () =>
    setSelected(allSelected ? new Set() : new Set(promotableAssets.map((a) => a.id)));

  const invalidateAfterPromote = () => {
    qc.invalidateQueries({ queryKey: ["bounty-assets", programId] });
    qc.invalidateQueries({ queryKey: ["bounty-targets", programId] });
    onChange();
  };

  const promote = useMutation({
    mutationFn: (assetId: string) => bountyAPI.promoteAsset(programId, assetId),
    onSuccess: () => {
      invalidateAfterPromote();
      toast.success("Promoted to an approved target");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Cannot promote"),
  });

  const promoteBulk = useMutation({
    mutationFn: (assetIds: string[]) => bountyAPI.promoteAssetsBulk(programId, assetIds),
    onSuccess: (res: any) => {
      invalidateAfterPromote();
      setSelected(new Set());
      const { promoted, skipped } = res.data;
      toast.success(
        skipped > 0 ? `Promoted ${promoted} · skipped ${skipped} (out of scope / already exists)` : `Promoted ${promoted} to approved targets`
      );
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Bulk promote failed"),
  });

  const promotedCount = assets.filter((a) => a.promoted).length;
  const unpromotedCount = assets.length - promotedCount;
  const passesFilter = (a: any) => filter === "all" || (filter === "promoted" ? a.promoted : !a.promoted);
  const q = query.trim().toLowerCase();
  const matchesQuery = (a: any) => !q || a.value.toLowerCase().includes(q);
  const filtered = assets.filter((a) => passesFilter(a) && matchesQuery(a));

  const { domainItems, childrenByDomain, ungrouped } = useMemo(() => {
    const eligible = assets.filter((a) => filter === "all" || (filter === "promoted" ? a.promoted : !a.promoted));
    return groupByDomain(eligible, (a) => a.asset_type === "subdomain");
  }, [assets, filter]);

  const assetActionCell = (a: any) => (
    <>
      {a.promoted ? (
        <span className="text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-medium flex-shrink-0">promoted</span>
      ) : isPromotable(a) ? (
        <button
          onClick={() => promote.mutate(a.id)}
          className="flex items-center gap-1 text-[11px] text-rose-400 hover:text-rose-300 font-medium flex-shrink-0 transition-colors"
        >
          <ArrowUpCircle className="w-3.5 h-3.5" /> Promote
        </button>
      ) : null}
    </>
  );

  const row = (a: any, indented = false) => (
    <div key={a.id} className={cn("flex items-center gap-3 p-2.5 rounded-lg bg-surface-900 border border-border", indented && "ml-6 bg-surface-900/60", !indented && LIFT)}>
      <div className="w-3.5 flex-shrink-0">
        {isPromotable(a) && (
          <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} className="w-3.5 h-3.5 rounded accent-rose-500" />
        )}
      </div>
      {!indented && <span className="text-xs text-muted-foreground uppercase w-24 flex-shrink-0">{a.asset_type}</span>}
      <span className="text-sm text-foreground font-mono flex-1 truncate">{a.value}</span>
      <span className="text-[11px] text-muted-foreground hidden sm:block">{a.source}</span>
      {assetActionCell(a)}
    </div>
  );

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Recon output — a suggestion list. Nothing here is testable until you explicitly promote it to a
        target. Discovery never expands scope on its own.
        {totalAssets > assets.length && (
          <span className="text-amber-400"> Showing the {assets.length} most recent of {totalAssets} — search to find something older.</span>
        )}
      </p>
      {assets.length === 0 ? (
        <EmptyState icon={Radar} label="No recon results. Run the Recon stage to populate this." />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={query} onChange={setQuery} placeholder="Search domain or URL…" />
            <FilterChip active={filter === "all"} onClick={() => setFilter("all")}>All <span className="opacity-60 ml-0.5">{assets.length}</span></FilterChip>
            <FilterChip active={filter === "unpromoted"} onClick={() => setFilter("unpromoted")}>Not promoted <span className="opacity-60 ml-0.5">{unpromotedCount}</span></FilterChip>
            <FilterChip active={filter === "promoted"} onClick={() => setFilter("promoted")}>Promoted <span className="opacity-60 ml-0.5">{promotedCount}</span></FilterChip>
            <ViewToggle view={view} onChange={setView} />
          </div>

          {promotableAssets.length > 0 && (
            <div className="flex items-center gap-3 p-2 rounded-lg bg-surface-800/60 border border-border">
              <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
                <input type="checkbox" checked={allSelected} onChange={toggleAll} className="w-3.5 h-3.5 rounded accent-rose-500" />
                Select all ({promotableAssets.length})
              </label>
              <span className="flex-1" />
              <span className="text-xs text-muted-foreground tabular-nums">{selected.size} selected</span>
              <button
                onClick={() => promoteBulk.mutate(Array.from(selected))}
                disabled={selected.size === 0 || promoteBulk.isPending}
                className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-md bg-rose-600 text-white hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {promoteBulk.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ArrowUpCircle className="w-3.5 h-3.5" />}
                Promote Selected ({selected.size})
              </button>
            </div>
          )}

          {view === "table" ? (
            <div className="border border-border rounded-lg overflow-auto max-h-[520px]">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-surface-900">
                  <tr className="text-[11px] uppercase tracking-wide text-muted-foreground text-left">
                    <th className="px-3 py-2 font-semibold w-8"></th>
                    <th className="px-3 py-2 font-semibold">Type</th>
                    <th className="px-3 py-2 font-semibold">Value</th>
                    <th className="px-3 py-2 font-semibold">Source</th>
                    <th className="px-3 py-2 font-semibold"></th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr><td colSpan={5}><EmptyState icon={SearchX} label={`No matches for "${query}"`} /></td></tr>
                  ) : filtered.map((a) => (
                    <tr key={a.id} className="border-t border-border hover:bg-rose-500/5">
                      <td className="px-3 py-2">{isPromotable(a) && <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} className="w-3.5 h-3.5 rounded accent-rose-500" />}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground uppercase">{a.asset_type}</td>
                      <td className="px-3 py-2 font-mono text-foreground truncate max-w-0">{a.value}</td>
                      <td className="px-3 py-2 text-[11px] text-muted-foreground">{a.source}</td>
                      <td className="px-3 py-2 text-right">{assetActionCell(a)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="space-y-1.5">
              {domainItems.map((d) => {
                if (q && !d.value.toLowerCase().includes(q) && !(childrenByDomain.get(d.value) || []).some((c) => c.value.toLowerCase().includes(q))) return null;
                const children = (childrenByDomain.get(d.value) || []).filter(matchesQuery);
                const isOpen = !collapsed.has(d.id);
                if (children.length === 0) return row(d);
                return (
                  <div key={d.id} className="border border-border rounded-lg overflow-hidden bg-surface-900">
                    <div className="w-full flex items-center gap-2.5 px-3 py-2.5 bg-surface-800/60">
                      <button onClick={() => setCollapsed((prev) => { const n = new Set(prev); n.has(d.id) ? n.delete(d.id) : n.add(d.id); return n; })} className="flex items-center gap-2.5 flex-1 min-w-0 text-left">
                        <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform flex-shrink-0", !isOpen && "-rotate-90")} />
                        <span className="text-sm text-foreground font-mono font-semibold truncate">{d.value}</span>
                        <span className="text-[11px] text-muted-foreground ml-auto flex-shrink-0 tabular-nums">{children.length} url{children.length === 1 ? "" : "s"}</span>
                      </button>
                      <span className="flex-shrink-0">{assetActionCell(d)}</span>
                    </div>
                    <div className={cn("grid transition-[grid-template-rows] duration-200 ease-out", isOpen ? "grid-rows-[1fr]" : "grid-rows-[0fr]")}>
                      <div className="overflow-hidden">
                        {children.map((c) => (
                          <div key={c.id} className="flex items-center gap-3 pl-9 pr-3 py-2 text-sm border-t border-border hover:bg-rose-500/5 transition-colors">
                            <div className="w-3.5 flex-shrink-0">
                              {isPromotable(c) && <input type="checkbox" checked={selected.has(c.id)} onChange={() => toggle(c.id)} className="w-3.5 h-3.5 rounded accent-rose-500" />}
                            </div>
                            <span className="text-foreground/90 font-mono flex-1 truncate">{c.value}</span>
                            <span className="text-[11px] text-muted-foreground hidden sm:block flex-shrink-0">{c.source}</span>
                            {assetActionCell(c)}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
              {ungrouped.filter(matchesQuery).map((a) => row(a))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Findings tab ──────────────────────────────────────────────

function FindingsTab({ programId }: { programId: string }) {
  const { data } = useQuery({
    queryKey: ["bounty-findings", programId],
    queryFn: () => bountyAPI.listFindings(programId, { page_size: 200 }).then((r) => r.data),
  });
  const findings: any[] = data?.items || [];
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | "confirmed" | "inconclusive">("all");
  const [sev, setSev] = useState<"all" | "critical" | "high" | "medium" | "low" | "info">("all");

  const confirmedCount = findings.filter((f) => f.status === "confirmed").length;
  const inconclusiveCount = findings.filter((f) => f.status === "inconclusive").length;

  const q = query.trim().toLowerCase();
  const filtered = findings.filter((f) =>
    (status === "all" || f.status === status) &&
    (sev === "all" || f.severity === sev) &&
    (!q || f.technique?.toLowerCase().includes(q) || f.evidence?.target_url?.toLowerCase().includes(q)),
  );

  if (findings.length === 0) {
    return <EmptyState icon={Bug} label="No findings yet. Run Vuln Scan or Exploit stages." />;
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput value={query} onChange={setQuery} placeholder="Search technique or URL…" />
        <FilterChip active={status === "all"} onClick={() => setStatus("all")}>All <span className="opacity-60 ml-0.5">{findings.length}</span></FilterChip>
        <FilterChip active={status === "confirmed"} onClick={() => setStatus("confirmed")}>Confirmed <span className="opacity-60 ml-0.5">{confirmedCount}</span></FilterChip>
        <FilterChip active={status === "inconclusive"} onClick={() => setStatus("inconclusive")}>Candidate <span className="opacity-60 ml-0.5">{inconclusiveCount}</span></FilterChip>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {(["all", "critical", "high", "medium", "low", "info"] as const).map((s) => (
          <FilterChip key={s} active={sev === s} onClick={() => setSev(s)}>
            {s === "all" ? "All severities" : s.charAt(0).toUpperCase() + s.slice(1)}
          </FilterChip>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">{filtered.length} of {findings.length} findings shown</p>

      <div className="space-y-2">
        {filtered.length === 0 ? (
          <EmptyState icon={SearchX} label="No findings match your filters." />
        ) : filtered.map((f) => (
          <div key={f.id} className={cn("p-3 rounded-lg bg-surface-900 border border-border", LIFT, "hover:border-rose-500/25")}>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", SEV_BAR_CLS[f.severity] || "bg-info")} />
              <span className="text-xs uppercase font-semibold text-muted-foreground">{f.module}</span>
              <span className={cn("text-xs font-semibold capitalize", SEV_CLS[f.severity] || "text-info")}>{f.severity}</span>
              <span className={cn("text-[11px] px-1.5 py-0.5 rounded border font-medium", STATUS_CLS[f.status] || STATUS_CLS.blocked)}>
                {f.status}
              </span>
              <span className="text-sm text-foreground font-mono flex-1 truncate">{f.technique}</span>
            </div>
            {f.evidence?.target_url && (
              <p className="text-xs text-muted-foreground font-mono mt-1.5 truncate flex items-center gap-1.5">
                <ExternalLink className="w-3 h-3 flex-shrink-0 opacity-60" /> {f.evidence.target_url}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Reports tab ───────────────────────────────────────────────

function ReportsTab({ programId }: { programId: string }) {
  const [openId, setOpenId] = useState<string | null>(null);
  const { data } = useQuery({
    queryKey: ["bounty-reports", programId],
    queryFn: () => bountyAPI.listReports(programId).then((r) => r.data),
  });
  const reports: any[] = data?.items || [];

  const { data: report } = useQuery({
    queryKey: ["bounty-report", programId, openId],
    queryFn: () => bountyAPI.getReport(programId, openId!).then((r) => r.data),
    enabled: !!openId,
  });

  if (reports.length === 0) {
    return <EmptyState icon={ScrollText} label="No report drafts. Run the Report stage on confirmed findings." />;
  }

  return (
    <div className="space-y-2">
      {reports.map((r) => (
        <div key={r.id} className={cn("rounded-lg bg-surface-900 border border-border overflow-hidden", LIFT)}>
          <button
            onClick={() => setOpenId(openId === r.id ? null : r.id)}
            className="w-full flex items-center gap-3 p-3 text-left hover:bg-surface-800/50 transition-colors"
          >
            <ScrollText className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span className="text-sm text-foreground flex-1 truncate">{r.title}</span>
            <span className="text-[11px] px-1.5 py-0.5 rounded border border-border text-muted-foreground capitalize">{r.status}</span>
            <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform flex-shrink-0", openId === r.id && "rotate-180")} />
          </button>
          <div className={cn("grid transition-[grid-template-rows] duration-200 ease-out", openId === r.id ? "grid-rows-[1fr]" : "grid-rows-[0fr]")}>
            <div className="overflow-hidden">
              {report && (
                <div className="border-t border-border p-3">
                  <pre className="text-xs text-muted-foreground whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">{report.markdown}</pre>
                  <button
                    onClick={() => { navigator.clipboard.writeText(report.markdown); toast.success("Markdown copied"); }}
                    className="mt-2 flex items-center gap-1.5 text-xs text-rose-400 hover:text-rose-300 font-medium transition-colors"
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> Copy Markdown
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
