"use client";

import { useMemo, useState, type ReactNode } from "react";
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

// The full module set exploit_worker.py::ALL_MODULES runs by default when
// exploit_modules is unset -- mirrored here so the checkboxes' "everything
// checked" state actually matches what the pipeline does with no override.
const EXPLOIT_MODULES = [
  "xss", "sqli", "ssrf", "lfi", "idor", "csrf",
  "ssti", "nosql", "jsonbody", "oauth", "bac", "upload", "jwt",
] as const;
const NUCLEI_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
// Off by default (BOUNTY_DEFAULT_EXCLUDED_TAGS in vulnscan_worker.py) -- only
// re-included via allowed_extra_tags, never a blanket global.
const EXTRA_NUCLEI_TAGS = ["dos", "destructive", "unsafe"] as const;

function toDatetimeLocal(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function omitEmpty(d: Record<string, any>, key: string, value: any): Record<string, any> {
  const isEmpty = value === "" || value === undefined || value === null || (Array.isArray(value) && value.length === 0);
  if (isEmpty) {
    const { [key]: _omit, ...rest } = d;
    return rest;
  }
  return { ...d, [key]: value };
}

function FieldLabel({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <label className="block text-xs font-medium text-muted-foreground mb-1" title={hint}>
      {children}
    </label>
  );
}

const roeInputCls = "w-full bg-surface-800 border border-border rounded-lg px-3 py-1.5 text-sm text-foreground font-mono focus:outline-none focus:border-rose-500/50 transition-colors";

function RulesOfEngagementEditor({ program, onChange }: { program: any; onChange: () => void }) {
  const savedRoe = program.rules_of_engagement || {};
  const [programId, setProgramId] = useState(program.id);
  const [draft, setDraft] = useState<Record<string, any>>(savedRoe);
  const [rawMode, setRawMode] = useState(false);
  const [rawText, setRawText] = useState(() => JSON.stringify(savedRoe, null, 2));
  const [rawError, setRawError] = useState<string | null>(null);
  const [fieldsError, setFieldsError] = useState<string | null>(null);
  const [fieldsText, setFieldsText] = useState(() => JSON.stringify(savedRoe.idor_registration_fields || {}, null, 2));

  // Reset local edit buffers when switching to a different program -- derived
  // state during render (React's own recommended pattern) rather than a
  // useEffect, so there's no stale-draft flash from another program's data.
  if (program.id !== programId) {
    setProgramId(program.id);
    setDraft(savedRoe);
    setRawText(JSON.stringify(savedRoe, null, 2));
    setFieldsText(JSON.stringify(savedRoe.idor_registration_fields || {}, null, 2));
    setRawError(null);
    setFieldsError(null);
  }

  const save = useMutation({
    mutationFn: (roe: Record<string, any>) => bountyAPI.updateProgram(program.id, { rules_of_engagement: roe }),
    onSuccess: () => { onChange(); toast.success("Rules of engagement updated"); },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed"),
  });

  const set = (key: string, value: any) => setDraft((d) => omitEmpty(d, key, value));

  const toggleInList = (key: string, value: string, allValues: readonly string[]) => {
    setDraft((d) => {
      const current: string[] = d[key] ?? [...allValues];
      const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
      return next.length === allValues.length ? omitEmpty(d, key, undefined) : { ...d, [key]: next };
    });
  };

  const handleSave = () => {
    if (rawMode) {
      try {
        const parsed = JSON.parse(rawText);
        setRawError(null);
        setDraft(parsed);
        save.mutate(parsed);
      } catch {
        setRawError("Invalid JSON — fix before saving.");
      }
      return;
    }
    save.mutate(draft);
  };

  const applyFieldsText = (text: string) => {
    setFieldsText(text);
    try {
      const parsed = JSON.parse(text);
      setFieldsError(null);
      set("idor_registration_fields", parsed);
    } catch {
      setFieldsError("Invalid JSON");
    }
  };

  const modules: string[] = draft.exploit_modules ?? [...EXPLOIT_MODULES];
  const severities: string[] = draft.nuclei_severities ?? [...NUCLEI_SEVERITIES];
  const extraTags: string[] = draft.allowed_extra_tags ?? [];

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-1.5">
          <SlidersHorizontal className="w-3.5 h-3.5 text-muted-foreground" /> Rules of Engagement
        </h3>
        <button
          onClick={() => {
            if (!rawMode) setRawText(JSON.stringify(draft, null, 2));
            setRawMode((v) => !v);
          }}
          className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2"
        >
          {rawMode ? "Back to form" : "Edit as raw JSON"}
        </button>
      </div>
      <p className="text-xs text-muted-foreground mb-3">
        Per-program aggressiveness dials read by the workers at execution time. Conservative by default;
        every capability below is opt-in — leaving a field empty keeps the safe default.
      </p>

      {rawMode ? (
        <div className="space-y-2">
          <textarea
            value={rawText}
            onChange={(e) => { setRawText(e.target.value); setRawError(null); }}
            rows={16}
            spellCheck={false}
            className={cn(roeInputCls, "resize-y")}
          />
          {rawError && <p className="text-xs text-critical">{rawError}</p>}
        </div>
      ) : (
        <div className="space-y-5">
          <div>
            <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">Authentication</h4>
            <p className="text-[11px] text-muted-foreground mb-2">
              Log in once as a test account and carry the session through recon/vulnscan/exploit — without
              this, testing only ever sees the slice of the app that doesn&apos;t require a login.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <div className="col-span-2">
                <FieldLabel>Login URL</FieldLabel>
                <input className={roeInputCls} placeholder="https://target/rest/user/login"
                  value={draft.auth_login_url || ""} onChange={(e) => set("auth_login_url", e.target.value)} />
              </div>
              <div>
                <FieldLabel>Email / username</FieldLabel>
                <input className={roeInputCls} value={draft.auth_email || ""} onChange={(e) => set("auth_email", e.target.value)} />
              </div>
              <div>
                <FieldLabel>Password</FieldLabel>
                <input className={roeInputCls} type="password" value={draft.auth_password || ""} onChange={(e) => set("auth_password", e.target.value)} />
              </div>
              <div>
                <FieldLabel hint="JSON body field name for the identifier, default 'email'">Email field name</FieldLabel>
                <input className={roeInputCls} placeholder="email" value={draft.auth_email_field || ""} onChange={(e) => set("auth_email_field", e.target.value)} />
              </div>
              <div>
                <FieldLabel hint="JSON body field name for the password, default 'password'">Password field name</FieldLabel>
                <input className={roeInputCls} placeholder="password" value={draft.auth_password_field || ""} onChange={(e) => set("auth_password_field", e.target.value)} />
              </div>
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">Exploit modules</h4>
            <p className="text-[11px] text-muted-foreground mb-2">All 13 modules run by default — uncheck to narrow.</p>
            <div className="flex flex-wrap gap-1.5">
              {EXPLOIT_MODULES.map((m) => (
                <button key={m} onClick={() => toggleInList("exploit_modules", m, EXPLOIT_MODULES)}
                  className={cn(
                    "text-[11px] px-2 py-1 rounded border font-mono transition-colors",
                    modules.includes(m)
                      ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                      : "text-muted-foreground bg-surface-800 border-border",
                  )}>
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">SQLi intensity</h4>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <FieldLabel>sqlmap level (1-5)</FieldLabel>
                  <input className={roeInputCls} type="number" min={1} max={5}
                    value={draft.sqlmap_level ?? ""} placeholder="1"
                    onChange={(e) => set("sqlmap_level", e.target.value ? Math.max(1, Math.min(5, Number(e.target.value))) : undefined)} />
                </div>
                <div>
                  <FieldLabel>sqlmap risk (1-3)</FieldLabel>
                  <input className={roeInputCls} type="number" min={1} max={3}
                    value={draft.sqlmap_risk ?? ""} placeholder="1"
                    onChange={(e) => set("sqlmap_risk", e.target.value ? Math.max(1, Math.min(3, Number(e.target.value))) : undefined)} />
                </div>
              </div>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">SSRF confirmation</h4>
              <FieldLabel hint="An interactsh/collaborator host you control -- SSRF stays a no-op without this">OOB domain</FieldLabel>
              <input className={roeInputCls} placeholder="your-oob.interact.sh" value={draft.oob_domain || ""} onChange={(e) => set("oob_domain", e.target.value)} />
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">Two-identity IDOR</h4>
            <p className="text-[11px] text-muted-foreground mb-2">
              Registers a second, disposable test account and compares its access against the primary
              identity&apos;s — a real capability increase (it creates a real account), not a passive check.
            </p>
            <div className="space-y-2">
              <div>
                <FieldLabel>Registration URL</FieldLabel>
                <input className={roeInputCls} placeholder="https://target/api/Users" value={draft.idor_registration_url || ""} onChange={(e) => set("idor_registration_url", e.target.value)} />
              </div>
              <div>
                <FieldLabel hint="JSON template -- {email}/{password} are substituted for the generated second identity">Registration payload template (JSON)</FieldLabel>
                <textarea className={cn(roeInputCls, "resize-y")} rows={4} spellCheck={false}
                  value={fieldsText} onChange={(e) => applyFieldsText(e.target.value)} />
                {fieldsError && <p className="text-xs text-critical mt-1">{fieldsError}</p>}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input type="checkbox" id="stored_xss_test" checked={!!draft.stored_xss_test}
              onChange={(e) => set("stored_xss_test", e.target.checked || undefined)}
              className="w-4 h-4 accent-rose-600" />
            <label htmlFor="stored_xss_test" className="text-sm text-foreground">
              Stored-XSS testing <span className="text-muted-foreground">(fills &amp; submits a real form field on the target — creates visible content)</span>
            </label>
          </div>

          <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/5 space-y-4">
            <div>
              <h4 className="text-xs font-semibold text-amber-400 mb-1 uppercase tracking-wide flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> Aggressive testing (opt-in only)
              </h4>
              <p className="text-[11px] text-muted-foreground">
                Off by default and deliberately separate from the module chips above — each of these
                either really executes something on the target, sends a real burst of repeated requests,
                or triggers a real flow. Only turn these on for a program you&apos;ve discussed this with.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <input type="checkbox" id="cmdi_test" checked={!!draft.cmdi_test}
                onChange={(e) => set("cmdi_test", e.target.checked || undefined)}
                className="w-4 h-4 accent-amber-500" />
              <label htmlFor="cmdi_test" className="text-sm text-foreground">
                OS command injection <span className="text-muted-foreground">(non-destructive: timing/echo-marker probes only, never reads/writes/deletes anything — but a working hit does execute a real command)</span>
              </label>
            </div>

            <div>
              <div className="flex items-center gap-2 mb-2">
                <input type="checkbox" id="brute_force_test" checked={!!draft.brute_force_test}
                  onChange={(e) => set("brute_force_test", e.target.checked || undefined)}
                  className="w-4 h-4 accent-amber-500" />
                <label htmlFor="brute_force_test" className="text-sm text-foreground">
                  Login rate-limit / lockout test <span className="text-muted-foreground">(sends repeated failed logins against a fake, never-registered email — never your real test account)</span>
                </label>
              </div>
              {draft.brute_force_test && (
                <div className="max-w-[200px] ml-6">
                  <FieldLabel>Attempts (5–50)</FieldLabel>
                  <input className={roeInputCls} type="number" min={5} max={50} placeholder="15"
                    value={draft.brute_force_test_attempts ?? ""}
                    onChange={(e) => set("brute_force_test_attempts", e.target.value ? Math.max(5, Math.min(50, Number(e.target.value))) : undefined)} />
                </div>
              )}
            </div>

            <div>
              <FieldLabel hint="Requests a reset for auth_email and checks two things: whether the API response itself leaks the token, and whether it reflects an attacker-controlled Host/X-Forwarded-Host header back into a generated link (host-header poisoning). Never completes a reset, your test account's password is never touched">Password-reset checks (token leak + host-header poisoning) — reset endpoint URL</FieldLabel>
              <input className={roeInputCls} placeholder="https://target/api/auth/forgot-password" value={draft.password_reset_url || ""} onChange={(e) => set("password_reset_url", e.target.value)} />
              <p className="text-[11px] text-muted-foreground mt-1">Leave empty to skip — uses the Authentication email above, read-only (no reset is ever completed).</p>
            </div>

            <div>
              <FieldLabel hint="Fires N identical requests at this exact endpoint as close to simultaneously as possible and reports if more than one succeeded — only meaningful for an action that should be single-use/quantity-limited (coupon redemption, one-time claim, balance transfer, limited-stock purchase). Always reported inconclusive, never confirmed — the pipeline can't judge business-logic impact on its own, that's for you to verify manually. Needs a specific endpoint you already suspect; there's no generic way to discover one">Race-condition / TOCTOU probe — target endpoint URL</FieldLabel>
              <input className={roeInputCls} placeholder="https://target/api/coupon/redeem" value={draft.race_condition_url || ""} onChange={(e) => set("race_condition_url", e.target.value)} />
              {draft.race_condition_url && (
                <div className="grid grid-cols-2 gap-2 mt-2 max-w-sm">
                  <div>
                    <FieldLabel>Method</FieldLabel>
                    <select className={roeInputCls} value={draft.race_condition_method || "POST"}
                      onChange={(e) => set("race_condition_method", e.target.value)}>
                      {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => <option key={m} value={m}>{m}</option>)}
                    </select>
                  </div>
                  <div>
                    <FieldLabel>Concurrent attempts (5–50)</FieldLabel>
                    <input className={roeInputCls} type="number" min={5} max={50} placeholder="15"
                      value={draft.race_condition_attempts ?? ""}
                      onChange={(e) => set("race_condition_attempts", e.target.value ? Math.max(5, Math.min(50, Number(e.target.value))) : undefined)} />
                  </div>
                </div>
              )}
              <p className="text-[11px] text-muted-foreground mt-1">Leave empty to skip. Needs a JSON request body? Use the raw-JSON mode above to set <code>race_condition_body</code> directly.</p>
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">Testing window</h4>
            <p className="text-[11px] text-muted-foreground mb-2">
              Every stage checks this before running and skips outside the window. Leave both empty for
              unrestricted (default).
            </p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <FieldLabel>Starts</FieldLabel>
                <input className={roeInputCls} type="datetime-local" value={toDatetimeLocal(draft.testing_window_start)}
                  onChange={(e) => set("testing_window_start", e.target.value ? new Date(e.target.value).toISOString() : undefined)} />
              </div>
              <div>
                <FieldLabel>Ends</FieldLabel>
                <input className={roeInputCls} type="datetime-local" value={toDatetimeLocal(draft.testing_window_end)}
                  onChange={(e) => set("testing_window_end", e.target.value ? new Date(e.target.value).toISOString() : undefined)} />
              </div>
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-foreground mb-2 uppercase tracking-wide">Nuclei tuning</h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <FieldLabel>Severities</FieldLabel>
                <div className="flex flex-wrap gap-1.5">
                  {NUCLEI_SEVERITIES.map((s) => (
                    <button key={s} onClick={() => toggleInList("nuclei_severities", s, NUCLEI_SEVERITIES)}
                      className={cn("text-[11px] px-2 py-1 rounded border capitalize transition-colors",
                        severities.includes(s) ? SEV_CLS[s] + " bg-surface-800 border-border" : "text-muted-foreground bg-surface-800 border-border opacity-50")}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <FieldLabel hint="Off by default -- dos/destructive templates can disrupt the target">Extra tags (off by default)</FieldLabel>
                <div className="flex flex-wrap gap-1.5">
                  {EXTRA_NUCLEI_TAGS.map((t) => (
                    <button key={t} onClick={() => setDraft((d) => {
                      const has = extraTags.includes(t);
                      const next = has ? extraTags.filter((v) => v !== t) : [...extraTags, t];
                      return omitEmpty(d, "allowed_extra_tags", next);
                    })}
                      className={cn("text-[11px] px-2 py-1 rounded border font-mono transition-colors",
                        extraTags.includes(t) ? "text-critical bg-critical/10 border-critical/30" : "text-muted-foreground bg-surface-800 border-border")}>
                      {t}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="mt-2 max-w-[200px]">
              <FieldLabel>Rate limit (req/s)</FieldLabel>
              <input className={roeInputCls} type="number" min={1} placeholder="100"
                value={draft.rate_limit_rps ?? ""} onChange={(e) => set("rate_limit_rps", e.target.value ? Number(e.target.value) : undefined)} />
            </div>
          </div>
        </div>
      )}

      <button onClick={handleSave} disabled={save.isPending}
        className="mt-4 flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-sm font-medium transition-colors">
        {save.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin" />} Save rules of engagement
      </button>
    </div>
  );
}

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

      <RulesOfEngagementEditor program={program} onChange={onChange} />
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

const TRIAGE_LABELS: Record<string, string> = {
  false_positive: "False positive", duplicate: "Duplicate", wont_fix: "Won't fix",
};

function FindingsTab({ programId }: { programId: string }) {
  const qc = useQueryClient();
  const [showDismissed, setShowDismissed] = useState(false);
  // Always fetch everything (including dismissed) and filter client-side --
  // fetching only when the "show dismissed" toggle is off would mean the
  // dismissed count itself is unknowable in that state (the server-filtered
  // response structurally never contains dismissed rows), which previously
  // showed a permanently-stuck "Dismissed 0" chip regardless of how many
  // were actually dismissed.
  const { data } = useQuery({
    queryKey: ["bounty-findings", programId],
    queryFn: () => bountyAPI.listFindings(programId, { page_size: 200, include_dismissed: true }).then((r) => r.data),
  });
  const allFindings: any[] = data?.items || [];
  const findings = showDismissed ? allFindings : allFindings.filter((f) => !f.triage_status);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | "confirmed" | "inconclusive">("all");
  const [sev, setSev] = useState<"all" | "critical" | "high" | "medium" | "low" | "info">("all");

  const triage = useMutation({
    mutationFn: ({ findingId, triageStatus }: { findingId: string; triageStatus: string | null }) =>
      bountyAPI.triageFinding(programId, findingId, triageStatus),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["bounty-findings", programId] });
      toast.success("Finding updated");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed"),
  });

  const confirmedCount = findings.filter((f) => f.status === "confirmed").length;
  const inconclusiveCount = findings.filter((f) => f.status === "inconclusive").length;
  const dismissedCount = allFindings.filter((f) => f.triage_status).length;

  const q = query.trim().toLowerCase();
  const filtered = findings.filter((f) =>
    (status === "all" || f.status === status) &&
    (sev === "all" || f.severity === sev) &&
    (!q || f.technique?.toLowerCase().includes(q) || f.evidence?.target_url?.toLowerCase().includes(q)),
  );

  if (allFindings.length === 0) {
    return <EmptyState icon={Bug} label="No findings yet. Run Vuln Scan or Exploit stages." />;
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput value={query} onChange={setQuery} placeholder="Search technique or URL…" />
        <FilterChip active={status === "all"} onClick={() => setStatus("all")}>All <span className="opacity-60 ml-0.5">{findings.length}</span></FilterChip>
        <FilterChip active={status === "confirmed"} onClick={() => setStatus("confirmed")}>Confirmed <span className="opacity-60 ml-0.5">{confirmedCount}</span></FilterChip>
        <FilterChip active={status === "inconclusive"} onClick={() => setStatus("inconclusive")}>Candidate <span className="opacity-60 ml-0.5">{inconclusiveCount}</span></FilterChip>
        <FilterChip active={showDismissed} onClick={() => setShowDismissed((v) => !v)}>
          Dismissed {showDismissed ? "shown" : "hidden"} <span className="opacity-60 ml-0.5">{dismissedCount}</span>
        </FilterChip>
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
          <div key={f.id} className={cn(
            "p-3 rounded-lg bg-surface-900 border border-border", LIFT, "hover:border-rose-500/25",
            f.triage_status && "opacity-50",
          )}>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", SEV_BAR_CLS[f.severity] || "bg-info")} />
              <span className="text-xs uppercase font-semibold text-muted-foreground">{f.module}</span>
              <span className={cn("text-xs font-semibold capitalize", SEV_CLS[f.severity] || "text-info")}>{f.severity}</span>
              <span className={cn("text-[11px] px-1.5 py-0.5 rounded border font-medium", STATUS_CLS[f.status] || STATUS_CLS.blocked)}>
                {f.status}
              </span>
              {f.occurrence_count > 1 && (
                <span className="text-[11px] text-muted-foreground" title={`First seen ${f.executed_at}, last seen ${f.last_seen_at}`}>
                  seen {f.occurrence_count}×
                </span>
              )}
              <span className="text-sm text-foreground font-mono flex-1 truncate">{f.technique}</span>
              <select
                value={f.triage_status || ""}
                onChange={(e) => triage.mutate({ findingId: f.id, triageStatus: e.target.value || null })}
                className="text-[11px] bg-surface-800 border border-border rounded px-1.5 py-1 text-muted-foreground flex-shrink-0"
                title="Triage status"
              >
                <option value="">Untriaged</option>
                <option value="false_positive">False positive</option>
                <option value="duplicate">Duplicate</option>
                <option value="wont_fix">Won&apos;t fix</option>
              </select>
            </div>
            {f.evidence?.target_url && (
              <p className="text-xs text-muted-foreground font-mono mt-1.5 truncate flex items-center gap-1.5">
                <ExternalLink className="w-3 h-3 flex-shrink-0 opacity-60" /> {f.evidence.target_url}
              </p>
            )}
            {f.triage_status && (
              <p className="text-[11px] text-amber-400 mt-1">Marked {TRIAGE_LABELS[f.triage_status] || f.triage_status}</p>
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
