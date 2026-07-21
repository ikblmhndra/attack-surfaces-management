"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Crosshair, Plus, ShieldCheck, PauseCircle, XCircle, ChevronRight, Target, Loader2,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { bountyAPI } from "@/lib/api";
import { cn } from "@/lib/utils";

type Platform = "hackerone" | "bugcrowd" | "independent";
type Status = "active" | "paused" | "closed";

interface Program {
  id: string;
  name: string;
  platform: Platform;
  status: Status;
  scope_rules: any[];
  target_count: number | null;
  created_at: string;
}

const STATUS_META: Record<Status, { label: string; cls: string; icon: typeof ShieldCheck }> = {
  active: { label: "Active", cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30", icon: ShieldCheck },
  paused: { label: "Paused", cls: "text-amber-400 bg-amber-500/10 border-amber-500/30", icon: PauseCircle },
  closed: { label: "Closed", cls: "text-muted-foreground bg-surface-700/40 border-border", icon: XCircle },
};

const PLATFORM_LABEL: Record<Platform, string> = {
  hackerone: "HackerOne",
  bugcrowd: "Bugcrowd",
  independent: "Independent",
};

export default function BountyProgramsPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["bounty-programs"],
    queryFn: () => bountyAPI.listPrograms({ page_size: 100 }).then((r) => r.data),
  });

  const programs: Program[] = data?.items || [];

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center flex-shrink-0">
            <Crosshair className="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-foreground tracking-tight">Bug Bounty</h1>
            <p className="text-sm text-muted-foreground mt-0.5 max-w-2xl">
              Authorized active testing for bug bounty engagements — a separate pipeline from ASM
              monitoring. Nothing runs until a program is <span className="text-foreground">active</span>,
              and every stage is confined to explicitly-entered scope.
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-sm font-medium transition-colors flex-shrink-0"
        >
          <Plus className="w-4 h-4" /> New Program
        </button>
      </div>

      {/* Programs */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />
        </div>
      ) : programs.length === 0 ? (
        <div className="text-center py-20 border border-dashed border-border rounded-xl">
          <Target className="w-8 h-8 text-muted-foreground/50 mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">No bug bounty programs yet.</p>
          <button
            onClick={() => setShowCreate(true)}
            className="mt-3 text-sm text-rose-400 hover:text-rose-300 font-medium"
          >
            Create your first program
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {programs.map((p, i) => {
            const meta = STATUS_META[p.status];
            const StatusIcon = meta.icon;
            return (
              <motion.div
                key={p.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.03 }}
              >
                <Link href={`/dashboard/bounty/${p.id}`}>
                  <div className="group flex items-center gap-4 p-4 rounded-xl bg-surface-900 border border-border hover:border-rose-500/40 transition-colors">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-foreground truncate">{p.name}</span>
                        <span className={cn("text-[11px] px-1.5 py-0.5 rounded border font-medium flex items-center gap-1", meta.cls)}>
                          <StatusIcon className="w-3 h-3" /> {meta.label}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                        <span>{PLATFORM_LABEL[p.platform]}</span>
                        <span>·</span>
                        <span>{p.target_count ?? 0} target{(p.target_count ?? 0) === 1 ? "" : "s"}</span>
                        <span>·</span>
                        <span>{(p.scope_rules?.length ?? 0)} scope rule{(p.scope_rules?.length ?? 0) === 1 ? "" : "s"}</span>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-rose-400 transition-colors" />
                  </div>
                </Link>
              </motion.div>
            );
          })}
        </div>
      )}

      {showCreate && (
        <CreateProgramModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            qc.invalidateQueries({ queryKey: ["bounty-programs"] });
            setShowCreate(false);
          }}
        />
      )}
    </div>
  );
}

function CreateProgramModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState<Platform>("hackerone");
  const [scopePattern, setScopePattern] = useState("");

  const createMutation = useMutation({
    mutationFn: () =>
      bountyAPI.createProgram({
        name,
        platform,
        scope_rules: scopePattern.trim()
          ? [{ pattern: scopePattern.trim(), type: "domain", in_scope: true }]
          : [],
      }),
    onSuccess: () => {
      toast.success("Program created (paused). Add scope + targets, then activate it.");
      onCreated();
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to create program"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-md bg-surface-900 border border-border rounded-xl p-5 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold text-foreground">New Bug Bounty Program</h2>
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground">Program name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Public Program"
              className="mt-1 w-full bg-surface-800 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-rose-500/50"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Platform</label>
            <select
              value={platform}
              onChange={(e) => setPlatform(e.target.value as Platform)}
              className="mt-1 w-full bg-surface-800 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-rose-500/50"
            >
              <option value="hackerone">HackerOne</option>
              <option value="bugcrowd">Bugcrowd</option>
              <option value="independent">Independent</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Initial in-scope pattern (optional)</label>
            <input
              value={scopePattern}
              onChange={(e) => setScopePattern(e.target.value)}
              placeholder="*.example.com"
              className="mt-1 w-full bg-surface-800 border border-border rounded-lg px-3 py-2 text-sm text-foreground font-mono focus:outline-none focus:border-rose-500/50"
            />
            <p className="text-[11px] text-muted-foreground mt-1">
              You can refine scope rules (and add out-of-scope exclusions) after creating the program.
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="px-3 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground">
            Cancel
          </button>
          <button
            onClick={() => createMutation.mutate()}
            disabled={!name.trim() || createMutation.isPending}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
          >
            {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Create
          </button>
        </div>
      </motion.div>
    </div>
  );
}
