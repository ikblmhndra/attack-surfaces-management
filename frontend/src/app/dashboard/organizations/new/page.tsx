"use client";

import { useState } from "react";
import {
  Building2, ArrowLeft, Save, RefreshCw, Plus, X
} from "lucide-react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import Link from "next/link";
import { organizationsAPI } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useWorkspaceStore } from "@/store/workspace";

export default function NewOrganizationPage() {
  const router = useRouter();
  const { canWrite } = useWorkspaceStore();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [domains, setDomains] = useState<string[]>([""]);
  const [rootDomains, setRootDomains] = useState<string[]>([""]);
  const [industry, setIndustry] = useState("");
  const [criticality, setCriticality] = useState(3);

  const qc = useQueryClient();

  const createMutation = useMutation({
    mutationFn: () =>
      organizationsAPI.create({
        name,
        description: description || undefined,
        domains: domains.filter(Boolean),
        root_domains: rootDomains.filter(Boolean),
        industry: industry || undefined,
        criticality,
      }),
    onSuccess: (res) => {
      toast.success("Organization created");
      qc.invalidateQueries({ queryKey: ["organizations"] });
      router.push(`/dashboard/organizations/${res.data.id}`);
    },
    onError: () => toast.error("Failed to create organization"),
  });

  const addDomain = () => setDomains(prev => [...prev, ""]);
  const removeDomain = (i: number) => setDomains(prev => prev.filter((_, idx) => idx !== i));
  const updateDomain = (i: number, v: string) => {
    const next = [...domains];
    next[i] = v;
    setDomains(next);
  };

  const addRootDomain = () => setRootDomains(prev => [...prev, ""]);
  const removeRootDomain = (i: number) => setRootDomains(prev => prev.filter((_, idx) => idx !== i));
  const updateRootDomain = (i: number, v: string) => {
    const next = [...rootDomains];
    next[i] = v;
    setRootDomains(next);
  };

  const valid = name.trim().length > 0 && domains.some(d => d.trim());

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          href="/dashboard/organizations"
          className="p-2 rounded-lg hover:bg-surface-700 text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <h1 className="text-xl font-semibold text-foreground">New Organization</h1>
          <p className="text-sm text-muted-foreground">
            Add a new organization to monitor
          </p>
        </div>
      </div>

      {!canWrite() ? (
        <div className="glass-card p-6 text-center text-muted-foreground">
          You don&apos;t have permission to create organizations.
        </div>
      ) : (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Basic info */}
          <div className="glass-card p-5 space-y-4">
            <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Building2 className="w-4 h-4 text-brand-400" />
              Basic Information
            </h2>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Name *</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g., Acme Corp"
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Description</label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="Optional description..."
                rows={2}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500 resize-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-muted-foreground mb-1">Industry</label>
                <select
                  value={industry}
                  onChange={e => setIndustry(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  <option value="">Select...</option>
                  <option value="technology">Technology</option>
                  <option value="finance">Finance</option>
                  <option value="healthcare">Healthcare</option>
                  <option value="education">Education</option>
                  <option value="government">Government</option>
                  <option value="ecommerce">E-commerce</option>
                  <option value="media">Media</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-muted-foreground mb-1">Criticality (1-5)</label>
                <div className="flex items-center gap-2">
                  {[1, 2, 3, 4, 5].map(v => (
                    <button
                      key={v}
                      onClick={() => setCriticality(v)}
                      className={cn(
                        "w-9 h-9 rounded-lg text-sm font-medium border transition-colors",
                        criticality >= v
                          ? "bg-orange-500/20 border-orange-500/30 text-orange-400"
                          : "bg-surface-800 border-surface-600 text-muted-foreground"
                      )}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Domains */}
          <div className="glass-card p-5 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">Domains</h2>
            <p className="text-xs text-muted-foreground">
              Add domains to monitor for this organization
            </p>
            {domains.map((d, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  value={d}
                  onChange={e => updateDomain(i, e.target.value)}
                  placeholder="example.com"
                  className="flex-1 px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
                {domains.length > 1 && (
                  <button onClick={() => removeDomain(i)} className="p-2 rounded hover:bg-surface-700 text-muted-foreground hover:text-red-400">
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            ))}
            <button onClick={addDomain} className="flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300">
              <Plus className="w-3.5 h-3.5" /> Add domain
            </button>
          </div>

          {/* Root domains */}
          <div className="glass-card p-5 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">Root Domains</h2>
            <p className="text-xs text-muted-foreground">
              Top-level domains for scope definition
            </p>
            {rootDomains.map((d, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  value={d}
                  onChange={e => updateRootDomain(i, e.target.value)}
                  placeholder="acme.com"
                  className="flex-1 px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
                {rootDomains.length > 1 && (
                  <button onClick={() => removeRootDomain(i)} className="p-2 rounded hover:bg-surface-700 text-muted-foreground hover:text-red-400">
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            ))}
            <button onClick={addRootDomain} className="flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300">
              <Plus className="w-3.5 h-3.5" /> Add root domain
            </button>
          </div>

          {/* Submit */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => createMutation.mutate()}
              disabled={createMutation.isPending || !valid}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
            >
              {createMutation.isPending ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              Create Organization
            </button>
            <Link href="/dashboard/organizations" className="text-sm text-muted-foreground hover:text-foreground">
              Cancel
            </Link>
          </div>
        </motion.div>
      )}
    </div>
  );
}

