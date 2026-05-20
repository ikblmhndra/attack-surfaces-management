"use client";

import { useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import {
  Search as SearchIcon, RefreshCw, Globe, AlertTriangle, Layers,
  ExternalLink, ChevronRight, X
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
import { searchAPI } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn, formatRelative } from "@/lib/utils";

export default function SearchPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { activeOrg } = useWorkspaceStore();
  const initialQuery = searchParams.get("q") || "";
  const [query, setQuery] = useState(initialQuery);
  const [submittedQuery, setSubmittedQuery] = useState(initialQuery);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["search", submittedQuery],
    queryFn: () => searchAPI.search(submittedQuery).then(r => r.data),
    enabled: submittedQuery.length > 0,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      setSubmittedQuery(query.trim());
      router.replace(`/dashboard/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  const assets = data?.assets || [];
  const findings = data?.findings || [];
  const totalAssets = data?.assets_total || 0;
  const totalFindings = data?.findings_total || 0;

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Search</h1>
        <p className="text-sm text-muted-foreground">
          Search across assets, findings, and more
        </p>
      </div>

      {/* Search bar */}
      <form onSubmit={handleSearch} className="relative max-w-2xl">
        <SearchIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search assets, findings, domains, IPs..."
          className="w-full pl-12 pr-12 py-3 bg-surface-800 border border-border rounded-xl text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
        {query && (
          <button
            type="button"
            onClick={() => { setQuery(""); setSubmittedQuery(""); }}
            className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </form>

      {/* Results */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : submittedQuery ? (
        <div className="space-y-6">
          {/* Summary */}
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <span>Results for &ldquo;{submittedQuery}&rdquo;</span>
            <span>·</span>
            <span>{totalAssets} assets</span>
            <span>·</span>
            <span>{totalFindings} findings</span>
          </div>

          {/* Assets */}
          {assets.length > 0 && (
            <div>
              <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4 text-brand-400" />
                Assets ({totalAssets})
              </h2>
              <div className="space-y-2">
                {assets.map((asset: any) => (
                  <div
                    key={asset.id}
                    className="glass-card p-4 flex items-center gap-3 cursor-pointer hover:bg-surface-700/30 transition-colors"
                    onClick={() => router.push(`/dashboard/assets/${asset.id}`)}
                  >
                    <Globe className="w-4 h-4 text-brand-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-foreground">{asset.value}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs text-muted-foreground capitalize">{asset.asset_type}</span>
                        {asset.subdomain?.title && (
                          <span className="text-xs text-muted-foreground">· {asset.subdomain.title}</span>
                        )}
                        <span className="text-xs text-muted-foreground">· {formatRelative(asset.last_seen)}</span>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Findings */}
          {findings.length > 0 && (
            <div>
              <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Findings ({totalFindings})
              </h2>
              <div className="space-y-2">
                {findings.map((f: any) => (
                  <div
                    key={f.id}
                    className="glass-card p-4 flex items-start gap-3 cursor-pointer hover:bg-surface-700/30 transition-colors"
                    onClick={() => router.push(`/dashboard/findings?id=${f.id}`)}
                  >
                    <SeverityBadge severity={f.severity} compact className="mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground">{f.title}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        {f.affected_url && (
                          <span className="text-xs font-mono text-muted-foreground truncate max-w-[200px]">{f.affected_url}</span>
                        )}
                        <span className="text-xs text-muted-foreground">· {f.category?.replace(/_/g, " ")}</span>
                        <span className="text-xs text-muted-foreground">· {formatRelative(f.first_seen)}</span>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0 mt-0.5" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No results */}
          {assets.length === 0 && findings.length === 0 && (
            <div className="glass-card flex flex-col items-center justify-center h-48 text-muted-foreground">
              <SearchIcon className="w-10 h-10 mb-3 opacity-30" />
              <p className="text-sm">No results found for &ldquo;{submittedQuery}&rdquo;</p>
              <p className="text-xs mt-1">Try a different search term</p>
            </div>
          )}
        </div>
      ) : (
        <div className="glass-card flex flex-col items-center justify-center h-64 text-muted-foreground">
          <SearchIcon className="w-12 h-12 mb-3 opacity-20" />
          <p className="text-sm">Enter a search query to find assets and findings</p>
          <p className="text-xs mt-1">Search by domain, IP, URL, CVE, or finding title</p>
        </div>
      )}
    </div>
  );
}
