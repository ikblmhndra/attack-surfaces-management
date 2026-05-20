"use client";

import { useState } from "react";
import {
  Network, RefreshCw, Search, AlertTriangle, Globe,
  ChevronLeft, ChevronRight, Server
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

export default function DnsPage() {
  const { activeOrg } = useWorkspaceStore();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 25;

  const params = new URLSearchParams({
    page: String(page),
    page_size: String(PAGE_SIZE),
  });
  if (activeOrg?.id) params.set("org_id", activeOrg.id);
  if (search) params.set("search", search);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["dns-intel", params.toString()],
    queryFn: () => apiClient.get(`/assets?${params}&expand=dns`).then(r => r.data),
    enabled: !!activeOrg?.id,
    refetchInterval: 60_000,
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">DNS Intelligence</h1>
          <p className="text-sm text-muted-foreground">
            DNS records and resolutions · {activeOrg?.name || "All organizations"}
          </p>
        </div>
        <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      {!activeOrg ? (
        <div className="glass-card flex items-center justify-center h-64">
          <div className="text-center text-muted-foreground">
            <Network className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select an organization to view DNS data</p>
          </div>
        </div>
      ) : (
        <>
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search domain or IP..."
              className="w-full pl-9 pr-4 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>

          <div className="glass-card overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center h-48">
                <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : data?.items?.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full data-table">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Type</th>
                      <th>IP Addresses</th>
                      <th>Records</th>
                      <th>Last Resolved</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((asset: any) => {
                      const sub = asset.subdomain || {};
                      const dns = sub.dns_records || {};
                      const ips = sub.ip_addresses || [];
                      return (
                        <tr key={asset.id}>
                          <td>
                            <div className="flex items-center gap-2">
                              <Globe className="w-4 h-4 text-brand-400" />
                              <span className="text-sm font-mono text-foreground">{asset.value}</span>
                            </div>
                          </td>
                          <td>
                            <span className="text-xs text-muted-foreground capitalize">{asset.asset_type}</span>
                          </td>
                          <td>
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                              {ips.slice(0, 3).map((ip: string) => (
                                <span key={ip} className="text-xs font-mono bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded">{ip}</span>
                              ))}
                              {ips.length > 3 && (
                                <span className="text-xs text-muted-foreground">+{ips.length - 3}</span>
                              )}
                            </div>
                          </td>
                          <td>
                            <div className="flex flex-wrap gap-1">
                              {Object.keys(dns).length > 0 ? (
                                Object.entries(dns).map(([type, records]: [string, any]) => (
                                  <span key={type} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded font-mono">
                                    {type}: {Array.isArray(records) ? records.length : 1}
                                  </span>
                                ))
                              ) : (
                                <span className="text-xs text-muted-foreground">—</span>
                              )}
                            </div>
                          </td>
                          <td>
                            <span className="text-xs text-muted-foreground">
                              {asset.last_seen ? formatDistanceToNow(new Date(asset.last_seen), { addSuffix: true }) : "—"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Network className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">No DNS data found</p>
              </div>
            )}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">Page {page} of {totalPages}</p>
              <div className="flex items-center gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50">
                  <ChevronLeft className="w-3 h-3" /> Previous
                </button>
                <button onClick={() => setPage(p => p + 1)} disabled={page >= totalPages}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground disabled:opacity-50">
                  Next <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
