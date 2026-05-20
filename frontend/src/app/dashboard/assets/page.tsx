"use client";

import { useState, useMemo } from "react";
import {
  Globe, Server, Network, Shield, Search, RefreshCw,
  Download, Filter, ChevronDown, ExternalLink, Eye,
  Layers, Cpu, Lock, Clock
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { StatusBadge } from "@/components/ui/SeverityBadge";
import { cn, formatNumber, formatRelative } from "@/lib/utils";

const ASSET_TYPE_CONFIG = {
  subdomain: { icon: Globe,   color: "#8b5cf6", label: "Subdomains" },
  ip:        { icon: Server,  color: "#059669", label: "IP Addresses" },
  cidr:      { icon: Network, color: "#0284c7", label: "CIDR Ranges" },
  url:       { icon: Globe,   color: "#d97706", label: "URLs" },
};

export default function AssetsPage() {
  const { activeOrg } = useWorkspaceStore();

  const [typeFilter, setTypeFilter]   = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("active");
  const [search, setSearch]           = useState("");
  const [page, setPage]               = useState(1);
  const [selected, setSelected]       = useState<any>(null);
  const PAGE_SIZE = 50;

  const params = useMemo(() => {
    const p = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (activeOrg?.id) p.set("org_id", activeOrg.id);
    if (typeFilter)    p.set("asset_type", typeFilter);
    if (statusFilter)  p.set("status", statusFilter);
    if (search)        p.set("search", search);
    return p.toString();
  }, [page, typeFilter, statusFilter, search, activeOrg?.id]);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["assets", params],
    queryFn: () => apiClient.get(`/assets?${params}`).then(r => r.data),
    refetchInterval: 60_000,
  });

  const { data: statsData } = useQuery({
    queryKey: ["assets-stats", activeOrg?.id],
    queryFn: () => apiClient.get(`/assets/stats/by-type?${activeOrg?.id ? `org_id=${activeOrg.id}` : ""}`).then(r => r.data),
  });

  const typeDistribution = statsData?.distribution || [];

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Asset Inventory</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total?.toLocaleString() ?? 0} assets · {activeOrg?.name || "All organizations"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <Download className="w-3 h-3" /> Export
          </button>
        </div>
      </div>

      {/* Type distribution cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {typeDistribution.map((t: any) => {
          const cfg = ASSET_TYPE_CONFIG[t.type as keyof typeof ASSET_TYPE_CONFIG];
          if (!cfg) return null;
          const Icon = cfg.icon;
          const isActive = typeFilter === t.type;
          return (
            <motion.button
              key={t.type}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => setTypeFilter(isActive ? "" : t.type)}
              className={cn(
                "glass-card p-4 text-left transition-all",
                isActive && "ring-1",
              )}
              style={isActive ? { "--tw-ring-color": cfg.color } as any : {}}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${cfg.color}20` }}>
                  <Icon className="w-4 h-4" style={{ color: cfg.color }} />
                </div>
                <span className="text-2xl font-bold tabular-nums" style={{ color: cfg.color }}>
                  {formatNumber(t.count)}
                </span>
              </div>
              <p className="text-xs font-medium text-foreground">{cfg.label}</p>
              <div className="mt-2 h-1 bg-surface-700 rounded-full overflow-hidden">
                <div className="h-full rounded-full" style={{
                  width: `${data?.total ? (t.count / data.total) * 100 : 0}%`,
                  backgroundColor: cfg.color,
                  opacity: 0.7,
                }} />
              </div>
            </motion.button>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search by domain, IP, URL..."
            className="pl-9 pr-3 py-1.5 text-sm bg-surface-800 border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-brand-500 w-64"
          />
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 text-sm bg-surface-800 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-brand-500">
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="">All statuses</option>
        </select>
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1); }}
          className="px-3 py-1.5 text-sm bg-surface-800 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-brand-500">
          <option value="">All types</option>
          <option value="subdomain">Subdomains</option>
          <option value="ip">IP Addresses</option>
          <option value="cidr">CIDR</option>
        </select>
      </div>

      {/* Asset table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full data-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>Status</th>
                <th>Technologies</th>
                <th>HTTP</th>
                <th>TLS Expiry</th>
                <th>Findings</th>
                <th>Last Seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 8 }).map((_, j) => (
                      <td key={j}><div className="skeleton h-4 rounded" style={{ width: `${50 + Math.random() * 40}%` }} /></td>
                    ))}
                  </tr>
                ))
              ) : data?.items?.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-16 text-muted-foreground">
                    <Layers className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No assets found. Run a scan to discover assets.</p>
                  </td>
                </tr>
              ) : (
                data?.items?.map((asset: any) => <AssetRow key={asset.id} asset={asset} onClick={setSelected} />)
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-xs text-muted-foreground">
              Page {page} of {data.pages} · {data.total.toLocaleString()} total
            </span>
            <div className="flex items-center gap-1.5">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-2 py-1 text-xs rounded bg-surface-700 hover:bg-surface-600 disabled:opacity-40 text-foreground">← Prev</button>
              <button onClick={() => setPage(p => Math.min(data.pages, p + 1))} disabled={page === data.pages}
                className="px-2 py-1 text-xs rounded bg-surface-700 hover:bg-surface-600 disabled:opacity-40 text-foreground">Next →</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function AssetRow({ asset, onClick }: { asset: any; onClick: (a: any) => void }) {
  const sub = asset.subdomain;
  const ip  = asset.ip;
  const cfg = ASSET_TYPE_CONFIG[asset.asset_type as keyof typeof ASSET_TYPE_CONFIG];
  const Icon = cfg?.icon || Globe;

  // TLS expiry color
  const tls = sub?.tls_expiry;
  let tlsColor = "text-muted-foreground";
  let tlsLabel = "—";
  if (tls) {
    const days = Math.ceil((new Date(tls).getTime() - Date.now()) / 86400000);
    tlsLabel = `${days}d`;
    tlsColor = days <= 7 ? "text-red-400" : days <= 30 ? "text-yellow-400" : "text-emerald-400";
  }

  return (
    <tr className="group cursor-pointer hover:bg-surface-700/30 transition-colors" onClick={() => onClick(asset)}>
      <td>
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ backgroundColor: `${cfg?.color || "#6b7280"}15` }}>
            <Icon className="w-3.5 h-3.5" style={{ color: cfg?.color || "#6b7280" }} />
          </div>
          <div>
            <p className="text-sm font-mono text-foreground truncate max-w-[280px]">{asset.value}</p>
            {sub?.title && <p className="text-xs text-muted-foreground truncate max-w-[280px]">{sub.title}</p>}
            {ip?.country_name && <p className="text-xs text-muted-foreground">{ip.country_name} · {ip.isp}</p>}
          </div>
        </div>
      </td>
      <td>
        <span className="text-xs capitalize text-muted-foreground">{asset.asset_type}</span>
      </td>
      <td><StatusBadge status={asset.status} /></td>
      <td>
        <div className="flex flex-wrap gap-1 max-w-[180px]">
          {(sub?.technologies || []).slice(0, 3).map((t: string) => (
            <span key={t} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded truncate max-w-[80px]">{t}</span>
          ))}
          {(sub?.technologies || []).length > 3 && (
            <span className="text-xs text-muted-foreground">+{sub.technologies.length - 3}</span>
          )}
        </div>
      </td>
      <td>
        {sub?.http_status ? (
          <span className={cn("text-xs font-mono font-bold",
            sub.http_status < 300 ? "text-emerald-400" :
            sub.http_status < 400 ? "text-yellow-400" : "text-red-400"
          )}>{sub.http_status}</span>
        ) : ip?.open_ports_count ? (
          <span className="text-xs text-muted-foreground">{ip.open_ports_count} ports</span>
        ) : <span className="text-xs text-muted-foreground">—</span>}
      </td>
      <td>
        {tls ? (
          <span className={cn("text-xs font-mono flex items-center gap-1", tlsColor)}>
            <Lock className="w-3 h-3" />{tlsLabel}
          </span>
        ) : <span className="text-xs text-muted-foreground">—</span>}
      </td>
      <td>
        {asset.open_findings > 0 ? (
          <span className="text-xs font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded">
            {asset.open_findings}
          </span>
        ) : <span className="text-xs text-emerald-400">✓ Clean</span>}
      </td>
      <td>
        <span className="text-xs text-muted-foreground">
          {asset.last_seen ? formatDistanceToNow(new Date(asset.last_seen), { addSuffix: true }) : "—"}
        </span>
      </td>
      <td>
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button onClick={e => { e.stopPropagation(); window.open(`/dashboard/assets/${asset.id}`, "_blank"); }}
            className="p-1 rounded hover:bg-surface-600 text-muted-foreground hover:text-foreground">
            <Eye className="w-3.5 h-3.5" />
          </button>
          {sub?.fqdn && (
            <a href={`https://${sub.fqdn}`} target="_blank" rel="noopener noreferrer"
              onClick={e => e.stopPropagation()}
              className="p-1 rounded hover:bg-surface-600 text-muted-foreground hover:text-foreground">
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
      </td>
    </tr>
  );
}
