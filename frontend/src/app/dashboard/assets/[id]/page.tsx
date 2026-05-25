"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft, Globe, Server, Shield, RefreshCw, AlertTriangle,
  Layers, Lock, Network, Activity, Eye, ExternalLink,
  MapPin, Clock, Cpu, ChevronRight, ChevronDown
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow, format } from "date-fns";
import { motion } from "framer-motion";
import { assetsAPI } from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/ui/SeverityBadge";
import { cn, formatRelative } from "@/lib/utils";

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;

  const [activeTab, setActiveTab] = useState<"overview" | "findings" | "screenshots" | "intel">("overview");

  const { data: asset, isLoading } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => assetsAPI.get(assetId).then(r => r.data),
    enabled: !!assetId,
  });

  const { data: findings } = useQuery({
    queryKey: ["asset-findings", assetId],
    queryFn: () => assetsAPI.getFindings(assetId).then(r => r.data),
    enabled: !!assetId && activeTab === "findings",
  });

  const { data: screenshots } = useQuery({
    queryKey: ["asset-screenshots", assetId],
    queryFn: () => assetsAPI.getScreenshots(assetId).then(r => r.data),
    enabled: !!assetId && activeTab === "screenshots",
  });

  const { data: intel } = useQuery({
    queryKey: ["asset-intel", assetId],
    queryFn: () => assetsAPI.getIntel(assetId).then(r => r.data),
    enabled: !!assetId && activeTab === "intel",
  });

  const sub = asset?.subdomain;
  const ip = asset?.ip;
  const ports = asset?.ports || [];

  const TABS: { id: "overview" | "findings" | "screenshots" | "intel"; label: string; count?: number }[] = [
    { id: "overview", label: "Overview" },
    { id: "findings", label: "Findings", count: asset?.open_findings },
    { id: "screenshots", label: "Screenshots" },
    { id: "intel", label: "Threat Intel" },
  ];

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!asset) {
    return (
      <div className="p-6 text-center text-muted-foreground">
        Asset not found
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button onClick={() => router.push("/dashboard/assets")} className="p-2 rounded-lg hover:bg-surface-700 text-muted-foreground hover:text-foreground">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold text-foreground font-mono truncate">{asset.value}</h1>
            <StatusBadge status={asset.status} />
            {sub?.title && <span className="text-sm text-muted-foreground hidden sm:inline">— {sub.title}</span>}
          </div>
          <div className="flex items-center gap-3 mt-1 text-sm text-muted-foreground">
            <span className="capitalize">{asset.asset_type}</span>
            <span>·</span>
            <span>First seen {formatRelative(asset.first_seen)}</span>
            <span>·</span>
            <span>Last seen {formatRelative(asset.last_seen)}</span>
          </div>
        </div>
        {sub?.fqdn && (
          <a href={`https://${sub.fqdn}`} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <ExternalLink className="w-3.5 h-3.5" /> Open
          </a>
        )}
      </div>

      {/* Detail grid */}
      <div className="grid grid-cols-12 gap-4">
        {/* Main info */}
        <div className="col-span-12 lg:col-span-8 space-y-4">
          {/* Tabs */}
          <div className="flex border-b border-border">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  "px-4 py-2.5 text-sm font-medium border-b-2 transition-colors flex items-center gap-2",
                  activeTab === tab.id
                    ? "border-brand-400 text-brand-400"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                {tab.label}
                {tab.count != null && tab.count > 0 && (
                  <span className="text-xs bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded-full">
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Tab content */}
          {activeTab === "overview" && (
            <div className="space-y-4">
              {/* Subdomain detail */}
              {sub && (
                <div className="glass-card p-5 space-y-3">
                  <h2 className="text-sm font-semibold text-foreground">Subdomain Details</h2>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground">FQDN</p>
                      <p className="text-sm font-mono text-foreground">{sub.fqdn}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Root Domain</p>
                      <p className="text-sm font-mono text-foreground">{sub.root_domain}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">HTTP Status</p>
                      <p className={cn("text-sm font-mono font-bold",
                        sub.http_status && sub.http_status < 300 ? "text-emerald-400" :
                        sub.http_status && sub.http_status < 400 ? "text-yellow-400" : "text-muted-foreground"
                      )}>{sub.http_status || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">HTTPS Status</p>
                      <p className={cn("text-sm font-mono", sub.https_status ? "text-emerald-400" : "text-muted-foreground")}>
                        {sub.https_status || "—"}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Server</p>
                      <p className="text-sm text-foreground">{sub.server || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">CDN</p>
                      <p className="text-sm text-foreground">{sub.cdn_provider || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">WAF</p>
                      <p className="text-sm text-foreground">{sub.waf_detected || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Last Probed</p>
                      <p className="text-sm text-foreground">{sub.last_probed ? formatRelative(sub.last_probed) : "—"}</p>
                    </div>
                  </div>

                  {/* IP addresses */}
                  {sub.ip_addresses?.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">IP Addresses</p>
                      <div className="flex flex-wrap gap-1.5">
                        {sub.ip_addresses.map((ipAddr: string) => (
                          <span key={ipAddr} className="text-xs font-mono bg-surface-800 text-muted-foreground px-2 py-1 rounded">
                            {ipAddr}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Security headers */}
                  {sub.security_headers && Object.keys(sub.security_headers).length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Security Headers</p>
                      <div className="space-y-1">
                        {Object.entries(sub.security_headers).map(([k, v]) => (
                          <div key={k} className="flex items-center gap-2 text-xs">
                            <span className="font-mono text-muted-foreground">{k}:</span>
                            <span className="text-foreground">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* DNS records */}
                  {sub.dns_records && Object.keys(sub.dns_records).length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">DNS Records</p>
                      <div className="space-y-1">
                        {Object.entries(sub.dns_records).map(([k, v]) => (
                          <div key={k} className="flex items-start gap-2 text-xs">
                            <span className="font-mono text-muted-foreground uppercase">{k}:</span>
                            <span className="text-foreground break-all">{String(Array.isArray(v) ? v.join(", ") : v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* IP detail */}
              {ip && (
                <div className="glass-card p-5 space-y-3">
                  <h2 className="text-sm font-semibold text-foreground">IP Details</h2>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground">IP</p>
                      <p className="text-sm font-mono text-foreground">{ip.ip}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Version</p>
                      <p className="text-sm text-foreground">IPv{ip.version}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">ASN</p>
                      <p className="text-sm text-foreground">{ip.asn ? `AS${ip.asn}` : "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Organization</p>
                      <p className="text-sm text-foreground">{ip.asn_org || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Country</p>
                      <p className="text-sm text-foreground">{ip.country_name || ip.country_code || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">City</p>
                      <p className="text-sm text-foreground">{ip.city || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">ISP</p>
                      <p className="text-sm text-foreground">{ip.isp || "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Cloud</p>
                      <p className="text-sm text-foreground">{ip.cloud_provider ? `${ip.cloud_provider} ${ip.cloud_region || ""}` : "—"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Open Ports</p>
                      <p className="text-sm text-foreground">{ip.open_ports_count || 0}</p>
                    </div>
                  </div>

                  {/* Flags */}
                  <div className="flex flex-wrap gap-2">
                    {ip.is_cdn && <span className="text-xs bg-brand-500/10 text-brand-400 border border-brand-500/20 px-2 py-0.5 rounded">CDN</span>}
                    {ip.is_hosting && <span className="text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded">Hosting</span>}
                    {ip.is_vpn && <span className="text-xs bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 px-2 py-0.5 rounded">VPN</span>}
                    {ip.is_tor && <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded">Tor Exit Node</span>}
                  </div>

                  {ports.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Open Ports</p>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                        {ports.map((port: any) => (
                          <div key={`${port.protocol}-${port.port}`} className="rounded-lg border border-surface-700 bg-surface-800/60 px-3 py-2">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-sm font-mono font-semibold text-foreground">{port.port}</span>
                              <span className="text-[10px] uppercase text-emerald-400">{port.state}</span>
                            </div>
                            <p className="text-xs text-muted-foreground truncate">{port.service || port.protocol}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Technologies */}
              <div className="glass-card p-5">
                <h2 className="text-sm font-semibold text-foreground mb-3">Technologies</h2>
                {sub?.technologies?.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {sub.technologies.map((t: string) => (
                      <span key={t} className="text-xs bg-surface-700 text-muted-foreground px-2.5 py-1 rounded-lg border border-surface-600">{t}</span>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No technologies detected</p>
                )}
              </div>
            </div>
          )}

          {activeTab === "findings" && (
            <div className="space-y-3">
              {findings?.items?.length > 0 ? (
                findings.items.map((f: any) => (
                  <div key={f.id} className="glass-card p-4 flex items-start gap-3 cursor-pointer hover:bg-surface-700/30 transition-colors">
                    <SeverityBadge severity={f.severity} compact />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground">{f.title}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{f.category?.replace(/_/g, " ")}</p>
                    </div>
                    <span className="text-xs text-muted-foreground">{formatRelative(f.first_seen)}</span>
                  </div>
                ))
              ) : (
                <div className="glass-card p-8 text-center text-muted-foreground">
                  <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No findings for this asset</p>
                </div>
              )}
            </div>
          )}

          {activeTab === "screenshots" && (
            <div className="grid grid-cols-2 gap-4">
              {screenshots?.items?.length > 0 ? (
                screenshots.items.map((s: any) => (
                  <div key={s.id} className="glass-card overflow-hidden">
                    <img
                      src={s.url}
                      alt={`Screenshot of ${asset.value}`}
                      className="w-full h-48 object-cover"
                    />
                    <div className="p-3 flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{formatRelative(s.captured_at)}</span>
                      <a href={s.url} target="_blank" rel="noopener noreferrer"
                        className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-1">
                        <Eye className="w-3 h-3" /> Full size
                      </a>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-2 glass-card p-8 text-center text-muted-foreground">
                  <Eye className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No screenshots available</p>
                </div>
              )}
            </div>
          )}

          {activeTab === "intel" && (
            <div className="space-y-3">
              {intel?.items?.length > 0 ? (
                intel.items.map((i: any) => (
                  <div key={i.id} className="glass-card p-4 flex items-start gap-3">
                    <div className={cn(
                      "w-2 h-2 rounded-full mt-1.5 flex-shrink-0",
                      i.is_malicious ? "bg-red-400" : "bg-muted-foreground"
                    )} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-foreground">{i.source}</span>
                        {i.is_malicious && <span className="text-xs bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded font-medium">Malicious</span>}
                      </div>
                      {i.tags && <div className="flex flex-wrap gap-1 mt-1">
                        {i.tags.map((tag: string) => (
                          <span key={tag} className="text-xs bg-surface-700 text-muted-foreground px-1.5 py-0.5 rounded">{tag}</span>
                        ))}
                      </div>}
                      <p className="text-xs text-muted-foreground mt-1">{formatRelative(i.enriched_at)}</p>
                    </div>
                    {i.risk_score != null && (
                      <span className={cn(
                        "text-sm font-bold tabular-nums",
                        i.risk_score >= 70 ? "text-red-400" : i.risk_score >= 40 ? "text-yellow-400" : "text-muted-foreground"
                      )}>
                        {i.risk_score}
                      </span>
                    )}
                  </div>
                ))
              ) : (
                <div className="glass-card p-8 text-center text-muted-foreground">
                  <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No threat intelligence data</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="col-span-12 lg:col-span-4 space-y-4">
          {/* Quick info */}
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Quick Info</h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Type</span>
                <span className="text-xs text-foreground capitalize">{asset.asset_type}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Status</span>
                <StatusBadge status={asset.status} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Open Findings</span>
                <span className={cn("text-xs font-bold", asset.open_findings > 0 ? "text-red-400" : "text-emerald-400")}>
                  {asset.open_findings || 0}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Criticality</span>
                <span className="text-xs text-foreground">{asset.criticality}/5</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Discovery</span>
                <span className="text-xs text-foreground capitalize">{asset.discovery_method || "—"}</span>
              </div>
            </div>
          </div>

          {/* Ports */}
          {ip?.open_ports_count > 0 && (
            <div className="glass-card p-4 space-y-3">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Open Ports</h3>
              <p className="text-sm text-foreground font-bold tabular-nums">{ip.open_ports_count} ports</p>
              {ports.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {ports.slice(0, 12).map((port: any) => (
                    <span key={`${port.protocol}-${port.port}`} className="text-xs font-mono bg-surface-800 text-muted-foreground border border-surface-700 px-2 py-1 rounded">
                      {port.port}/{port.protocol}
                    </span>
                  ))}
                  {ports.length > 12 && (
                    <span className="text-xs text-muted-foreground px-2 py-1">+{ports.length - 12}</span>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TLS Info */}
          {sub?.tls_expiry && (
            <div className="glass-card p-4 space-y-2">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">TLS/SSL</h3>
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">Expiry</span>
                  <span className={cn(
                    "text-xs font-mono font-bold",
                    new Date(sub.tls_expiry) < new Date() ? "text-red-400" :
                    new Date(sub.tls_expiry) < new Date(Date.now() + 30 * 86400000) ? "text-yellow-400" : "text-emerald-400"
                  )}>
                    {formatRelative(sub.tls_expiry)}
                  </span>
                </div>
                {sub.tls_issuer && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Issuer</span>
                    <span className="text-xs text-foreground truncate max-w-[140px]">{sub.tls_issuer}</span>
                  </div>
                )}
                {sub.tls_version && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Version</span>
                    <span className="text-xs text-foreground">{sub.tls_version}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tags */}
          {asset.tags?.length > 0 && (
            <div className="glass-card p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Tags</h3>
              <div className="flex flex-wrap gap-1.5">
                {asset.tags.map((tag: string) => (
                  <span key={tag} className="text-xs bg-surface-700 text-muted-foreground px-2 py-0.5 rounded">{tag}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
