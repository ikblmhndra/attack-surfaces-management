"use client";

import { useState, useEffect } from "react";
import { Network, RefreshCw, Filter, ZoomIn, Download, Info } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { AssetRelationshipGraph } from "@/components/charts/AssetRelationshipGraph";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn } from "@/lib/utils";

export default function AttackSurfacePage() {
  const { activeOrg } = useWorkspaceStore();
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [layout, setLayout] = useState<"cose" | "breadthfirst" | "circle">("cose");
  const [nodeTypes, setNodeTypes] = useState({
    domain: true, ip: true, port: true, tech: true, finding: true,
  });

  // Fetch organization graph data
  const { data: graphData, isLoading, refetch } = useQuery({
    queryKey: ["attack-surface-graph", activeOrg?.id],
    queryFn: async () => {
      if (!activeOrg?.id) return { nodes: [], edges: [] };

      // Fetch top assets and their relationships. IP-type assets are fetched
      // separately and merged in: they're touched far less often than
      // subdomains (a port scan runs once, DNS/HTTP rechecks on subdomains run
      // constantly), so sorted by last_seen desc they consistently rank
      // outside the general page_size=200 window and would otherwise never
      // appear on the graph at all — not a rendering bug, just never fetched.
      const [assetsResp, ipsResp, findingsResp] = await Promise.all([
        apiClient.get(`/assets?org_id=${activeOrg.id}&page_size=200&status=active`),
        apiClient.get(`/assets?org_id=${activeOrg.id}&asset_type=ip&page_size=200&status=active`),
        apiClient.get(`/findings?org_id=${activeOrg.id}&status=open&page_size=100`),
      ]);

      const assetsById = new Map<string, any>();
      for (const asset of [...(assetsResp.data.items || []), ...(ipsResp.data.items || [])]) {
        assetsById.set(asset.id, asset);
      }
      const assets = Array.from(assetsById.values());
      const findings = findingsResp.data.items || [];

      // Build graph nodes
      const nodes: any[] = [];
      const edges: any[] = [];
      const seen = new Set<string>();

      // Org node
      nodes.push({
        id: `org-${activeOrg.id}`,
        label: activeOrg.name,
        type: "org",
        data: { criticality: 5 },
      });

      // Asset nodes
      for (const asset of assets) {
        if (seen.has(asset.id)) continue;
        seen.add(asset.id);

        const nodeType = asset.asset_type === "ip" ? "ip" : "domain";
        nodes.push({
          id: asset.id,
          label: asset.value,
          type: nodeType,
          data: {
            criticality: asset.criticality,
            http_status: asset.subdomain?.http_status,
            open_findings: asset.open_findings || 0,
          },
        });

        // Connect to org
        edges.push({
          id: `org-${asset.id}`,
          source: `org-${activeOrg.id}`,
          target: asset.id,
          label: "contains",
          type: "contains",
        });

        // Technology nodes
        if (asset.subdomain?.technologies) {
          for (const tech of asset.subdomain.technologies.slice(0, 3)) {
            const techId = `tech-${tech}-${asset.id}`;
            if (!seen.has(techId)) {
              seen.add(techId);
              nodes.push({ id: techId, label: tech, type: "tech", data: {} });
            }
            edges.push({
              id: `tech-edge-${techId}`,
              source: asset.id,
              target: techId,
              label: "runs",
              type: "runs",
            });
          }
        }
      }

      // Finding nodes (critical/high only to avoid clutter)
      for (const finding of findings.filter((f: any) => ["critical", "high"].includes(f.severity))) {
        const findingId = `finding-${finding.id}`;
        nodes.push({
          id: findingId,
          label: finding.title.slice(0, 30),
          type: "finding",
          severity: finding.severity,
          data: {
            severity: finding.severity,
            category: finding.category,
            cve_ids: finding.cve_ids,
          },
        });

        // Connect finding to asset
        if (finding.asset_id) {
          edges.push({
            id: `finding-edge-${findingId}`,
            source: finding.asset_id,
            target: findingId,
            label: "has",
            type: "has_finding",
          });
        }
      }

      return { nodes, edges };
    },
    enabled: !!activeOrg?.id,
    staleTime: 120_000,
  });

  // Filter nodes by type
  const filteredGraph = graphData ? {
    nodes: graphData.nodes.filter((n: any) => {
      if (n.type === "org") return true;
      return nodeTypes[n.type as keyof typeof nodeTypes] !== false;
    }),
    edges: graphData.edges.filter((e: any) => {
      const sourceOk = graphData.nodes.some((n: any) => n.id === e.source && (n.type === "org" || nodeTypes[n.type as keyof typeof nodeTypes] !== false));
      const targetOk = graphData.nodes.some((n: any) => n.id === e.target && (n.type === "org" || nodeTypes[n.type as keyof typeof nodeTypes] !== false));
      return sourceOk && targetOk;
    }),
  } : { nodes: [], edges: [] };

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Attack Surface Map</h1>
          <p className="text-sm text-muted-foreground">
            {filteredGraph.nodes.length} nodes · {filteredGraph.edges.length} relationships
            {activeOrg ? ` · ${activeOrg.name}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-700 hover:bg-surface-600 border border-surface-600 text-foreground">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Controls row */}
      <div className="flex items-center gap-4 flex-wrap">
        {/* Node type toggles */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Show:</span>
          {Object.entries(nodeTypes).map(([type, enabled]) => (
            <button
              key={type}
              onClick={() => setNodeTypes(prev => ({ ...prev, [type]: !prev[type as keyof typeof prev] }))}
              className={cn(
                "px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors capitalize",
                enabled
                  ? "bg-brand-500/20 border-brand-500/30 text-brand-400"
                  : "bg-surface-800 border-surface-600 text-muted-foreground"
              )}
            >
              {type}
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-border" />

        {/* Layout selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Layout:</span>
          {(["cose", "breadthfirst", "circle"] as const).map(l => (
            <button
              key={l}
              onClick={() => setLayout(l)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-xs border transition-colors capitalize",
                layout === l
                  ? "bg-surface-600 border-surface-500 text-foreground"
                  : "bg-surface-800 border-surface-700 text-muted-foreground"
              )}
            >
              {l}
            </button>
          ))}
        </div>
      </div>

      {/* Main graph + sidebar */}
      <div className="grid grid-cols-12 gap-4">
        {/* Graph */}
        <div className="col-span-12 lg:col-span-9">
          {isLoading ? (
            <div className="glass-card flex items-center justify-center h-[600px]">
              <div className="text-center">
                <div className="w-10 h-10 border-2 border-brand-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">Building attack surface graph...</p>
              </div>
            </div>
          ) : !activeOrg ? (
            <div className="glass-card flex items-center justify-center h-[600px]">
              <div className="text-center text-muted-foreground">
                <Network className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p className="text-sm">Select an organization to view its attack surface</p>
              </div>
            </div>
          ) : (
            <AssetRelationshipGraph
              nodes={filteredGraph.nodes}
              edges={filteredGraph.edges}
              height={600}
              onNodeClick={setSelectedNode}
            />
          )}
        </div>

        {/* Sidebar: selected node details + stats */}
        <div className="col-span-12 lg:col-span-3 space-y-4">
          {/* Graph stats */}
          <div className="glass-card p-4">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
              Graph Summary
            </h3>
            {[
              { label: "Organizations", count: filteredGraph.nodes.filter((n: any) => n.type === "org").length, color: "#0ea5e9" },
              { label: "Domains", count: filteredGraph.nodes.filter((n: any) => n.type === "domain").length, color: "#8b5cf6" },
              { label: "IPs", count: filteredGraph.nodes.filter((n: any) => n.type === "ip").length, color: "#059669" },
              { label: "Technologies", count: filteredGraph.nodes.filter((n: any) => n.type === "tech").length, color: "#0284c7" },
              { label: "Findings", count: filteredGraph.nodes.filter((n: any) => n.type === "finding").length, color: "#ef4444" },
              { label: "Relationships", count: filteredGraph.edges.length, color: "#475569" },
            ].map(stat => (
              <div key={stat.label} className="flex items-center justify-between py-1.5 border-b border-border/50 last:border-0">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: stat.color }} />
                  <span className="text-xs text-muted-foreground">{stat.label}</span>
                </div>
                <span className="text-xs font-bold text-foreground tabular-nums">{stat.count}</span>
              </div>
            ))}
          </div>

          {/* Selected node detail */}
          {selectedNode && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-card p-4"
            >
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
                Selected Node
              </h3>
              <div className="space-y-2">
                <p className="text-xs font-mono text-brand-400 break-all">{selectedNode.label}</p>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Type:</span>
                  <span className="text-xs text-foreground capitalize">{selectedNode.type}</span>
                </div>
                {selectedNode.severity && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Severity:</span>
                    <SeverityBadge severity={selectedNode.severity} compact />
                  </div>
                )}
                {selectedNode.data && Object.entries(selectedNode.data).map(([k, v]) => (
                  <div key={k} className="flex items-start gap-2">
                    <span className="text-xs text-muted-foreground capitalize flex-shrink-0">{k.replace(/_/g, " ")}:</span>
                    <span className="text-xs text-foreground break-all">{String(v)}</span>
                  </div>
                ))}
                <button
                  onClick={() => window.open(`/dashboard/assets/${selectedNode.id}`, "_blank")}
                  className="w-full mt-2 py-1.5 text-xs rounded-lg bg-brand-600/20 hover:bg-brand-600/30 border border-brand-500/30 text-brand-400 transition-colors"
                >
                  View Asset Details →
                </button>
              </div>
            </motion.div>
          )}

          {/* Instructions */}
          {!selectedNode && (
            <div className="glass-card p-4">
              <div className="flex items-start gap-2 text-xs text-muted-foreground">
                <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-brand-400" />
                <div>
                  <p className="font-medium text-foreground mb-1">Graph Navigation</p>
                  <ul className="space-y-1">
                    <li>• Click a node to select it</li>
                    <li>• Click background to clear</li>
                    <li>• Scroll to zoom in/out</li>
                    <li>• Drag to pan the view</li>
                    <li>• Use controls top-right to fit/export</li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
