"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, Download } from "lucide-react";
import { cn } from "@/lib/utils";

interface GraphNode {
  id: string;
  label: string;
  type: "org" | "domain" | "ip" | "port" | "tech" | "finding";
  severity?: string;
  data?: Record<string, any>;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: string;
}

interface AssetGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  className?: string;
  onNodeClick?: (node: GraphNode) => void;
  height?: number;
}

// Node type → visual config
const NODE_STYLES: Record<string, {
  bg: string; border: string; size: number; shape: string; icon: string;
}> = {
  org:     { bg: "#0ea5e9", border: "#38bdf8", size: 60, shape: "ellipse",   icon: "🏢" },
  domain:  { bg: "#8b5cf6", border: "#a78bfa", size: 44, shape: "roundrectangle", icon: "🌐" },
  ip:      { bg: "#059669", border: "#34d399", size: 38, shape: "ellipse",   icon: "🖥️" },
  port:    { bg: "#d97706", border: "#fbbf24", size: 28, shape: "diamond",   icon: "⚡" },
  tech:    { bg: "#0284c7", border: "#38bdf8", size: 30, shape: "octagon",   icon: "⚙️" },
  finding: { bg: "#dc2626", border: "#f87171", size: 32, shape: "star",      icon: "⚠️" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#3b82f6",
  info:     "#6b7280",
};

export function AssetRelationshipGraph({
  nodes,
  edges,
  className,
  onNodeClick,
  height = 600,
}: AssetGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
  const [isReady, setIsReady] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState(1);

  const initCytoscape = useCallback(async () => {
    if (!containerRef.current || !nodes.length) return;

    // Dynamically import cytoscape
    const cytoscape = (await import("cytoscape")).default;

    // Build elements
    const elements = [
      ...nodes.map((n) => {
        const style = NODE_STYLES[n.type] || NODE_STYLES.domain;
        const borderColor = n.severity
          ? SEVERITY_COLORS[n.severity] || style.border
          : style.border;

        return {
          data: {
            id: n.id,
            label: n.label.length > 24 ? n.label.slice(0, 21) + "…" : n.label,
            fullLabel: n.label,
            type: n.type,
            severity: n.severity,
            ...n.data,
          },
          classes: [n.type, n.severity].filter(Boolean).join(" "),
        };
      }),
      ...edges.map((e) => ({
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label || "",
          type: e.type || "relates_to",
        },
      })),
    ];

    // Destroy existing instance
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        // Base node style
        {
          selector: "node",
          style: {
            "background-color": (el: any) => {
              const type = el.data("type");
              const sev = el.data("severity");
              if (sev) return SEVERITY_COLORS[sev] || NODE_STYLES[type]?.bg || "#334155";
              return NODE_STYLES[type]?.bg || "#334155";
            },
            "border-color": (el: any) => NODE_STYLES[el.data("type")]?.border || "#475569",
            "border-width": 2,
            "border-opacity": 0.8,
            width: (el: any) => NODE_STYLES[el.data("type")]?.size || 36,
            height: (el: any) => NODE_STYLES[el.data("type")]?.size || 36,
            shape: (el: any) => NODE_STYLES[el.data("type")]?.shape || "ellipse",
            label: "data(label)",
            "font-size": 10,
            "font-family": "var(--font-geist-mono, monospace)",
            color: "#94a3b8",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 4,
            "text-outline-width": 2,
            "text-outline-color": "#0a0f1a",
            "min-zoomed-font-size": 8,
            "overlay-opacity": 0,
            "transition-property": "background-color, border-color, width, height",
            "transition-duration": "0.15s",
          } as any,
        },

        // Selected node
        {
          selector: "node:selected",
          style: {
            "border-width": 3,
            "border-color": "#0ea5e9",
            "box-shadow": "0 0 0 4px rgba(14,165,233,0.3)",
          } as any,
        },

        // Hover
        {
          selector: "node.hover",
          style: {
            "border-width": 3,
            "border-color": "#38bdf8",
          } as any,
        },

        // Edge style
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#1e293b",
            "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.8,
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 9,
            color: "#475569",
            "text-outline-width": 2,
            "text-outline-color": "#0a0f1a",
            "text-margin-y": -6,
            "min-zoomed-font-size": 8,
            opacity: 0.7,
          } as any,
        },

        // Edge hover
        {
          selector: "edge.hover",
          style: { "line-color": "#334155", opacity: 1 } as any,
        },

        // Finding nodes
        {
          selector: "node.finding",
          style: { "background-color": "#7f1d1d", "border-color": "#ef4444" } as any,
        },
        {
          selector: "node.finding.critical",
          style: { "background-color": "#dc2626" } as any,
        },

        // Highlighted path
        {
          selector: ".highlighted",
          style: {
            "line-color": "#0ea5e9",
            "target-arrow-color": "#0ea5e9",
            opacity: 1,
            width: 2.5,
          } as any,
        },
        {
          selector: ".dimmed",
          style: { opacity: 0.2 } as any,
        },
      ],

      layout: {
        name: "cose",
        animate: true,
        animationDuration: 800,
        randomize: false,
        nodeRepulsion: () => 8000,
        nodeOverlap: 10,
        idealEdgeLength: () => 80,
        edgeElasticity: () => 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0,
        fit: true,
        padding: 40,
      } as any,

      wheelSensitivity: 0.3,
      minZoom: 0.1,
      maxZoom: 5,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    // ── Events ──────────────────────────────────────────────
    cy.on("tap", "node", (evt: any) => {
      const nodeData = evt.target.data();
      const matchedNode = nodes.find((n) => n.id === nodeData.id);
      if (matchedNode) {
        setSelectedNode(matchedNode);
        onNodeClick?.(matchedNode);

        // Highlight connected edges and neighbors
        cy.elements().addClass("dimmed");
        evt.target.removeClass("dimmed").addClass("highlighted");
        evt.target.connectedEdges().removeClass("dimmed").addClass("highlighted");
        evt.target.neighborhood("node").removeClass("dimmed");
      }
    });

    cy.on("tap", (evt: any) => {
      if (evt.target === cy) {
        // Click on background: clear selection
        setSelectedNode(null);
        cy.elements().removeClass("dimmed highlighted");
      }
    });

    cy.on("mouseover", "node", (evt: any) => {
      evt.target.addClass("hover");
      containerRef.current!.style.cursor = "pointer";
    });

    cy.on("mouseout", "node", (evt: any) => {
      evt.target.removeClass("hover");
      containerRef.current!.style.cursor = "default";
    });

    cy.on("zoom", () => {
      setZoom(cy.zoom());
    });

    cyRef.current = cy;
    setIsReady(true);
  }, [nodes, edges, onNodeClick]);

  useEffect(() => {
    initCytoscape();
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [initCytoscape]);

  // ── Controls ──────────────────────────────────────────────
  const handleZoomIn  = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit     = () => cyRef.current?.fit(undefined, 40);
  const handleReset   = () => { cyRef.current?.fit(undefined, 40); cyRef.current?.zoom(1); };

  const handleExport = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({ scale: 2, full: true, bg: "#0a0f1a" });
    const link = document.createElement("a");
    link.href = png;
    link.download = "attack-surface-graph.png";
    link.click();
  };

  return (
    <div className={cn("relative rounded-xl overflow-hidden bg-surface-950 border border-border", className)}>
      {/* Controls */}
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1.5">
        {[
          { icon: ZoomIn,     title: "Zoom in",        action: handleZoomIn  },
          { icon: ZoomOut,    title: "Zoom out",       action: handleZoomOut },
          { icon: Maximize2,  title: "Fit to screen",  action: handleFit     },
          { icon: RotateCcw,  title: "Reset view",     action: handleReset   },
          { icon: Download,   title: "Export PNG",     action: handleExport  },
        ].map(({ icon: Icon, title, action }) => (
          <button
            key={title}
            title={title}
            onClick={action}
            className="w-8 h-8 flex items-center justify-center rounded-lg bg-surface-800/90 backdrop-blur border border-border text-muted-foreground hover:text-foreground hover:bg-surface-700 transition-colors"
          >
            <Icon className="w-3.5 h-3.5" />
          </button>
        ))}
      </div>

      {/* Legend */}
      <div className="absolute top-3 left-3 z-10 glass-card p-2.5 text-xs space-y-1.5">
        {Object.entries(NODE_STYLES).map(([type, cfg]) => (
          <div key={type} className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-full flex-shrink-0"
              style={{ backgroundColor: cfg.bg }}
            />
            <span className="text-muted-foreground capitalize">{type}</span>
          </div>
        ))}
      </div>

      {/* Zoom indicator */}
      <div className="absolute bottom-3 right-3 z-10 px-2 py-1 rounded bg-surface-800/80 text-xs text-muted-foreground font-mono">
        {Math.round(zoom * 100)}%
      </div>

      {/* Node info panel */}
      {selectedNode && (
        <div className="absolute bottom-3 left-3 z-10 glass-card p-3 w-64 text-xs">
          <div className="flex items-center gap-2 mb-2">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: NODE_STYLES[selectedNode.type]?.bg }}
            />
            <span className="font-medium text-foreground capitalize">{selectedNode.type}</span>
          </div>
          <p className="text-muted-foreground font-mono truncate">{selectedNode.label}</p>
          {selectedNode.severity && (
            <p className="mt-1" style={{ color: SEVERITY_COLORS[selectedNode.severity] }}>
              {selectedNode.severity.toUpperCase()}
            </p>
          )}
          {selectedNode.data && Object.keys(selectedNode.data).slice(0, 4).map((k) => (
            <div key={k} className="flex gap-2 mt-0.5">
              <span className="text-muted-foreground shrink-0">{k}:</span>
              <span className="text-foreground truncate">{String(selectedNode.data![k])}</span>
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {!nodes.length && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center text-muted-foreground">
            <p className="text-sm">No graph data available</p>
            <p className="text-xs mt-1">Run a scan to populate the attack surface graph</p>
          </div>
        </div>
      )}

      {/* Graph container */}
      <div
        ref={containerRef}
        style={{ height, width: "100%" }}
        className="bg-transparent"
      />
    </div>
  );
}
