# Graph Report - frontend  (2026-07-21)

## Corpus Check
- 50 files · ~48,561 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 481 nodes · 837 edges · 59 communities (14 shown, 45 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 3 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `83bd1ecf`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- api.ts
- cn
- SeverityBadge.tsx
- index.ts
- devDependencies
- utils.ts
- compilerOptions
- page.tsx
- page.tsx
- NetworkClusters.tsx
- dependencies
- WSClient
- AssetRelationshipGraph.tsx
- GroupedFindingRow.tsx
- .eslintrc.json
- class-variance-authority
- clsx
- cytoscape
- d3
- date-fns
- framer-motion
- geist
- @hookform/resolvers
- lucide-react
- mapbox-gl
- next.config.js
- next-env.d.ts
- @radix-ui/react-alert-dialog
- @radix-ui/react-avatar
- @radix-ui/react-collapsible
- @radix-ui/react-dialog
- @radix-ui/react-dropdown-menu
- @radix-ui/react-hover-card
- @radix-ui/react-progress
- @radix-ui/react-scroll-area
- @radix-ui/react-select
- @radix-ui/react-separator
- @radix-ui/react-slider
- @radix-ui/react-switch
- @radix-ui/react-tabs
- @radix-ui/react-tooltip
- react
- react-cytoscapejs
- react-dom
- react-hook-form
- react-hot-toast
- react-map-gl
- react-resizable-panels
- react-virtuoso
- recharts
- sonner
- tailwind-merge
- @tanstack/react-query
- @tanstack/react-table
- vaul
- zod
- zustand
- tailwind.config.ts

## God Nodes (most connected - your core abstractions)
1. `cn()` - 92 edges
2. `useWorkspaceStore` - 51 edges
3. `apiClient` - 21 edges
4. `compilerOptions` - 16 edges
5. `SeverityBadge()` - 15 edges
6. `WSClient` - 11 edges
7. `formatRelative()` - 10 edges
8. `scripts` - 7 edges
9. `tokenStorage` - 7 edges
10. `useRealtimeEvents()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `ValidationMetric()` --calls--> `cn()`  [EXTRACTED]
  src/app/dashboard/assets/[id]/page.tsx → src/lib/utils.ts
- `CreateRuleForm()` --calls--> `cn()`  [EXTRACTED]
  src/app/dashboard/notifications/page.tsx → src/lib/utils.ts
- `StatusBadge()` --calls--> `cn()`  [EXTRACTED]
  src/app/dashboard/scans/[id]/page.tsx → src/lib/utils.ts
- `SummaryCard()` --calls--> `cn()`  [EXTRACTED]
  src/app/dashboard/scans/[id]/page.tsx → src/lib/utils.ts
- `DiscoverySummary()` --calls--> `cn()`  [EXTRACTED]
  src/app/dashboard/scans/[id]/page.tsx → src/lib/utils.ts

## Import Cycles
- None detected.

## Communities (59 total, 45 thin omitted)

### Community 0 - "api.ts"
Cohesion: 0.06
Nodes (49): LoginForm, LoginPage(), loginSchema, PRODUCTS, RegisterForm, RegisterPage(), registerSchema, DnsPage() (+41 more)

### Community 1 - "cn"
Cohesion: 0.07
Nodes (40): ASSET_TYPE_CONFIG, AssetRow(), AssetsPage(), classifyHttpStatus(), HTTP_STATUS_CONFIG, HttpStatusBadge(), ValidationPill(), BountyProgramDetail() (+32 more)

### Community 2 - "SeverityBadge.tsx"
Cohesion: 0.07
Nodes (37): AssetDetailPage(), classifyHttpStatus(), HTTP_STATUS_CONFIG, HttpStatusBadge(), ValidationMetric(), columnHelper, FindingsPage(), SEVERITY_ORDER (+29 more)

### Community 3 - "index.ts"
Cohesion: 0.05
Nodes (41): APIKey, Asset, AssetType, AuditLog, CategoryScore, CategoryScores, ClusterHost, ClusterTopFinding (+33 more)

### Community 4 - "devDependencies"
Cohesion: 0.05
Nodes (37): autoprefixer, eslint, eslint-config-next, devDependencies, autoprefixer, eslint, eslint-config-next, postcss (+29 more)

### Community 5 - "utils.ts"
Cohesion: 0.06
Nodes (19): getScanProgressLabel(), OrganizationDetailPage(), ASM_NAV_ITEMS, BOTTOM_ITEMS, BOUNTY_NAV_ITEMS, BRANDING, NavItem, SidebarProps (+11 more)

### Community 6 - "compilerOptions"
Cohesion: 0.07
Nodes (26): dom, dom.iterable, esnext, next-env.d.ts, .next/types/**/*.ts, node_modules, **/*.ts, **/*.tsx (+18 more)

### Community 7 - "page.tsx"
Cohesion: 0.15
Nodes (18): CATEGORY_LABELS, DashboardPage(), fadeUp, getPhaseLabel(), getScanProgressLabel(), ScanActivityRow(), getActivePhaseKey(), getPhaseDetail() (+10 more)

### Community 8 - "page.tsx"
Cohesion: 0.13
Nodes (11): CHANGE_TONE_CLASS, ChangeSection(), DiscoverySummary(), formatDuration(), PhaseRow(), ScanDetailPage(), STATUS_CLASS, STATUS_ICON (+3 more)

### Community 9 - "NetworkClusters.tsx"
Cohesion: 0.20
Nodes (8): AttackSurfacePage(), ClusterRow(), NetworkClusters(), SEVERITY_ORDER, NetworkCluster, NetworkClustersResponse, Severity, StandaloneHost

### Community 10 - "dependencies"
Cohesion: 0.18
Nodes (11): axios, cmdk, next, dependencies, axios, cmdk, next, @radix-ui/react-popover (+3 more)

### Community 12 - "AssetRelationshipGraph.tsx"
Cohesion: 0.29
Nodes (7): ALWAYS_LABELED_TYPES, AssetGraphProps, AssetRelationshipGraph(), GraphEdge, GraphNode, NODE_STYLES, SEVERITY_COLORS

### Community 13 - "GroupedFindingRow.tsx"
Cohesion: 0.50
Nodes (3): CollapsibleContent(), Finding, FindingGroup

## Knowledge Gaps
- **213 isolated node(s):** `extends`, `next/core-web-vitals`, `nextConfig`, `name`, `version` (+208 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **45 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `cn()` connect `cn` to `api.ts`, `SeverityBadge.tsx`, `utils.ts`, `page.tsx`, `page.tsx`, `NetworkClusters.tsx`, `AssetRelationshipGraph.tsx`, `GroupedFindingRow.tsx`?**
  _High betweenness centrality (0.136) - this node is a cross-community bridge._
- **Why does `dependencies` connect `dependencies` to `devDependencies`, `class-variance-authority`, `clsx`, `cytoscape`, `d3`, `date-fns`, `framer-motion`, `geist`, `@hookform/resolvers`, `lucide-react`, `mapbox-gl`, `@radix-ui/react-alert-dialog`, `@radix-ui/react-avatar`, `@radix-ui/react-collapsible`, `@radix-ui/react-dialog`, `@radix-ui/react-dropdown-menu`, `@radix-ui/react-hover-card`, `@radix-ui/react-progress`, `@radix-ui/react-scroll-area`, `@radix-ui/react-select`, `@radix-ui/react-separator`, `@radix-ui/react-slider`, `@radix-ui/react-switch`, `@radix-ui/react-tabs`, `@radix-ui/react-tooltip`, `react`, `react-cytoscapejs`, `react-dom`, `react-hook-form`, `react-hot-toast`, `react-map-gl`, `react-resizable-panels`, `react-virtuoso`, `recharts`, `sonner`, `tailwind-merge`, `@tanstack/react-query`, `@tanstack/react-table`, `vaul`, `zod`, `zustand`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Why does `useWorkspaceStore` connect `api.ts` to `cn`, `SeverityBadge.tsx`, `utils.ts`, `page.tsx`, `NetworkClusters.tsx`?**
  _High betweenness centrality (0.030) - this node is a cross-community bridge._
- **What connects `extends`, `next/core-web-vitals`, `nextConfig` to the rest of the system?**
  _213 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `api.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.05859969558599695 - nodes in this community are weakly interconnected._
- **Should `cn` be split into smaller, more focused modules?**
  _Cohesion score 0.06666666666666667 - nodes in this community are weakly interconnected._
- **Should `SeverityBadge.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.06976744186046512 - nodes in this community are weakly interconnected._