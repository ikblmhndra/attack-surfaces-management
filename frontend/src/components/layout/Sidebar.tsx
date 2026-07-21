"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield, LayoutDashboard, Building2, Globe, AlertTriangle,
  BarChart3, Bell, Settings, Key, FileText, Search,
  ChevronLeft, ChevronRight, Scan, Network,
  Eye, Layers, Lock, User, Crosshair, ArrowLeftRight
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { useWorkspaceStore } from "@/store/workspace";

interface NavItem {
  label: string;
  href: string;
  icon: typeof LayoutDashboard;
  exact?: boolean;
  badge?: boolean;
}

// Two fully separate products, two fully separate nav trees -- a workspace
// only ever sees the one (or two, via the switcher below) it's entitled to.
// See Workspace.enabled_products / RequireProduct (backend) and
// dashboard/layout.tsx (which picks the variant from the current route).
const ASM_NAV_ITEMS: NavItem[] = [
  { label: "Overview", href: "/dashboard", icon: LayoutDashboard, exact: true },
  { label: "Organizations", href: "/dashboard/organizations", icon: Building2 },
  { label: "Assets", href: "/dashboard/assets", icon: Layers },
  { label: "Attack Surface", href: "/dashboard/attack-surface", icon: Globe },
  { label: "Findings", href: "/dashboard/findings", icon: AlertTriangle },
  { label: "Risk Scores", href: "/dashboard/risks", icon: BarChart3 },
  { label: "Scans", href: "/dashboard/scans", icon: Scan },
  { label: "Screenshots", href: "/dashboard/screenshots", icon: Eye },
  { label: "DNS Intel", href: "/dashboard/dns", icon: Network },
  { label: "TLS/SSL", href: "/dashboard/tls", icon: Lock },
  { label: "Network Intel", href: "/dashboard/intel", icon: Shield },
  { label: "Reports", href: "/dashboard/reports", icon: FileText },
];

const BOUNTY_NAV_ITEMS: NavItem[] = [
  { label: "Programs", href: "/dashboard/bounty", icon: Crosshair, exact: true },
];

const BOTTOM_ITEMS: NavItem[] = [
  { label: "Notifications", href: "/dashboard/notifications", icon: Bell, badge: true },
  { label: "Search", href: "/dashboard/search", icon: Search },
  { label: "API Keys", href: "/dashboard/settings/api-keys", icon: Key },
  { label: "Settings", href: "/dashboard/settings", icon: Settings },
];

const BRANDING = {
  asm: { title: "ASM Platform", subtitle: "Security Posture", icon: Shield },
  bounty: { title: "Bug Bounty", subtitle: "Active Testing", icon: Crosshair },
} as const;

export type SidebarVariant = keyof typeof BRANDING;

interface SidebarProps {
  variant?: SidebarVariant;
}

export function Sidebar({ variant = "asm" }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, sidebarCollapsed, setSidebarCollapsed, enabledProducts } = useWorkspaceStore();
  const collapsed = sidebarCollapsed;
  const isBounty = variant === "bounty";
  const navItems = isBounty ? BOUNTY_NAV_ITEMS : ASM_NAV_ITEMS;
  const allItems = [...navItems, ...BOTTOM_ITEMS];
  const branding = BRANDING[variant];
  const canSwitch = enabledProducts.includes("asm") && enabledProducts.includes("bounty");

  // Prefix-matching on its own lights up both a parent route and its child
  // at once (e.g. "Settings" -> /dashboard/settings and "API Keys" ->
  // /dashboard/settings/api-keys both match on /dashboard/settings/api-keys).
  // Only the single most specific (longest href) match should be active.
  const isActive = (href: string, exact = false) => {
    if (exact) return pathname === href;
    if (pathname !== href && !pathname.startsWith(`${href}/`)) return false;
    const matches = allItems.filter(
      (item) => !item.exact && (pathname === item.href || pathname.startsWith(`${item.href}/`))
    );
    const mostSpecific = matches.reduce((a, b) => (b.href.length > a.href.length ? b : a));
    return href === mostSpecific.href;
  };

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 224 }}
      transition={{ duration: 0.2, ease: "easeInOut" }}
      className="fixed left-0 top-0 bottom-0 z-40 flex flex-col bg-surface-900 border-r border-border overflow-hidden"
    >
      {/* Logo */}
      <div className="flex items-center h-14 px-4 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className={cn(
            "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
            isBounty ? "bg-rose-600" : "bg-brand-600",
          )}>
            <branding.icon className="w-4 h-4 text-white" />
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                transition={{ duration: 0.15 }}
                className="min-w-0"
              >
                <span className="text-sm font-bold text-foreground tracking-tight block">
                  {branding.title}
                </span>
                <span className="text-xs text-muted-foreground block">{branding.subtitle}</span>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Product switcher -- only shown when a workspace is entitled to
          both products, since that's the only case there's anywhere to
          switch to. */}
      {canSwitch && (
        <div className="px-2 pt-2 flex-shrink-0">
          <button
            onClick={() => router.push(isBounty ? "/dashboard" : "/dashboard/bounty")}
            title={collapsed ? `Switch to ${isBounty ? "ASM" : "Bug Bounty"}` : undefined}
            className={cn(
              "w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-xs font-medium",
              "border border-border bg-surface-800 hover:bg-surface-700/70 text-muted-foreground hover:text-foreground transition-colors",
              collapsed && "justify-center px-2"
            )}
          >
            <ArrowLeftRight className="w-3.5 h-3.5 flex-shrink-0" />
            {!collapsed && <span className="truncate">Switch to {isBounty ? "ASM" : "Bug Bounty"}</span>}
          </button>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2 space-y-0.5">
        {navItems.map((item) => {
          const active = isActive(item.href, item.exact);
          return (
            <Link key={item.href} href={item.href}>
              <motion.div
                whileHover={{ x: 2 }}
                className={cn(
                  "nav-item",
                  active && "active",
                  active && isBounty && "!bg-rose-500/10 !text-rose-300",
                  collapsed && "justify-center px-2"
                )}
                title={collapsed ? item.label : undefined}
              >
                <item.icon className={cn(
                  "w-4 h-4 flex-shrink-0",
                  active
                    ? (isBounty ? "text-rose-400" : "text-brand-400")
                    : (isBounty ? "text-rose-400/70" : "text-muted-foreground")
                )} />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.1 }}
                      className="truncate"
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </motion.div>
            </Link>
          );
        })}

        {/* Divider */}
        <div className="my-2 border-t border-border/50" />

        {BOTTOM_ITEMS.map((item) => {
          const active = isActive(item.href);
          return (
            <Link key={item.href} href={item.href}>
              <motion.div
                whileHover={{ x: 2 }}
                className={cn(
                  "nav-item",
                  active && "active",
                  collapsed && "justify-center px-2"
                )}
                title={collapsed ? item.label : undefined}
              >
                <item.icon className={cn(
                  "w-4 h-4 flex-shrink-0",
                  active ? "text-brand-400" : "text-muted-foreground"
                )} />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.1 }}
                      className="truncate"
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </motion.div>
            </Link>
          );
        })}
      </nav>

      {/* User + collapse */}
      <div className="border-t border-border p-2 flex-shrink-0">
        {/* User profile */}
        <div className={cn(
          "flex items-center gap-2 px-2 py-2 rounded-lg mb-1",
          collapsed && "justify-center"
        )}>
          <div className="w-7 h-7 rounded-full bg-brand-600/30 flex items-center justify-center flex-shrink-0">
            <User className="w-3.5 h-3.5 text-brand-400" />
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex-1 min-w-0"
              >
                <p className="text-xs font-medium text-foreground truncate">
                  {user?.full_name || "User"}
                </p>
                <p className="text-xs text-muted-foreground capitalize truncate">
                  {user?.role || "viewer"}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Collapse button */}
        <button
          onClick={() => setSidebarCollapsed(!collapsed)}
          className={cn(
            "w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs text-muted-foreground",
            "hover:text-foreground hover:bg-surface-700/50 transition-colors",
            collapsed && "justify-center"
          )}
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <>
              <ChevronLeft className="w-4 h-4" />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>
    </motion.aside>
  );
}
