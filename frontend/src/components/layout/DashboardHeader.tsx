"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Bell, Search, ChevronDown, Plus, Check,
  Building2, LogOut, Settings, User, Zap, Sun, Moon
} from "lucide-react";
import { motion } from "framer-motion";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/ui/SeverityBadge";

interface DashboardHeaderProps {
  variant?: "asm" | "bounty";
}

// Shared styling for the three dropdown panels below, so they read as one
// consistent menu system (Radix DropdownMenu.Content handles positioning/
// collision detection itself, replacing the old manual absolute+top-full
// classes and the window "click outside" listener).
const MENU_CONTENT_CLS =
  "z-50 bg-surface-800 border border-border rounded-xl shadow-xl overflow-hidden";

export function DashboardHeader({ variant = "asm" }: DashboardHeaderProps) {
  const router = useRouter();
  const qc = useQueryClient();
  const { user, activeOrg, setActiveOrg, logout, theme, toggleTheme } = useWorkspaceStore();
  const isBounty = variant === "bounty";

  const [orgDropdownOpen, setOrgDropdownOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Organizations are an ASM-only concept (/organizations is gated behind
  // RequireProduct("asm") server-side) -- skip the query entirely on a
  // bounty-only workspace rather than firing a request that can only 403.
  const { data: orgs } = useQuery({
    queryKey: ["organizations", "dropdown"],
    queryFn: () => apiClient.get("/organizations?page_size=50").then(r => r.data),
    enabled: !isBounty,
  });

  // Fetch unread notifications
  const { data: notifs, refetch: refetchNotifs } = useQuery({
    queryKey: ["notifications-unread"],
    queryFn: () => apiClient.get("/notifications?is_read=false&page_size=10").then(r => r.data),
    refetchInterval: 30_000,
  });

  const unreadCount = notifs?.total || 0;

  const handleOrgSelect = (org: any) => {
    setActiveOrg(org);
    qc.invalidateQueries();
  };

  const handleMarkAllRead = async () => {
    await apiClient.post("/notifications/mark-all-read");
    refetchNotifs();
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      router.push(`/dashboard/search?q=${encodeURIComponent(searchQuery)}`);
    }
  };

  return (
    <header className="h-14 border-b border-border bg-surface-900/80 backdrop-blur-sm flex items-center px-4 gap-3 sticky top-0 z-30">

      {/* Org selector -- an ASM-only concept, not shown on the Bug Bounty shell */}
      {!isBounty && (
      <DropdownMenu.Root open={orgDropdownOpen} onOpenChange={setOrgDropdownOpen}>
        <DropdownMenu.Trigger asChild>
          <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-surface-700 transition-colors text-sm max-w-[220px]">
            <div className="w-5 h-5 rounded bg-brand-600/30 flex items-center justify-center flex-shrink-0">
              <Building2 className="w-3 h-3 text-brand-400" />
            </div>
            <span className="text-foreground font-medium truncate">
              {activeOrg?.name || "Select Organization"}
            </span>
            <ChevronDown className={cn(
              "w-3.5 h-3.5 text-muted-foreground transition-transform flex-shrink-0",
              orgDropdownOpen && "rotate-180"
            )} />
          </button>
        </DropdownMenu.Trigger>

        <DropdownMenu.Portal>
          <DropdownMenu.Content
            asChild
            align="start"
            sideOffset={4}
          >
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ duration: 0.15 }}
              className={cn(MENU_CONTENT_CLS, "w-72")}
            >
              <div className="p-2 max-h-80 overflow-y-auto">
                <p className="text-xs text-muted-foreground px-2 py-1.5 font-medium uppercase tracking-wider">
                  Organizations
                </p>
                {orgs?.items?.map((org: any) => (
                  <DropdownMenu.Item
                    key={org.id}
                    onSelect={() => handleOrgSelect(org)}
                    className="w-full flex items-center gap-3 px-2 py-2 rounded-lg hover:bg-surface-700 focus:bg-surface-700 outline-none transition-colors text-left cursor-pointer"
                  >
                    <div className="w-8 h-8 rounded-lg bg-brand-600/20 flex items-center justify-center flex-shrink-0">
                      <Building2 className="w-4 h-4 text-brand-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate">{org.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {org.total_assets} assets · Score: {org.current_score?.overall ?? "—"}
                      </p>
                    </div>
                    {activeOrg?.id === org.id && (
                      <Check className="w-4 h-4 text-brand-400 flex-shrink-0" />
                    )}
                  </DropdownMenu.Item>
                ))}
              </div>
              <div className="border-t border-border p-2">
                <DropdownMenu.Item
                  onSelect={() => router.push("/dashboard/organizations/new")}
                  className="w-full flex items-center gap-2 px-2 py-2 rounded-lg hover:bg-surface-700 focus:bg-surface-700 outline-none text-sm text-brand-400 transition-colors cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  Add organization
                </DropdownMenu.Item>
              </div>
            </motion.div>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
      )}

      {/* Search */}
      <form onSubmit={handleSearch} className="flex-1 max-w-md">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" aria-hidden="true" />
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder={isBounty ? "Search..." : "Search assets, findings, CVEs..."}
            aria-label="Search"
            className="w-full pl-9 pr-4 py-1.5 text-sm bg-surface-800 border border-border rounded-lg
                       text-foreground placeholder:text-muted-foreground
                       focus:outline-none focus:ring-1 focus:ring-brand-500"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground hidden sm:block">
            ⌘K
          </kbd>
        </div>
      </form>

      {/* Right side controls */}
      <div className="flex items-center gap-2 ml-auto">

        {/* Quick scan -- ASM-only; guards against a stale persisted
            activeOrg surviving a switch to the Bug Bounty shell */}
        {!isBounty && activeOrg && (
          <button
            onClick={async () => {
              await apiClient.post(`/organizations/${activeOrg.id}/scans`, { scan_type: "quick" });
              qc.invalidateQueries({ queryKey: ["recent-scans"] });
            }}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-brand-600/20 hover:bg-brand-600/30 border border-brand-500/30 text-brand-400 text-xs font-medium transition-colors"
          >
            <Zap className="w-3.5 h-3.5" />
            Quick Scan
          </button>
        )}

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-surface-700 transition-colors text-muted-foreground hover:text-foreground"
        >
          {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* Notifications */}
        <DropdownMenu.Root open={notifOpen} onOpenChange={setNotifOpen}>
          <DropdownMenu.Trigger asChild>
            <button
              aria-label={unreadCount > 0 ? `Notifications, ${unreadCount} unread` : "Notifications"}
              className="relative w-8 h-8 flex items-center justify-center rounded-lg hover:bg-surface-700 transition-colors"
            >
              <Bell className="w-4 h-4 text-muted-foreground" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 rounded-full text-[10px] font-bold text-white flex items-center justify-center">
                  {unreadCount > 9 ? "9+" : unreadCount}
                </span>
              )}
            </button>
          </DropdownMenu.Trigger>

          <DropdownMenu.Portal>
            <DropdownMenu.Content
              asChild
              align="end"
              sideOffset={4}
            >
              <motion.div
                initial={{ opacity: 0, y: -8, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.15 }}
                className={cn(MENU_CONTENT_CLS, "w-96")}
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                  <h3 className="text-sm font-semibold text-foreground">Notifications</h3>
                  {unreadCount > 0 && (
                    <button
                      onClick={(e) => { e.preventDefault(); handleMarkAllRead(); }}
                      className="text-xs text-brand-400 hover:text-brand-300"
                    >
                      Mark all read
                    </button>
                  )}
                </div>

                <div className="max-h-80 overflow-y-auto">
                  {notifs?.items?.length > 0 ? (
                    notifs.items.map((n: any) => (
                      <div
                        key={n.id}
                        className={cn(
                          "flex items-start gap-3 px-4 py-3 hover:bg-surface-700/50 transition-colors",
                          !n.is_read && "bg-brand-500/5"
                        )}
                      >
                        <SeverityBadge severity={n.severity} compact className="mt-0.5 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-foreground truncate font-medium">{n.title}</p>
                          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{n.message}</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {formatDistanceToNow(new Date(n.created_at), { addSuffix: true })}
                          </p>
                        </div>
                        {!n.is_read && (
                          <span className="w-2 h-2 rounded-full bg-brand-400 flex-shrink-0 mt-1.5" />
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="flex items-center justify-center h-24 text-muted-foreground text-sm">
                      No unread notifications
                    </div>
                  )}
                </div>

                <div className="border-t border-border p-2">
                  <DropdownMenu.Item
                    onSelect={() => router.push("/dashboard/notifications")}
                    className="w-full text-center text-xs text-brand-400 hover:text-brand-300 py-1.5 outline-none cursor-pointer"
                  >
                    View all notifications →
                  </DropdownMenu.Item>
                </div>
              </motion.div>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>

        {/* User menu */}
        <DropdownMenu.Root open={userMenuOpen} onOpenChange={setUserMenuOpen}>
          <DropdownMenu.Trigger asChild>
            <button
              aria-label="User menu"
              className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-surface-700 transition-colors"
            >
              <div className="w-7 h-7 rounded-full bg-brand-600/30 flex items-center justify-center">
                <User className="w-3.5 h-3.5 text-brand-400" />
              </div>
              <ChevronDown className="w-3 h-3 text-muted-foreground" />
            </button>
          </DropdownMenu.Trigger>

          <DropdownMenu.Portal>
            <DropdownMenu.Content
              asChild
              align="end"
              sideOffset={4}
            >
              <motion.div
                initial={{ opacity: 0, y: -8, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.15 }}
                className={cn(MENU_CONTENT_CLS, "w-56 py-1")}
              >
                <div className="px-3 py-2 border-b border-border">
                  <p className="text-sm font-medium text-foreground truncate">{user?.full_name}</p>
                  <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                  <span className="text-xs bg-brand-500/10 text-brand-400 border border-brand-500/20 px-1.5 py-0.5 rounded mt-1 inline-block capitalize">
                    {user?.role}
                  </span>
                </div>
                {[
                  { label: "Profile Settings", icon: User, href: "/dashboard/settings/profile" },
                  { label: "API Keys", icon: Settings, href: "/dashboard/settings/api-keys" },
                ].map(item => (
                  <DropdownMenu.Item
                    key={item.label}
                    onSelect={() => router.push(item.href)}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-foreground hover:bg-surface-700 focus:bg-surface-700 outline-none transition-colors cursor-pointer"
                  >
                    <item.icon className="w-4 h-4 text-muted-foreground" />
                    {item.label}
                  </DropdownMenu.Item>
                ))}
                <div className="border-t border-border mt-1 pt-1">
                  <DropdownMenu.Item
                    onSelect={logout}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 focus:bg-red-500/10 outline-none transition-colors cursor-pointer"
                  >
                    <LogOut className="w-4 h-4" />
                    Sign out
                  </DropdownMenu.Item>
                </div>
              </motion.div>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}
