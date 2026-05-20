"use client";

import { useEffect, useRef } from "react";
import { useRouter, usePathname } from "next/navigation";
import { motion } from "framer-motion";
import { Sidebar } from "@/components/layout/Sidebar";
import { DashboardHeader } from "@/components/layout/DashboardHeader";
import { useWorkspaceStore } from "@/store/workspace";
import { wsClient } from "@/lib/api";
import { tokenStorage } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { isAuthenticated, isLoading, sidebarCollapsed, activeOrg } = useWorkspaceStore();
  const queryClient = useQueryClient();
  const wsInitialized = useRef(false);

  // Auth guard
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.replace("/auth/login");
    }
  }, [isAuthenticated, isLoading, router]);

  // WebSocket connection
  useEffect(() => {
    if (!isAuthenticated || wsInitialized.current) return;
    wsInitialized.current = true;

    wsClient.connect(activeOrg?.id);

    // Listen for real-time events and invalidate relevant queries
    const unsubScore = wsClient.on("score.updated", (data) => {
      queryClient.invalidateQueries({ queryKey: ["org-score", data.data?.org_id] });
      queryClient.invalidateQueries({ queryKey: ["organizations"] });
    });

    const unsubFinding = wsClient.on("finding.new", () => {
      queryClient.invalidateQueries({ queryKey: ["findings-summary"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    });

    const unsubScan = wsClient.on("scan.progress", (data) => {
      queryClient.invalidateQueries({ queryKey: ["recent-scans"] });
    });

    return () => {
      unsubScore();
      unsubFinding();
      unsubScan();
      wsClient.disconnect();
      wsInitialized.current = false;
    };
  }, [isAuthenticated, activeOrg?.id]);

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-brand-400 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-muted-foreground">Loading ASM Platform...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) return null;

  const mainPadding = sidebarCollapsed ? "pl-16" : "pl-56";

  return (
    <div className="min-h-screen bg-background">
      {/* Sidebar */}
      <Sidebar />

      {/* Main content area */}
      <motion.div
        animate={{ paddingLeft: sidebarCollapsed ? 64 : 224 }}
        transition={{ duration: 0.2, ease: "easeInOut" }}
        className="min-h-screen flex flex-col"
      >
        {/* Header */}
        <DashboardHeader />

        {/* Page content */}
        <main className="flex-1 overflow-auto">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
          >
            {children}
          </motion.div>
        </main>
      </motion.div>
    </div>
  );
}
