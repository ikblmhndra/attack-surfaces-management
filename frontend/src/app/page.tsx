"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useWorkspaceStore } from "@/store/workspace";

// The bare origin ("/") has no content of its own -- Providers.tsx already
// resolves auth state on mount, so this just waits for that and forwards to
// wherever the user actually belongs, mirroring the login page's own
// post-auth redirect (auth/login/page.tsx) and the dashboard layout's guard.
export default function RootPage() {
  const router = useRouter();
  const { isAuthenticated, isLoading, hasProduct } = useWorkspaceStore();

  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated) {
      router.replace("/auth/login");
      return;
    }
    router.replace(hasProduct("asm") ? "/dashboard" : "/dashboard/bounty");
  }, [isAuthenticated, isLoading, hasProduct, router]);

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="w-10 h-10 border-2 border-brand-400 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}
