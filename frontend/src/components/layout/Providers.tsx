"use client";

import { useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "framer-motion";
import { Toaster } from "sonner";
import { useWorkspaceStore } from "@/store/workspace";
import { tokenStorage } from "@/lib/api";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 300_000,
      retry: (failureCount, error: any) => {
        if (error?.response?.status === 401 || error?.response?.status === 403) return false;
        return failureCount < 2;
      },
      refetchOnWindowFocus: true,
    },
    mutations: {
      retry: false,
    },
  },
});

export function Providers({ children }: { children: React.ReactNode }) {
  const { refreshUser, setLoading, isAuthenticated, theme } = useWorkspaceStore();

  // Initialize auth state on mount
  useEffect(() => {
    const token = tokenStorage.getAccess();
    if (token) {
      refreshUser().catch(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  // Keep the `.dark` class (Tailwind's darkMode: ["class"] switch) in sync
  // with the persisted theme choice. A blocking inline script in
  // app/layout.tsx sets the initial class before paint to avoid a flash --
  // this effect only needs to react to later toggles.
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  return (
    <QueryClientProvider client={queryClient}>
      {/* prefers-reduced-motion: "user" makes every framer-motion animation
          in the app (page transitions, dropdown/modal enter-exit, sidebar
          width, nav hover) respect the OS-level reduced-motion setting
          without touching each animation individually. */}
      <MotionConfig reducedMotion="user">
        {children}
        <Toaster
          position="bottom-right"
          theme={theme}
          toastOptions={{
            style: {
              background: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              color: "hsl(var(--card-foreground))",
            },
          }}
          richColors
        />
      </MotionConfig>
    </QueryClientProvider>
  );
}
