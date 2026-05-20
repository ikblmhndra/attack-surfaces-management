"use client";

import { useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
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
  const { refreshUser, setLoading, isAuthenticated } = useWorkspaceStore();

  // Initialize auth state on mount
  useEffect(() => {
    const token = tokenStorage.getAccess();
    if (token) {
      refreshUser().catch(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <Toaster
        position="bottom-right"
        theme="dark"
        toastOptions={{
          style: {
            background: "hsl(222 47% 6%)",
            border: "1px solid hsl(217 33% 14%)",
            color: "hsl(210 40% 96%)",
          },
        }}
        richColors
      />
    </QueryClientProvider>
  );
}
