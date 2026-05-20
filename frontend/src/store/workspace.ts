/**
 * ASM Platform — Workspace & Auth State Store
 * Global state management with Zustand + persistence.
 */
import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { tokenStorage, authAPI } from "@/lib/api";

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: "owner" | "admin" | "analyst" | "viewer";
  workspace_id: string;
  mfa_enabled: boolean;
  last_login?: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  domains: string[];
  total_assets: number;
  total_findings: number;
  current_score?: {
    overall: number;
    grade: string;
    critical: number;
    high: number;
  };
}

interface WorkspaceState {
  // Auth
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;

  // Workspace
  workspaceId: string | null;
  workspaceName: string | null;

  // Active org (selected in UI)
  activeOrg: Organization | null;

  // UI state
  sidebarCollapsed: boolean;
  theme: "dark" | "light";
  notifications: number;

  // Actions
  setUser: (user: User | null) => void;
  setAuthenticated: (v: boolean) => void;
  setLoading: (v: boolean) => void;
  setWorkspace: (id: string, name: string) => void;
  setActiveOrg: (org: Organization | null) => void;
  setSidebarCollapsed: (v: boolean) => void;
  setNotifications: (count: number) => void;

  // Auth actions
  login: (accessToken: string, refreshToken: string, user: User) => void;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;

  // RBAC helpers
  hasRole: (roles: string[]) => boolean;
  canWrite: () => boolean;
  canAdmin: () => boolean;
}

export const useWorkspaceStore = create<WorkspaceState>()(
  persist(
    (set, get) => ({
      // Initial state
      user: null,
      isAuthenticated: false,
      isLoading: true,
      workspaceId: null,
      workspaceName: null,
      activeOrg: null,
      sidebarCollapsed: false,
      theme: "dark",
      notifications: 0,

      // Basic setters
      setUser: (user) => set({ user }),
      setAuthenticated: (v) => set({ isAuthenticated: v }),
      setLoading: (v) => set({ isLoading: v }),
      setWorkspace: (id, name) => set({ workspaceId: id, workspaceName: name }),
      setActiveOrg: (org) => set({ activeOrg: org }),
      setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),
      setNotifications: (count) => set({ notifications: count }),

      // Login: store tokens + user
      login: (accessToken, refreshToken, user) => {
        tokenStorage.setTokens(accessToken, refreshToken);
        set({
          user,
          isAuthenticated: true,
          isLoading: false,
          workspaceId: user.workspace_id,
        });
      },

      // Logout: clear everything
      logout: async () => {
        try {
          await authAPI.logout();
        } catch {
          // Ignore errors on logout
        }
        tokenStorage.clearTokens();
        set({
          user: null,
          isAuthenticated: false,
          workspaceId: null,
          workspaceName: null,
          activeOrg: null,
        });
        window.location.href = "/auth/login";
      },

      // Refresh user profile from API
      refreshUser: async () => {
        try {
          const { data } = await authAPI.me();
          set({ user: data, isAuthenticated: true, isLoading: false });
        } catch {
          set({ isLoading: false });
        }
      },

      // RBAC helpers
      hasRole: (roles: string[]) => {
        const role = get().user?.role;
        return role ? roles.includes(role) : false;
      },

      canWrite: () => {
        return get().hasRole(["owner", "admin", "analyst"]);
      },

      canAdmin: () => {
        return get().hasRole(["owner", "admin"]);
      },
    }),
    {
      name: "asm-workspace",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        // Only persist non-sensitive state
        workspaceId: state.workspaceId,
        workspaceName: state.workspaceName,
        activeOrg: state.activeOrg,
        sidebarCollapsed: state.sidebarCollapsed,
        theme: state.theme,
      }),
    }
  )
);
