/**
 * ASM Platform — API Client
 * Axios instance with JWT auth, refresh token rotation, and error handling.
 */
import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosError,
  InternalAxiosRequestConfig,
} from "axios";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "/api/v1";

// Token storage keys
const ACCESS_TOKEN_KEY = "asm_access_token";
const REFRESH_TOKEN_KEY = "asm_refresh_token";

// Token helpers
export const tokenStorage = {
  getAccess: (): string | null => {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  },
  getRefresh: (): string | null => {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  },
  setTokens: (access: string, refresh: string) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, access);
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  },
  clearTokens: () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: {
    "Content-Type": "application/json",
    "X-Client": "ASM-Platform-Web/1.0",
  },
});

// Track refresh state to prevent multiple simultaneous refreshes
let isRefreshing = false;
let refreshSubscribers: Array<(token: string) => void> = [];

const subscribeTokenRefresh = (cb: (token: string) => void) => {
  refreshSubscribers.push(cb);
};

const onRefreshed = (token: string) => {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
};

// ── Request interceptor: inject access token ──────────────────
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = tokenStorage.getAccess();
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response interceptor: handle token refresh ────────────────
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // 401 → attempt token refresh
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      originalRequest.url !== "/auth/login" &&
      originalRequest.url !== "/auth/refresh"
    ) {
      const refreshToken = tokenStorage.getRefresh();
      if (!refreshToken) {
        tokenStorage.clearTokens();
        window.location.href = "/auth/login";
        return Promise.reject(error);
      }

      if (isRefreshing) {
        // Queue request until refresh completes
        return new Promise((resolve) => {
          subscribeTokenRefresh((token) => {
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${token}`;
            }
            resolve(api(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await axios.post(`${BASE_URL}/auth/refresh`, {
          refresh_token: refreshToken,
        });

        const { access_token, refresh_token } = data;
        tokenStorage.setTokens(access_token, refresh_token);

        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
        }

        onRefreshed(access_token);
        isRefreshing = false;

        return api(originalRequest);
      } catch (refreshError) {
        isRefreshing = false;
        tokenStorage.clearTokens();
        window.location.href = "/auth/login";
        return Promise.reject(refreshError);
      }
    }

    // 403 → redirect to unauthorized page
    if (error.response?.status === 403) {
      console.warn("Access denied:", originalRequest.url);
    }

    return Promise.reject(error);
  }
);

export const apiClient = api;

// ── Typed API functions ───────────────────────────────────────

export const authAPI = {
  login: (email: string, password: string, mfa_code?: string) =>
    api.post("/auth/login", { email, password, mfa_code }),

  register: (data: {
    email: string;
    password: string;
    full_name: string;
    workspace_name: string;
    enabled_products: string[];
    invite_token?: string;
  }) => api.post("/auth/register", data),

  logout: () => api.post("/auth/logout"),

  me: () => api.get("/auth/me"),

  setupMFA: () => api.post("/auth/mfa/setup"),

  enableMFA: (secret: string, code: string) =>
    api.post("/auth/mfa/enable", { secret, code }),
};

export const workspacesAPI = {
  getMembers: () => api.get("/workspaces/members"),

  invite: (email: string, role: "admin" | "analyst" | "viewer") =>
    api.post("/workspaces/invite", { email, role }),
};

export const organizationsAPI = {
  list: (params?: Record<string, any>) =>
    api.get("/organizations", { params }),

  get: (id: string) => api.get(`/organizations/${id}`),

  create: (data: Record<string, any>) => api.post("/organizations", data),

  update: (id: string, data: Record<string, any>) =>
    api.put(`/organizations/${id}`, data),

  delete: (id: string) => api.delete(`/organizations/${id}`),

  triggerScan: (id: string, config: Record<string, any>) =>
    api.post(`/organizations/${id}/scans`, config),

  getScans: (id: string, params?: Record<string, any>) =>
    api.get(`/organizations/${id}/scans`, { params }),

  getScoreHistory: (id: string, days: number = 90) =>
    api.get(`/organizations/${id}/score-history`, { params: { days } }),

  getTimeline: (id: string, days: number = 30) =>
    api.get(`/organizations/${id}/timeline`, { params: { days } }),
};

export const assetsAPI = {
  list: (params?: Record<string, any>) => api.get("/assets", { params }),
  get: (id: string) => api.get(`/assets/${id}`),
  getEndpoints: (id: string, params?: Record<string, any>) => api.get(`/assets/${id}/endpoints`, { params }),
  getFindings: (id: string) => api.get(`/assets/${id}/findings`),
  getTechnologies: (id: string) => api.get(`/assets/${id}/technologies`),
  getScreenshots: (id: string) => api.get(`/assets/${id}/screenshots`),
  getIntel: (id: string) => api.get(`/assets/${id}/intel`),
  review: (id: string, data: { decision: "approve" | "reject" | "needs_review"; note?: string }) =>
    api.post(`/assets/${id}/review`, data),
};

export const findingsAPI = {
  list: (params?: Record<string, any>) => api.get("/findings", { params }),
  get: (id: string) => api.get(`/findings/${id}`),
  update: (id: string, data: Record<string, any>) =>
    api.put(`/findings/${id}`, data),
  markFalsePositive: (id: string, reason: string) =>
    api.post(`/findings/${id}/false-positive`, { reason }),
  acceptRisk: (id: string, reason: string, until?: string) =>
    api.post(`/findings/${id}/accept-risk`, { reason, until }),
};

export const scansAPI = {
  list: (params?: Record<string, any>) => api.get("/scans", { params }),
  get: (id: string) => api.get(`/scans/${id}`),
  cancel: (id: string) => api.post(`/scans/${id}/cancel`),
};

export const scoresAPI = {
  list: (params?: Record<string, any>) => api.get("/scores", { params }),
  history: (params?: Record<string, any>) =>
    api.get("/scores/history", { params }),
  breakdown: (params?: Record<string, any>) =>
    api.get("/scores/breakdown", { params }),
};

export const searchAPI = {
  search: (query: string, filters?: Record<string, any>) =>
    api.post("/search", { query, filters }),
};

export const notificationsAPI = {
  list: (params?: Record<string, any>) =>
    api.get("/notifications", { params }),
  markRead: (id: string) => api.patch(`/notifications/${id}/read`),
  markAllRead: () => api.post("/notifications/mark-all-read"),
  getRules: () => api.get("/notifications/rules"),
  createRule: (data: Record<string, any>) =>
    api.post("/notifications/rules", data),
  updateRule: (id: string, data: Record<string, any>) =>
    api.put(`/notifications/rules/${id}`, data),
  deleteRule: (id: string) => api.delete(`/notifications/rules/${id}`),
};

export const reportsAPI = {
  generate: (data: Record<string, any>) => api.post("/reports/generate", data),
  download: (id: string) => api.get(`/reports/${id}/download`, { responseType: "blob" }),
};

export const keysAPI = {
  list: () => api.get("/keys"),
  create: (data: { name: string; scopes: string[]; expires_at?: string }) =>
    api.post("/keys", data),
  delete: (id: string) => api.delete(`/keys/${id}`),
};

export const adminAPI = {
  getUsers: (params?: Record<string, any>) => api.get("/admin/users", { params }),
  updateUser: (id: string, data: Record<string, any>) =>
    api.put(`/admin/users/${id}`, data),
  getAuditLogs: (params?: Record<string, any>) =>
    api.get("/admin/audit-logs", { params }),
};

// Bug Bounty active-testing pipeline (workspace-scoped, independent of the
// ASM org/asset model — see backend endpoints/bounty.py).
export const bountyAPI = {
  listPrograms: (params?: Record<string, any>) => api.get("/bounty/programs", { params }),
  getProgram: (id: string) => api.get(`/bounty/programs/${id}`),
  createProgram: (data: Record<string, any>) => api.post("/bounty/programs", data),
  updateProgram: (id: string, data: Record<string, any>) => api.put(`/bounty/programs/${id}`, data),
  deleteProgram: (id: string) => api.delete(`/bounty/programs/${id}`),
  runStage: (id: string, stage: string) => api.post(`/bounty/programs/${id}/run/${stage}`),
  runPipeline: (id: string) => api.post(`/bounty/programs/${id}/run/pipeline`),

  listTargets: (id: string) => api.get(`/bounty/programs/${id}/targets`),
  createTarget: (id: string, data: { value: string; target_type?: string }) =>
    api.post(`/bounty/programs/${id}/targets`, data),
  deleteTarget: (id: string, targetId: string) =>
    api.delete(`/bounty/programs/${id}/targets/${targetId}`),

  listAssets: (id: string, params?: Record<string, any>) =>
    api.get(`/bounty/programs/${id}/assets`, { params }),
  promoteAsset: (id: string, assetId: string) =>
    api.post(`/bounty/programs/${id}/assets/${assetId}/promote`),
  promoteAssetsBulk: (id: string, assetIds: string[]) =>
    api.post(`/bounty/programs/${id}/assets/promote-bulk`, { asset_ids: assetIds }),

  listFindings: (id: string, params?: Record<string, any>) =>
    api.get(`/bounty/programs/${id}/findings`, { params }),

  getSummary: (id: string) => api.get(`/bounty/programs/${id}/summary`),
  getReportHtml: (id: string) =>
    api.get(`/bounty/programs/${id}/report.html`, { responseType: "text" }),

  listReports: (id: string, params?: Record<string, any>) =>
    api.get(`/bounty/programs/${id}/reports`, { params }),
  getReport: (id: string, reportId: string) =>
    api.get(`/bounty/programs/${id}/reports/${reportId}`),
  updateReport: (id: string, reportId: string, data: Record<string, any>) =>
    api.put(`/bounty/programs/${id}/reports/${reportId}`, data),
  deleteReport: (id: string, reportId: string) =>
    api.delete(`/bounty/programs/${id}/reports/${reportId}`),
};

// ── WebSocket client ──────────────────────────────────────────

export class WSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private listeners: Map<string, Set<(data: any) => void>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;

  constructor(private wsUrl: string = process.env.NEXT_PUBLIC_WS_URL || "/ws") {}

  connect(orgId?: string) {
    const token = tokenStorage.getAccess();
    if (!token) return;

    const url = `${this.wsUrl}?token=${encodeURIComponent(token)}${orgId ? `&org_id=${orgId}` : ""}`;

    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      console.log("[WS] Connected");
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000;
      this.emit("connected", {});
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        this.emit(msg.type || "message", msg);
        this.emit("*", msg);
      } catch (e) {
        console.warn("[WS] Invalid message:", event.data);
      }
    };

    this.ws.onclose = (event) => {
      console.log("[WS] Disconnected", event.code);
      this.emit("disconnected", { code: event.code });
      this.scheduleReconnect(orgId);
    };

    this.ws.onerror = (error) => {
      console.error("[WS] Error:", error);
    };
  }

  on(event: string, handler: (data: any) => void) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
    return () => this.off(event, handler);
  }

  off(event: string, handler: (data: any) => void) {
    this.listeners.get(event)?.delete(handler);
  }

  private emit(event: string, data: any) {
    this.listeners.get(event)?.forEach((handler) => {
      try {
        handler(data);
      } catch (e) {
        console.error("[WS] Handler error:", e);
      }
    });
  }

  send(data: Record<string, any>) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  private scheduleReconnect(orgId?: string) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, 30_000);
      console.log(`[WS] Reconnecting (attempt ${this.reconnectAttempts})...`);
      this.connect(orgId);
    }, this.reconnectDelay);
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close(1000, "Client disconnect");
    this.ws = null;
  }

  get isConnected() {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

export const wsClient = new WSClient();
