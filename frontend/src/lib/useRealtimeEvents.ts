"use client";

import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { tokenStorage } from "@/lib/api";

function getWsUrl(orgId?: string) {
  const configured = process.env.NEXT_PUBLIC_WS_URL || "wss://localhost/ws";
  const url = new URL(configured);
  const token = tokenStorage.getAccess();
  if (token) url.searchParams.set("token", token);
  if (orgId) url.searchParams.set("org_id", orgId);
  return url.toString();
}

export function useRealtimeEvents(orgId?: string) {
  const queryClient = useQueryClient();

  useEffect(() => {
    const token = tokenStorage.getAccess();
    if (!token) return;

    let closed = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let ws: WebSocket | undefined;

    const connect = () => {
      ws = new WebSocket(getWsUrl(orgId));

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "ping") {
            ws?.send(JSON.stringify({ type: "pong" }));
            return;
          }

          if (msg.type?.startsWith("scan.")) {
            queryClient.invalidateQueries({ queryKey: ["scans"] });
            queryClient.invalidateQueries({ queryKey: ["recent-scans"] });
          }

          if (msg.type === "score.updated") {
            queryClient.invalidateQueries({ queryKey: ["org-score"] });
            queryClient.invalidateQueries({ queryKey: ["score-history"] });
          }

          if (msg.type === "finding.new") {
            queryClient.invalidateQueries({ queryKey: ["findings-summary"] });
            queryClient.invalidateQueries({ queryKey: ["findings"] });
          }
        } catch {
          // Ignore malformed real-time events; polling remains the fallback.
        }
      };

      ws.onclose = () => {
        if (!closed) retryTimer = setTimeout(connect, 5000);
      };
    };

    connect();

    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      ws?.close();
    };
  }, [orgId, queryClient]);
}
