"""
ASM Platform — WebSocket Endpoint
Real-time event streaming for scan progress, alerts, and score updates.
Supports per-workspace and per-org subscriptions.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Set
from uuid import UUID

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from app.core.redis_client import get_redis
from app.core.security import verify_token

log = structlog.get_logger()
router = APIRouter()

# ── Connection manager ─────────────────────────────────────────

class ConnectionManager:
    """
    Manages active WebSocket connections.
    Organizes connections by workspace_id for isolated broadcasting.
    """

    def __init__(self):
        # workspace_id → set of WebSocket connections
        self._workspace_connections: Dict[str, Set[WebSocket]] = {}
        # ws → metadata
        self._meta: Dict[WebSocket, dict] = {}

    async def connect(
        self,
        websocket: WebSocket,
        workspace_id: str,
        user_id: str,
        org_id: str | None = None,
    ) -> None:
        await websocket.accept()

        if workspace_id not in self._workspace_connections:
            self._workspace_connections[workspace_id] = set()
        self._workspace_connections[workspace_id].add(websocket)

        self._meta[websocket] = {
            "workspace_id": workspace_id,
            "user_id": user_id,
            "org_id": org_id,
            "connected_at": datetime.now(timezone.utc).isoformat(),
        }

        log.info(
            "ws_connected",
            workspace_id=workspace_id,
            user_id=user_id,
            total=len(self._workspace_connections.get(workspace_id, set())),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        meta = self._meta.pop(websocket, {})
        workspace_id = meta.get("workspace_id")
        if workspace_id and workspace_id in self._workspace_connections:
            self._workspace_connections[workspace_id].discard(websocket)
            if not self._workspace_connections[workspace_id]:
                del self._workspace_connections[workspace_id]

        log.info("ws_disconnected", workspace_id=workspace_id, user_id=meta.get("user_id"))

    async def send_to_workspace(self, workspace_id: str, message: dict) -> None:
        """Send a message to all connections in a workspace."""
        connections = self._workspace_connections.get(workspace_id, set()).copy()
        if not connections:
            return

        payload = json.dumps(message, default=str)
        dead = set()

        for ws in connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        for ws in dead:
            self.disconnect(ws)

    async def send_to_connection(self, websocket: WebSocket, message: dict) -> None:
        """Send a message to a specific connection."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception as e:
            log.warning("ws_send_failed", error=str(e))

    @property
    def total_connections(self) -> int:
        return sum(len(conns) for conns in self._workspace_connections.values())

    def get_workspace_count(self, workspace_id: str) -> int:
        return len(self._workspace_connections.get(workspace_id, set()))


# Singleton connection manager
manager = ConnectionManager()


# ── WebSocket endpoint ────────────────────────────────────────

@router.websocket("/")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
    org_id: str | None = Query(None),
):
    """
    WebSocket connection for real-time platform events.

    Authentication via `token` query parameter (JWT).

    Events pushed to client:
    - scan.started        Scan queued/started
    - scan.progress       Scan progress update (%)
    - scan.completed      Scan finished
    - scan.failed         Scan error
    - finding.new         New finding discovered
    - score.updated       Risk score recomputed
    - asset.new           New asset discovered
    - alert.created       New notification/alert
    - system.message      System broadcast

    Client can send:
    - ping                Keep-alive
    - subscribe {org_id}  Subscribe to specific org events
    """
    # ── Authenticate ──────────────────────────────────────────
    payload = verify_token(token)
    if not payload or payload.get("type") != "access":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
        return

    workspace_id = payload.get("wid")
    user_id = payload.get("sub")

    if not workspace_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="No workspace")
        return

    await manager.connect(websocket, workspace_id, user_id, org_id)

    # Send connection acknowledgment
    await manager.send_to_connection(websocket, {
        "type": "connected",
        "data": {
            "workspace_id": workspace_id,
            "user_id": user_id,
            "org_id": org_id,
            "server_time": datetime.now(timezone.utc).isoformat(),
            "message": "Real-time events active",
        },
    })

    # ── Subscribe to Redis pub/sub ────────────────────────────
    redis = get_redis()
    pubsub = redis.pubsub()
    channel = f"asm:events:{workspace_id}"
    await pubsub.subscribe(channel)

    # Start background listener task
    listener_task = asyncio.create_task(
        _redis_listener(pubsub, websocket, workspace_id, org_id)
    )

    # ── Message loop ──────────────────────────────────────────
    try:
        while True:
            try:
                raw = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30,  # 30s heartbeat window
                )
            except asyncio.TimeoutError:
                # Send server heartbeat
                await manager.send_to_connection(websocket, {
                    "type": "ping",
                    "data": {"time": datetime.now(timezone.utc).isoformat()},
                })
                continue

            # Handle client messages
            try:
                msg = json.loads(raw)
                msg_type = msg.get("type", "")

                if msg_type == "ping":
                    await manager.send_to_connection(websocket, {
                        "type": "pong",
                        "data": {"time": datetime.now(timezone.utc).isoformat()},
                    })

                elif msg_type == "subscribe":
                    # Change org subscription
                    new_org_id = msg.get("org_id")
                    if new_org_id:
                        meta = manager._meta.get(websocket, {})
                        meta["org_id"] = new_org_id
                        await manager.send_to_connection(websocket, {
                            "type": "subscribed",
                            "data": {"org_id": new_org_id},
                        })

                elif msg_type == "get_stats":
                    await manager.send_to_connection(websocket, {
                        "type": "stats",
                        "data": {
                            "total_connections": manager.total_connections,
                            "workspace_connections": manager.get_workspace_count(workspace_id),
                        },
                    })

            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        log.info("ws_client_disconnected", workspace_id=workspace_id, user_id=user_id)
    except Exception as e:
        log.error("ws_error", error=str(e), workspace_id=workspace_id)
    finally:
        listener_task.cancel()
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
        except Exception:
            pass
        manager.disconnect(websocket)


async def _redis_listener(
    pubsub,
    websocket: WebSocket,
    workspace_id: str,
    org_id: str | None,
) -> None:
    """Listen to Redis pub/sub and forward messages to WebSocket client."""
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])

                # Filter by org_id if client is subscribed to specific org
                if org_id and data.get("data", {}).get("org_id"):
                    if data["data"]["org_id"] != org_id:
                        continue

                await websocket.send_text(json.dumps(data, default=str))
            except Exception as e:
                log.warning("ws_forward_error", error=str(e))
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.error("redis_listener_error", error=str(e))


# ── Event publisher (called from workers/API) ─────────────────

async def publish_event(
    workspace_id: str,
    event_type: str,
    data: dict,
    org_id: str | None = None,
) -> None:
    """
    Publish a real-time event to all WebSocket clients in a workspace.
    Also publishes to Redis pub/sub for multi-instance support.
    """
    message = {
        "type": event_type,
        "data": {
            "org_id": org_id,
            **data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

    # Direct broadcast to local connections
    await manager.send_to_workspace(workspace_id, message)

    # Publish to Redis for other API instances
    try:
        redis = get_redis()
        channel = f"asm:events:{workspace_id}"
        await redis.publish(channel, json.dumps(message, default=str))
    except Exception as e:
        log.warning("ws_redis_publish_failed", error=str(e))


# ── Convenience event publishers ──────────────────────────────

async def emit_scan_progress(
    workspace_id: str,
    org_id: str,
    scan_id: str,
    progress_pct: float,
    status: str,
    message: str = "",
) -> None:
    await publish_event(workspace_id, "scan.progress", {
        "scan_id": scan_id,
        "progress_pct": progress_pct,
        "status": status,
        "message": message,
    }, org_id=org_id)


async def emit_new_finding(
    workspace_id: str,
    org_id: str,
    finding: dict,
) -> None:
    await publish_event(workspace_id, "finding.new", finding, org_id=org_id)


async def emit_score_updated(
    workspace_id: str,
    org_id: str,
    score: int,
    grade: str,
    delta: int = 0,
) -> None:
    await publish_event(workspace_id, "score.updated", {
        "score": score,
        "grade": grade,
        "delta": delta,
    }, org_id=org_id)
