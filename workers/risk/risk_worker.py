"""
ASM Platform — Risk Scoring Worker
Consumes risk.compute messages, runs the scoring engine,
persists snapshots, and emits real-time score updates.
"""
import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.base_worker import BaseWorker
from workers.db import get_session

log = structlog.get_logger()


class RiskWorker(BaseWorker):
    """
    Computes organization risk scores after each scan cycle.

    Workflow:
    1. Load all open findings for the org
    2. Run the scoring engine (9 categories, weighted)
    3. Persist a RiskScore snapshot
    4. Compute delta vs. previous score
    5. Update org denormalized stats
    6. Publish score.updated event via Redis
    7. Queue notification if score degraded significantly
    """

    QUEUE = "risk.compute"
    CONCURRENCY = 2

    async def process(self, message: Dict[str, Any]) -> None:
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        scan_id = message.get("scan_id", "unknown")

        log.info("risk_computation_started", org_id=org_id, scan_id=scan_id)

        async with get_session() as db:
            # ── Load findings ──────────────────────────────────
            findings = await self._load_findings(db, org_id)
            total_assets = await self._count_assets(db, org_id)

            # ── Get previous score ─────────────────────────────
            prev_score = await self._get_latest_score(db, org_id)

            # ── Run scoring engine ─────────────────────────────
            from app.services.risk_engine import compute_org_score
            score_result = compute_org_score(
                org_id=org_id,
                findings=findings,
                total_assets=total_assets,
            )

            # ── Persist score snapshot ─────────────────────────
            await self._persist_score(db, workspace_id, score_result)

            # ── Compute delta ──────────────────────────────────
            delta = 0
            if prev_score:
                delta = score_result.overall_score - prev_score["overall_score"]

            log.info(
                "risk_score_computed",
                org_id=org_id,
                score=score_result.overall_score,
                grade=score_result.grade,
                delta=delta,
                findings=len(findings),
            )

        # ── Emit real-time update ─────────────────────────────
        await self._emit_score_event(
            workspace_id=workspace_id,
            org_id=org_id,
            score=score_result.overall_score,
            grade=score_result.grade,
            delta=delta,
        )

        # ── Queue notification if score degraded ──────────────
        if delta <= -10:  # Significant score drop
            await self._queue_score_alert(
                org_id=org_id,
                workspace_id=workspace_id,
                score=score_result.overall_score,
                prev_score=prev_score["overall_score"] if prev_score else None,
                delta=delta,
                grade=score_result.grade,
            )

    async def _load_findings(self, db, org_id: str) -> list:
        """Load all non-excluded findings for scoring."""
        from workers.db_models import Finding
        from app.services.exploit_intel import compute_exploit_boost, get_exploit_intel

        result = await db.execute(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.deleted_at.is_(None),
                Finding.is_false_positive == False,
                Finding.is_risk_accepted == False,
                Finding.status.notin_(["resolved", "false_positive"]),
            )
        )
        findings = result.scalars().all()

        all_cve_ids = sorted({cve for f in findings for cve in (f.cve_ids or [])})
        intel_by_cve = await get_exploit_intel(db, all_cve_ids)

        return [
            {
                "id": str(f.id),
                "category": f.category or "unknown",
                "severity": f.severity,
                "status": f.status,
                "confidence": float((f.proof or {}).get("confidence_score", 1.0)),
                "exploit_boost": compute_exploit_boost(intel_by_cve, f.cve_ids or []),
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
                "is_false_positive": f.is_false_positive,
                "is_risk_accepted": f.is_risk_accepted,
                "cvss_score": f.cvss_score,
            }
            for f in findings
        ]

    async def _count_assets(self, db, org_id: str) -> int:
        from sqlalchemy import func
        from workers.db_models import Asset
        result = await db.execute(
            select(func.count(Asset.id)).where(
                Asset.org_id == org_id,
                Asset.deleted_at.is_(None),
                Asset.status == "active",
            )
        )
        return result.scalar_one()

    async def _get_latest_score(self, db, org_id: str) -> dict | None:
        from workers.db_models import RiskScore
        result = await db.execute(
            select(RiskScore).where(RiskScore.org_id == org_id)
            .order_by(RiskScore.computed_at.desc())
            .limit(1)
        )
        score = result.scalar_one_or_none()
        if not score:
            return None
        return {
            "overall_score": score.overall_score,
            "grade": score.grade,
            "computed_at": score.computed_at,
        }

    async def _persist_score(self, db, workspace_id: str, score_result) -> None:
        from workers.db_models import RiskScore, Organization

        cat = score_result.score_breakdown

        score_record = {
            "org_id": score_result.org_id,
            "workspace_id": workspace_id,
            "overall_score": score_result.overall_score,
            "grade": score_result.grade,
            "score_version": score_result.score_version,
            "network_security_score":  cat.get("network_security", {}).get("score", 100),
            "dns_health_score":        cat.get("dns_health", {}).get("score", 100),
            "web_security_score":      cat.get("web_security", {}).get("score", 100),
            "tls_security_score":      cat.get("tls_security", {}).get("score", 100),
            "exposure_mgmt_score":     cat.get("exposure_mgmt", {}).get("score", 100),
            "patch_hygiene_score":     cat.get("patch_hygiene", {}).get("score", 100),
            "info_leakage_score":      cat.get("info_leakage", {}).get("score", 100),
            "reputation_score":        cat.get("reputation", {}).get("score", 100),
            "misconfiguration_score":  cat.get("misconfiguration", {}).get("score", 100),
            "total_assets":   score_result.total_assets,
            "total_findings": score_result.total_findings,
            "critical_count": score_result.critical_count,
            "high_count":     score_result.high_count,
            "medium_count":   score_result.medium_count,
            "low_count":      score_result.low_count,
            "info_count":     score_result.info_count,
            "score_breakdown": score_result.score_breakdown,
            "score_factors":   score_result.score_factors,
            "computed_at":     score_result.computed_at,
        }

        await db.execute(pg_insert(RiskScore.__table__).values(**score_record))

        # Update org denormalized stats
        from sqlalchemy import update
        await db.execute(
            update(Organization).where(Organization.id == score_result.org_id).values(
                total_assets=score_result.total_assets,
                total_findings=score_result.total_findings,
            )
        )
        await db.commit()

    async def _emit_score_event(
        self,
        workspace_id: str,
        org_id: str,
        score: int,
        grade: str,
        delta: int,
    ) -> None:
        """Publish score update to Redis for WebSocket broadcast."""
        try:
            import redis.asyncio as aioredis
            redis = aioredis.from_url(
                os.getenv("REDIS_URL", "redis://redis:6379/0"),
                decode_responses=True,
            )
            channel = f"asm:events:{workspace_id}"
            message = json.dumps({
                "type": "score.updated",
                "data": {
                    "org_id": org_id,
                    "score": score,
                    "grade": grade,
                    "delta": delta,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            })
            await redis.publish(channel, message)
            await redis.aclose()
        except Exception as e:
            log.warning("score_event_publish_failed", error=str(e))

    async def _queue_score_alert(
        self,
        org_id: str,
        workspace_id: str,
        score: int,
        prev_score: int | None,
        delta: int,
        grade: str,
    ) -> None:
        from workers.queue_client import QueueClient
        queue = QueueClient()
        await queue.connect()
        await queue.publish(
            routing_key="notify.send",
            message={
                "scan_id": "risk-monitor",
                "org_id": org_id,
                "workspace_id": workspace_id,
                "changes": [{
                    "type": "score_degradation",
                    "severity": "high" if delta <= -20 else "medium",
                    "message": (
                        f"Security score dropped by {abs(delta)} points to {score}/100 (Grade {grade}). "
                        f"Previous score: {prev_score}"
                    ),
                    "score": score,
                    "prev_score": prev_score,
                    "delta": delta,
                    "grade": grade,
                }],
            },
            priority=8,
        )
        await queue.close()


if __name__ == "__main__":
    worker = RiskWorker()
    asyncio.run(worker.run())
