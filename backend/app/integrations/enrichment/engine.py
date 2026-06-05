"""
ASM Platform - Threat intelligence enrichment compatibility layer.

The active enrichment path is intentionally no-key and tool/public-source based.
Provider API plugins were removed so scans do not depend on paid or entitled
third-party threat-intelligence APIs.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog

log = structlog.get_logger()


@dataclass
class EnrichmentResult:
    source: str
    indicator_type: str
    data: Dict[str, Any]
    risk_score: Optional[int] = None
    is_malicious: bool = False
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    expires_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


class EnrichmentEngine:
    """No-op API plugin engine kept for backwards-compatible imports."""

    def __init__(self) -> None:
        self.plugins: List[Any] = []
        self.enabled_plugins: List[Any] = []
        log.info("enrichment_engine_initialized", enabled_plugins=[])

    async def enrich(
        self,
        indicator: str,
        indicator_type: str,
        plugins: Optional[List[str]] = None,
    ) -> Dict[str, EnrichmentResult]:
        log.info(
            "enrichment_api_plugins_disabled",
            indicator=indicator,
            indicator_type=indicator_type,
        )
        return {}

    def aggregate_risk(self, results: Dict[str, EnrichmentResult]) -> Dict[str, Any]:
        if not results:
            return {"risk_score": 0, "is_malicious": False, "sources": []}

        scores = [r.risk_score for r in results.values() if r.risk_score is not None]
        is_malicious = any(r.is_malicious for r in results.values())
        all_tags = list({tag for r in results.values() for tag in r.tags})
        all_categories = list({cat for r in results.values() for cat in r.categories})
        agg_score = int(sum(scores) / len(scores)) if scores else 0
        if is_malicious:
            agg_score = max(agg_score, 50)

        return {
            "risk_score": min(100, agg_score),
            "is_malicious": is_malicious,
            "tags": all_tags[:30],
            "categories": all_categories[:20],
            "sources": [
                {
                    "name": name,
                    "score": result.risk_score,
                    "malicious": result.is_malicious,
                    "error": result.error,
                }
                for name, result in results.items()
            ],
        }


enrichment_engine = EnrichmentEngine()
