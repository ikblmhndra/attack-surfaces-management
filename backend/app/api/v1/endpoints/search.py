"""
ASM Platform — Search API Endpoint
Full-text search across assets and findings using OpenSearch.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import get_current_user, get_db, get_workspace_id
from app.core.opensearch import get_opensearch
from app.db.models.models import User

log = structlog.get_logger()
router = APIRouter()


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    filters: Optional[Dict[str, Any]] = None
    types: List[str] = Field(default=["assets", "findings"])
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


@router.post("")
async def search(
    request: SearchRequest,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
):
    """Full-text search across assets and findings."""
    try:
        os_client = get_opensearch()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Search service unavailable")

    results = {"assets": [], "findings": [], "total": 0, "query": request.query}

    base_filter = [{"term": {"workspace_id": str(workspace_id)}}]
    if request.filters:
        if org_id := request.filters.get("org_id"):
            base_filter.append({"term": {"org_id": org_id}})
        if severity := request.filters.get("severity"):
            base_filter.append({"term": {"severity": severity}})
        if status := request.filters.get("status"):
            base_filter.append({"term": {"status": status}})

    from_offset = (request.page - 1) * request.page_size

    # Search assets
    if "assets" in request.types:
        try:
            asset_resp = await os_client.search(
                index="asm-assets",
                body={
                    "query": {
                        "bool": {
                            "must": [{"multi_match": {
                                "query": request.query,
                                "fields": ["value^3", "title^2", "technologies", "ip_addresses"],
                                "type": "best_fields",
                                "fuzziness": "AUTO",
                            }}],
                            "filter": base_filter,
                        }
                    },
                    "highlight": {
                        "fields": {"value": {}, "title": {}},
                        "pre_tags": ["<mark>"],
                        "post_tags": ["</mark>"],
                    },
                    "from": from_offset,
                    "size": request.page_size,
                    "_source": ["id", "value", "asset_type", "status", "technologies",
                                "http_status", "title", "ip_addresses", "first_seen", "last_seen"],
                },
            )
            hits = asset_resp.get("hits", {})
            results["assets"] = [
                {**h["_source"], "highlight": h.get("highlight", {}), "score": h.get("_score")}
                for h in hits.get("hits", [])
            ]
            results["assets_total"] = hits.get("total", {}).get("value", 0)
        except Exception as e:
            log.warning("opensearch_asset_search_error", error=str(e))

    # Search findings
    if "findings" in request.types:
        try:
            finding_resp = await os_client.search(
                index="asm-findings",
                body={
                    "query": {
                        "bool": {
                            "must": [{"multi_match": {
                                "query": request.query,
                                "fields": ["title^3", "description^2", "template_id", "cve_ids^2", "affected_url"],
                                "type": "best_fields",
                                "fuzziness": "AUTO",
                            }}],
                            "filter": base_filter,
                        }
                    },
                    "highlight": {
                        "fields": {"title": {}, "description": {}, "affected_url": {}},
                        "pre_tags": ["<mark>"],
                        "post_tags": ["</mark>"],
                    },
                    "from": from_offset,
                    "size": request.page_size,
                    "_source": ["id", "title", "severity", "category", "status",
                                "template_id", "cve_ids", "cvss_score", "affected_url",
                                "first_seen", "last_seen"],
                },
            )
            hits = finding_resp.get("hits", {})
            results["findings"] = [
                {**h["_source"], "highlight": h.get("highlight", {}), "score": h.get("_score")}
                for h in hits.get("hits", [])
            ]
            results["findings_total"] = hits.get("total", {}).get("value", 0)
        except Exception as e:
            log.warning("opensearch_finding_search_error", error=str(e))

    results["total"] = results.get("assets_total", 0) + results.get("findings_total", 0)
    return results
