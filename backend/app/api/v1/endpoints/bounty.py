"""
ASM Platform — Bug Bounty API Endpoints
CRUD for programs/targets, recon/probe/vulnscan/exploit/report stage triggers,
and review of recon assets / findings / report drafts on the active-testing
pipeline. See CHANGELOG.md for the pipeline's design rationale and
`app.services.bounty_scope` for the scope gate that every stage re-validates
against, both here and again inside the worker itself.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, text, type_coerce, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import (
    RequireRole,
    get_db,
    get_workspace_id,
)
from app.db.models.bounty_models import (
    BountyAsset,
    BountyProgram,
    BountyReport,
    BountyTarget,
    ExploitAttempt,
)
from app.db.models.models import User
from app.services.audit_service import audit_log
from app.services.bounty_report import classify_program, render_html
from app.services.bounty_scope import is_target_in_scope
from app.services.outbox_service import create_queue_event, dispatch_pending_outbox_once

log = structlog.get_logger()
router = APIRouter()

require_admin = RequireRole(["owner", "admin"])

PLATFORMS = {"hackerone", "bugcrowd", "independent"}
PROGRAM_STATUSES = {"active", "paused", "closed"}
VALUE_TYPES = {"domain", "ip", "url"}

# Stage name -> RabbitMQ routing key. Only stages with a worker actually
# consuming the queue belong here -- report is the last remaining stage
# (see the approved plan's build order).
RUNNABLE_STAGES = {
    "recon": "bounty.recon",
    "probe": "bounty.probe",
    "vulnscan": "bounty.vulnscan",
    "exploit": "bounty.exploit",
    "report": "bounty.report",
}

REPORT_STATUSES = {"draft", "submitted", "triaged", "resolved", "paid"}


# ── Schemas ───────────────────────────────────────────────────

class ScopeRule(BaseModel):
    pattern: str = Field(..., min_length=1)
    type: str = Field(default="domain")
    in_scope: bool = True

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in VALUE_TYPES:
            raise ValueError(f"type must be one of: {', '.join(sorted(VALUE_TYPES))}")
        return value


class ProgramCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    platform: str = Field(default="independent")
    scope_rules: List[ScopeRule] = Field(default_factory=list)
    rules_of_engagement: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, value: str) -> str:
        if value not in PLATFORMS:
            raise ValueError(f"platform must be one of: {', '.join(sorted(PLATFORMS))}")
        return value


class ProgramUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    platform: Optional[str] = None
    status: Optional[str] = None
    scope_rules: Optional[List[ScopeRule]] = None
    rules_of_engagement: Optional[Dict[str, Any]] = None

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in PLATFORMS:
            raise ValueError(f"platform must be one of: {', '.join(sorted(PLATFORMS))}")
        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in PROGRAM_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(PROGRAM_STATUSES))}")
        return value


class TargetCreateRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=500)
    target_type: str = Field(default="domain")

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, value: str) -> str:
        if value not in VALUE_TYPES:
            raise ValueError(f"target_type must be one of: {', '.join(sorted(VALUE_TYPES))}")
        return value


class ReportUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    summary: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    status: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in REPORT_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(REPORT_STATUSES))}")
        return value


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    pages: int


# ── Program endpoints ────────────────────────────────────────

@router.get("/programs", response_model=PaginatedResponse)
async def list_programs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List bug bounty programs in the workspace."""
    query = select(BountyProgram).where(BountyProgram.workspace_id == workspace_id)
    if status_filter:
        query = query.where(BountyProgram.status == status_filter)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    query = query.order_by(BountyProgram.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    programs = (await db.execute(query)).scalars().all()

    target_counts: Dict[UUID, int] = {}
    if programs:
        count_rows = (await db.execute(
            select(BountyTarget.program_id, func.count(BountyTarget.id))
            .where(BountyTarget.program_id.in_([p.id for p in programs]))
            .group_by(BountyTarget.program_id)
        )).all()
        target_counts = {pid: n for pid, n in count_rows}

    return PaginatedResponse(
        items=[_program_to_dict(p, target_count=target_counts.get(p.id, 0)) for p in programs],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, (total + page_size - 1) // page_size),
    )


@router.post("/programs", status_code=status.HTTP_201_CREATED)
async def create_program(
    request: ProgramCreateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new bug bounty program. Starts paused -- nothing runs until
    a human explicitly flips status to active."""
    program = BountyProgram(
        workspace_id=workspace_id,
        name=request.name,
        platform=request.platform,
        status="paused",
        scope_rules=[rule.model_dump() for rule in request.scope_rules],
        rules_of_engagement=request.rules_of_engagement,
        created_by=current_user.id,
    )
    db.add(program)
    await db.commit()
    await db.refresh(program)

    log.info("bounty_program_created", program_id=str(program.id), workspace_id=str(workspace_id))

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_program.create",
        resource_type="bounty_program",
        resource_id=str(program.id),
        changes={"name": program.name, "platform": program.platform},
    )

    return _program_to_dict(program, target_count=0)


@router.get("/programs/{program_id}")
async def get_program(
    program_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get a bounty program with its target list."""
    program = await _get_program_or_404(db, program_id, workspace_id)
    targets = (await db.execute(
        select(BountyTarget).where(BountyTarget.program_id == program_id).order_by(BountyTarget.created_at.desc())
    )).scalars().all()

    payload = _program_to_dict(program, target_count=len(targets))
    payload["targets"] = [_target_to_dict(t) for t in targets]
    return payload


@router.put("/programs/{program_id}")
async def update_program(
    program_id: UUID,
    request: ProgramUpdateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update a bounty program's scope, rules of engagement, or status."""
    program = await _get_program_or_404(db, program_id, workspace_id)

    changes: Dict[str, Any] = {}
    update_data = request.model_dump(exclude_none=True)

    for field, value in update_data.items():
        if getattr(program, field) != value:
            changes[field] = {"old": getattr(program, field), "new": value}
            setattr(program, field, value)

    await db.commit()
    await db.refresh(program)

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_program.update",
        resource_type="bounty_program",
        resource_id=str(program_id),
        changes=changes,
    )

    return _program_to_dict(program, target_count=None)


@router.delete("/programs/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_program(
    program_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete a bounty program and cascade its targets/assets/attempts/reports."""
    program = await _get_program_or_404(db, program_id, workspace_id)
    await db.delete(program)
    await db.commit()

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_program.delete",
        resource_type="bounty_program",
        resource_id=str(program_id),
    )


@router.post("/programs/{program_id}/run/pipeline", status_code=status.HTTP_202_ACCEPTED)
async def run_pipeline(
    program_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Kick off the FULL auto pipeline: queue recon with auto_chain, and each
    worker hands off to the next stage on completion (recon auto-promotes its
    in-scope findings, then probe->vulnscan->exploit->report run themselves).
    Same `active`-only gate as a single-stage run; the scope gate is still
    re-validated inside every worker.

    NOTE: this literal `/run/pipeline` route must be declared BEFORE the
    parameterized `/run/{stage}` route below, or FastAPI matches "pipeline"
    as a {stage} value first."""
    program = await _get_program_or_404(db, program_id, workspace_id)
    if program.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Program is '{program.status}', not 'active' -- flip it to active before running the pipeline.",
        )

    event = create_queue_event(
        routing_key="bounty.recon",
        payload={"program_id": str(program_id), "workspace_id": str(workspace_id), "auto_chain": True},
        priority=4,
        aggregate_type="bounty_program",
        aggregate_id=str(program_id),
    )
    db.add(event)
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.execute(
        update(BountyProgram)
        .where(BountyProgram.id == program_id)
        .values(stage_status=func.jsonb_set(
            func.coalesce(BountyProgram.stage_status, text("'{}'::jsonb")),
            text("'{recon}'"),
            type_coerce({"status": "queued", "queued_at": now_iso, "updated_at": now_iso}, JSONB),
            True,
        ))
    )
    await db.commit()

    try:
        await dispatch_pending_outbox_once(limit=5)
    except Exception as exc:
        log.warning("bounty_run_pipeline_outbox_dispatch_deferred", program_id=str(program_id), error=str(exc))

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_program.run.pipeline",
        resource_type="bounty_program",
        resource_id=str(program_id),
    )

    return {"status": "queued", "stage": "pipeline", "auto_chain": True}


@router.post("/programs/{program_id}/run/{stage}", status_code=status.HTTP_202_ACCEPTED)
async def run_stage(
    program_id: UUID,
    stage: str,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Queue a pipeline stage for this program. Refuses anything but an
    `active` program -- paused/closed programs are never runnable, matching
    the gate the worker itself re-checks on the other end of the queue."""
    if stage not in RUNNABLE_STAGES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"stage must be one of: {', '.join(sorted(RUNNABLE_STAGES))}",
        )

    program = await _get_program_or_404(db, program_id, workspace_id)
    if program.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Program is '{program.status}', not 'active' -- flip it to active before running a stage.",
        )

    routing_key = RUNNABLE_STAGES[stage]
    event = create_queue_event(
        routing_key=routing_key,
        payload={"program_id": str(program_id), "workspace_id": str(workspace_id)},
        priority=4,
        aggregate_type="bounty_program",
        aggregate_id=str(program_id),
    )
    db.add(event)
    # Mark the stage 'queued' so the UI shows it immediately; the worker
    # transitions it to running/completed/failed. jsonb_set only touches this
    # one stage key, so a concurrently-updating stage isn't clobbered. `stage`
    # is validated against RUNNABLE_STAGES above, so it's safe in the path text.
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.execute(
        update(BountyProgram)
        .where(BountyProgram.id == program_id)
        .values(stage_status=func.jsonb_set(
            func.coalesce(BountyProgram.stage_status, text("'{}'::jsonb")),
            text(f"'{{{stage}}}'"),
            # type_coerce so the JSONB bind encodes once (a cast(json.dumps())
            # double-encodes into a JSON string instead of an object).
            type_coerce({"status": "queued", "queued_at": now_iso, "updated_at": now_iso}, JSONB),
            True,
        ))
    )
    await db.commit()

    try:
        await dispatch_pending_outbox_once(limit=5)
    except Exception as exc:
        log.warning("bounty_run_stage_outbox_dispatch_deferred", program_id=str(program_id), stage=stage, error=str(exc))

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action=f"bounty_program.run.{stage}",
        resource_type="bounty_program",
        resource_id=str(program_id),
    )

    return {"status": "queued", "stage": stage, "routing_key": routing_key}


# ── Target endpoints ─────────────────────────────────────────

@router.get("/programs/{program_id}/targets")
async def list_targets(
    program_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List the explicitly-approved testable targets for a program."""
    await _get_program_or_404(db, program_id, workspace_id)
    targets = (await db.execute(
        select(BountyTarget).where(BountyTarget.program_id == program_id).order_by(BountyTarget.created_at.desc())
    )).scalars().all()
    return {"items": [_target_to_dict(t) for t in targets], "total": len(targets)}


@router.post("/programs/{program_id}/targets", status_code=status.HTTP_201_CREATED)
async def create_target(
    program_id: UUID,
    request: TargetCreateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Explicitly add a value to a program's testable target list.

    Rejected up front if it doesn't pass the program's own scope_rules --
    the same is_target_in_scope gate every worker re-checks at execution
    time, so a target can never exist here without also being scope-valid.
    """
    program = await _get_program_or_404(db, program_id, workspace_id)

    if not is_target_in_scope(request.value, program.scope_rules or []):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"'{request.value}' does not match this program's scope_rules. "
                "Add a matching in-scope rule first, or double-check for a typo."
            ),
        )

    existing = (await db.execute(
        select(BountyTarget).where(
            BountyTarget.program_id == program_id,
            BountyTarget.value == request.value,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Target already exists on this program")

    target = BountyTarget(
        program_id=program_id,
        value=request.value,
        target_type=request.target_type,
        added_by=current_user.id,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_target.create",
        resource_type="bounty_target",
        resource_id=str(target.id),
        changes={"program_id": str(program_id), "value": target.value},
    )

    return _target_to_dict(target)


@router.delete("/programs/{program_id}/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    program_id: UUID,
    target_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove a target from a program's testable list."""
    await _get_program_or_404(db, program_id, workspace_id)
    target = (await db.execute(
        select(BountyTarget).where(BountyTarget.id == target_id, BountyTarget.program_id == program_id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    await db.delete(target)
    await db.commit()

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_target.delete",
        resource_type="bounty_target",
        resource_id=str(target_id),
        changes={"program_id": str(program_id)},
    )


# ── Recon asset endpoints ────────────────────────────────────

@router.get("/programs/{program_id}/assets")
async def list_assets(
    program_id: UUID,
    asset_type: Optional[str] = Query(default=None),
    promoted: Optional[bool] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List bounty.recon's output for human review -- never auto-promoted,
    see promote_asset below for the explicit approval step."""
    await _get_program_or_404(db, program_id, workspace_id)

    query = select(BountyAsset).where(BountyAsset.program_id == program_id)
    if asset_type:
        query = query.where(BountyAsset.asset_type == asset_type)
    if promoted is not None:
        query = query.where(BountyAsset.promoted == promoted)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    query = query.order_by(BountyAsset.discovered_at.desc()).offset((page - 1) * page_size).limit(page_size)
    assets = (await db.execute(query)).scalars().all()

    return {
        "items": [_asset_to_dict(a) for a in assets],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


@router.post("/programs/{program_id}/assets/{asset_id}/promote", status_code=status.HTTP_201_CREATED)
async def promote_asset(
    program_id: UUID,
    asset_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Turn a recon suggestion into an explicitly-approved testable target.

    The only path from BountyAsset to BountyTarget -- always a deliberate
    human action, never automatic, and still gated by the same scope check
    every other target-creation path goes through.
    """
    program = await _get_program_or_404(db, program_id, workspace_id)
    asset = (await db.execute(
        select(BountyAsset).where(BountyAsset.id == asset_id, BountyAsset.program_id == program_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if asset.asset_type not in VALUE_TYPES.union({"subdomain"}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"asset_type '{asset.asset_type}' isn't a testable target shape (need subdomain/url/ip).",
        )

    if not is_target_in_scope(asset.value, program.scope_rules or []):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{asset.value}' does not match this program's scope_rules.",
        )

    target_type = "domain" if asset.asset_type == "subdomain" else asset.asset_type
    existing = (await db.execute(
        select(BountyTarget).where(
            BountyTarget.program_id == program_id,
            BountyTarget.value == asset.value,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Target already exists on this program")

    target = BountyTarget(
        program_id=program_id,
        value=asset.value,
        target_type=target_type,
        added_by=current_user.id,
    )
    db.add(target)
    asset.promoted = True
    await db.commit()
    await db.refresh(target)

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_asset.promote",
        resource_type="bounty_target",
        resource_id=str(target.id),
        changes={"program_id": str(program_id), "value": target.value, "from_asset_id": str(asset_id)},
    )

    return _target_to_dict(target)


class BulkPromoteRequest(BaseModel):
    asset_ids: List[UUID] = Field(..., min_length=1, max_length=500)


@router.post("/programs/{program_id}/assets/promote-bulk")
async def promote_assets_bulk(
    program_id: UUID,
    request: BulkPromoteRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Same rule as promote_asset (scope check, type check, dedup) applied to
    many assets in one request/transaction -- a Recon tab with hundreds of
    suggestions otherwise means clicking "Promote" hundreds of times, and
    doing that many individual API calls back-to-back from the browser trips
    nginx's per-client rate limit (`zone=api rate=200r/m burst=50`) well
    before it finishes. Still exactly the same human-approval + scope gate as
    the single-asset endpoint, just batched."""
    program = await _get_program_or_404(db, program_id, workspace_id)
    scope_rules = program.scope_rules or []

    assets = (await db.execute(
        select(BountyAsset).where(
            BountyAsset.id.in_(request.asset_ids), BountyAsset.program_id == program_id,
        )
    )).scalars().all()
    assets_by_id = {a.id: a for a in assets}

    existing_values = set((await db.execute(
        select(BountyTarget.value).where(BountyTarget.program_id == program_id)
    )).scalars().all())

    promoted: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for asset_id in request.asset_ids:
        asset = assets_by_id.get(asset_id)
        if not asset:
            skipped.append({"asset_id": str(asset_id), "reason": "not_found"})
            continue
        if asset.promoted:
            skipped.append({"asset_id": str(asset_id), "value": asset.value, "reason": "already_promoted"})
            continue
        if asset.asset_type not in VALUE_TYPES.union({"subdomain"}):
            skipped.append({
                "asset_id": str(asset_id), "value": asset.value,
                "reason": f"not_a_target_shape:{asset.asset_type}",
            })
            continue
        if not is_target_in_scope(asset.value, scope_rules):
            skipped.append({"asset_id": str(asset_id), "value": asset.value, "reason": "out_of_scope"})
            continue
        if asset.value in existing_values:
            # A target with this exact value already exists (e.g. promoted
            # individually earlier) -- settle the asset's own flag either way
            # so it stops showing up as an unpromoted candidate.
            asset.promoted = True
            skipped.append({"asset_id": str(asset_id), "value": asset.value, "reason": "target_already_exists"})
            continue

        target_type = "domain" if asset.asset_type == "subdomain" else asset.asset_type
        target = BountyTarget(
            program_id=program_id, value=asset.value, target_type=target_type, added_by=current_user.id,
        )
        db.add(target)
        asset.promoted = True
        existing_values.add(asset.value)
        promoted.append({"asset_id": str(asset_id), "value": asset.value, "target_type": target_type})

    await db.commit()

    if promoted:
        bg.add_task(
            audit_log,
            workspace_id=str(workspace_id),
            user_id=str(current_user.id),
            action="bounty_asset.promote_bulk",
            resource_type="bounty_program",
            resource_id=str(program_id),
            changes={"promoted_count": len(promoted), "values": [p["value"] for p in promoted][:50]},
        )

    return {"promoted": len(promoted), "skipped": len(skipped), "details": {"promoted": promoted, "skipped": skipped}}


# ── Findings (ExploitAttempt) endpoints ──────────────────────

@router.get("/programs/{program_id}/findings")
async def list_findings(
    program_id: UUID,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    module: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List everything modules 6+ (nuclei so far) have confirmed against
    this program's approved targets."""
    await _get_program_or_404(db, program_id, workspace_id)

    query = select(ExploitAttempt).where(ExploitAttempt.program_id == program_id)
    if status_filter:
        query = query.where(ExploitAttempt.status == status_filter)
    if module:
        query = query.where(ExploitAttempt.module == module)
    if severity:
        query = query.where(ExploitAttempt.severity == severity)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    query = query.order_by(ExploitAttempt.executed_at.desc()).offset((page - 1) * page_size).limit(page_size)
    attempts = (await db.execute(query)).scalars().all()

    return {
        "items": [_attempt_to_dict(a) for a in attempts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


# ── Program summary + HTML report (classifier) ───────────────

# Findings from these modules come from the vulnscan stage (nuclei +
# detect.py's sensitive-file/CORS/403-bypass checks); everything else comes
# from the exploit stage. Used to scope "current" findings to the latest
# completed run of the stage that produced them -- see _gather_urls_findings.
_VULNSCAN_MODULES = {"nuclei", "exposure", "cors", "403bypass"}


def _stage_run_cutoff(stage_status: Optional[Dict[str, Any]], stage: str) -> Optional[datetime]:
    info = (stage_status or {}).get(stage) or {}
    if info.get("status") != "completed":
        return None
    started = info.get("started_at")
    if not started:
        return None
    try:
        return datetime.fromisoformat(started)
    except ValueError:
        return None


async def _gather_urls_findings(db: AsyncSession, program_id: UUID, stage_status: Optional[Dict[str, Any]] = None):
    finding_rows = (await db.execute(
        select(ExploitAttempt).where(ExploitAttempt.program_id == program_id)
    )).scalars().all()

    # A program can be tested many times over its life -- each run persists
    # new rows rather than replacing old ones (by design: it's an append-only
    # activity log, not just a snapshot). A report/summary should reflect the
    # *current* assessment though, so scope each finding to the latest
    # completed run of whichever stage produced it. A finding from a run that
    # predates a pipeline bugfix (a false positive that no longer reproduces)
    # is exactly what this excludes; `stage_status` missing/incomplete falls
    # back to "include everything" rather than risk hiding real findings.
    vulnscan_cutoff = _stage_run_cutoff(stage_status, "vulnscan")
    exploit_cutoff = _stage_run_cutoff(stage_status, "exploit")
    findings = []
    for f in finding_rows:
        cutoff = vulnscan_cutoff if f.module in _VULNSCAN_MODULES else exploit_cutoff
        if cutoff is not None and f.executed_at < cutoff:
            continue
        findings.append(_attempt_to_dict(f))

    asset_urls = list((await db.execute(
        select(BountyAsset.value).where(
            BountyAsset.program_id == program_id, BountyAsset.asset_type == "url",
        ).limit(5000)
    )).scalars().all())
    finding_urls = [
        (f.get("evidence") or {}).get("target_url") or (f.get("evidence") or {}).get("url")
        for f in findings
    ]
    urls = [u for u in asset_urls + finding_urls if u]
    return urls, findings


@router.get("/programs/{program_id}/summary")
async def program_summary(
    program_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Smart-classifier summary: severity/module counts + priority target
    buckets (IDOR/BAC/OAuth/upload/payment/webhook/debug/...) computed on
    demand from the program's recon URLs + findings from the latest run."""
    program = await _get_program_or_404(db, program_id, workspace_id)
    urls, findings = await _gather_urls_findings(db, program_id, program.stage_status)
    return classify_program(urls, findings)


@router.get("/programs/{program_id}/report.html", response_class=HTMLResponse)
async def program_report_html(
    program_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Standalone, self-contained HTML report for the whole program."""
    program = await _get_program_or_404(db, program_id, workspace_id)
    urls, findings = await _gather_urls_findings(db, program_id, program.stage_status)
    summary = classify_program(urls, findings)
    return HTMLResponse(content=render_html(_program_to_dict(program, target_count=None), findings, summary))


# ── Report endpoints ─────────────────────────────────────────

@router.get("/programs/{program_id}/reports")
async def list_reports(
    program_id: UUID,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List the submission-ready report drafts bounty.report generated."""
    await _get_program_or_404(db, program_id, workspace_id)
    query = select(BountyReport).where(BountyReport.program_id == program_id)
    if status_filter:
        query = query.where(BountyReport.status == status_filter)
    reports = (await db.execute(query.order_by(BountyReport.created_at.desc()))).scalars().all()
    return {"items": [_report_to_dict(r) for r in reports], "total": len(reports)}


@router.get("/programs/{program_id}/reports/{report_id}")
async def get_report(
    program_id: UUID,
    report_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """A single report, including a rendered Markdown document ready to paste
    into a HackerOne/Bugcrowd submission."""
    await _get_program_or_404(db, program_id, workspace_id)
    report = await _get_report_or_404(db, report_id, program_id)
    payload = _report_to_dict(report)
    payload["markdown"] = _render_report_markdown(report)
    return payload


@router.put("/programs/{program_id}/reports/{report_id}")
async def update_report(
    program_id: UUID,
    report_id: UUID,
    request: ReportUpdateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Edit a draft before submission, or advance its status
    (draft -> submitted -> triaged -> resolved -> paid)."""
    await _get_program_or_404(db, program_id, workspace_id)
    report = await _get_report_or_404(db, report_id, program_id)

    changes: Dict[str, Any] = {}
    for field, value in request.model_dump(exclude_none=True).items():
        if getattr(report, field) != value:
            changes[field] = value
            setattr(report, field, value)

    await db.commit()
    await db.refresh(report)

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_report.update",
        resource_type="bounty_report",
        resource_id=str(report_id),
        changes=changes,
    )

    return _report_to_dict(report)


@router.delete("/programs/{program_id}/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    program_id: UUID,
    report_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Discard a report draft."""
    await _get_program_or_404(db, program_id, workspace_id)
    report = await _get_report_or_404(db, report_id, program_id)
    await db.delete(report)
    await db.commit()

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="bounty_report.delete",
        resource_type="bounty_report",
        resource_id=str(report_id),
    )


# ── Helpers ───────────────────────────────────────────────────

async def _get_report_or_404(db: AsyncSession, report_id: UUID, program_id: UUID) -> BountyReport:
    report = (await db.execute(
        select(BountyReport).where(
            BountyReport.id == report_id,
            BountyReport.program_id == program_id,
        )
    )).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


def _report_to_dict(report: BountyReport) -> dict:
    return {
        "id": str(report.id),
        "program_id": str(report.program_id),
        "finding_ids": [str(fid) for fid in (report.finding_ids or [])],
        "title": report.title,
        "summary": report.summary,
        "steps_to_reproduce": report.steps_to_reproduce,
        "impact": report.impact,
        "remediation": report.remediation,
        "status": report.status,
        "format": report.format,
        "created_at": report.created_at.isoformat(),
        "updated_at": report.updated_at.isoformat(),
    }


def _render_report_markdown(report: BountyReport) -> str:
    """Assemble the stored report fields into one Markdown document, ready to
    paste into a HackerOne/Bugcrowd submission (mirrors the worker-side
    report_templates.render_markdown; kept here so the API has no worker dep)."""
    sections = [
        f"# {report.title or 'Untitled finding'}",
        "",
        "## Summary",
        report.summary or "",
        "",
        "## Steps to Reproduce",
        report.steps_to_reproduce or "",
        "",
        "## Impact",
        report.impact or "",
        "",
        "## Remediation",
        report.remediation or "",
    ]
    return "\n".join(sections).strip() + "\n"


async def _get_program_or_404(db: AsyncSession, program_id: UUID, workspace_id: UUID) -> BountyProgram:
    result = await db.execute(
        select(BountyProgram).where(
            BountyProgram.id == program_id,
            BountyProgram.workspace_id == workspace_id,
        )
    )
    program = result.scalar_one_or_none()
    if not program:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bounty program not found")
    return program


def _program_to_dict(program: BountyProgram, *, target_count: Optional[int]) -> dict:
    return {
        "id": str(program.id),
        "workspace_id": str(program.workspace_id),
        "name": program.name,
        "platform": program.platform,
        "status": program.status,
        "scope_rules": program.scope_rules or [],
        "rules_of_engagement": program.rules_of_engagement or {},
        "stage_status": program.stage_status or {},
        "target_count": target_count,
        "created_at": program.created_at.isoformat(),
        "updated_at": program.updated_at.isoformat(),
    }


def _asset_to_dict(asset: BountyAsset) -> dict:
    return {
        "id": str(asset.id),
        "program_id": str(asset.program_id),
        "value": asset.value,
        "asset_type": asset.asset_type,
        "source": asset.source,
        "promoted": asset.promoted,
        "metadata": asset.metadata_ or {},
        "discovered_at": asset.discovered_at.isoformat(),
    }


def _attempt_to_dict(attempt: ExploitAttempt) -> dict:
    return {
        "id": str(attempt.id),
        "program_id": str(attempt.program_id),
        "target_id": str(attempt.target_id),
        "module": attempt.module,
        "technique": attempt.technique,
        "severity": attempt.severity,
        "status": attempt.status,
        "evidence": attempt.evidence or {},
        "executed_at": attempt.executed_at.isoformat(),
        "executed_by": str(attempt.executed_by) if attempt.executed_by else None,
    }


def _target_to_dict(target: BountyTarget) -> dict:
    return {
        "id": str(target.id),
        "program_id": str(target.program_id),
        "value": target.value,
        "target_type": target.target_type,
        "added_by": str(target.added_by) if target.added_by else None,
        "created_at": target.created_at.isoformat(),
        "last_probed_at": target.last_probed_at.isoformat() if target.last_probed_at else None,
        "is_alive": target.is_alive,
        "probe_metadata": target.probe_metadata or {},
    }
