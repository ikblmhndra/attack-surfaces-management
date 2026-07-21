"""
ASM Platform — Worker DB Models
Lightweight mirror of backend models for use in worker processes.
Imports directly from the backend models package.
"""
import sys
import os

# Allow workers to import backend models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.db.models.models import (
    Base,
    Workspace,
    User,
    APIKey,
    AuditLog,
    Organization,
    Asset,
    Subdomain,
    IPAddress,
    Port,
    Technology,
    Finding,
    RiskScore,
    ExploitIntel,
    EolIntel,
    VersionCveCache,
    Scan,
    ScanFinding,
    ScanPhaseRun,
    ScanTargetSelection,
    DiscoveredAsset,
    OutboxEvent,
    NotificationRule,
    Notification,
    Screenshot,
    WebEndpoint,
    ThreatIntel,
    AssetRelationship,
)
from app.db.models.bounty_models import (
    BountyProgram,
    BountyTarget,
    BountyAsset,
    ExploitAttempt,
    BountyReport,
)

__all__ = [
    "Base", "Workspace", "User", "APIKey", "AuditLog",
    "Organization", "Asset", "Subdomain", "IPAddress", "Port",
    "Technology", "Finding", "RiskScore", "ExploitIntel", "EolIntel", "VersionCveCache", "Scan", "ScanFinding", "ScanPhaseRun",
    "ScanTargetSelection", "DiscoveredAsset", "OutboxEvent",
    "NotificationRule", "Notification", "Screenshot", "ThreatIntel",
    "WebEndpoint", "AssetRelationship",
    "BountyProgram", "BountyTarget", "BountyAsset", "ExploitAttempt", "BountyReport",
]
