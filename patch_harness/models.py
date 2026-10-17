"""Data crossing the loader, provider, and policy boundaries."""

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
from typing import Any

REPO_ID = "takehome-assignment-bot/homework"
POLICY_VERSION = "004-v1"
SERVICE_ROOTS = {
    "inventory-api": "services/inventory-api",
    "report-worker": "services/report-worker",
}
MANIFEST_PATHS = {
    "inventory-api": "services/inventory-api/pom.xml",
    "report-worker": "services/report-worker/requirements.lock",
}
REQUIRED_CHECKS = (
    "dependency_resolution",
    "tests",
    "security_compatibility",
    "change_scope",
)


class InputError(ValueError):
    """Input cannot safely be loaded; no proposal decision can be made."""


@dataclass(frozen=True)
class Finding:
    id: str
    cve: str
    severity: str
    service: str
    package: str
    installed_version: str
    fixed_version: str | None
    notes: str = ""


@dataclass(frozen=True)
class Snapshot:
    root: Path
    repo_id: str
    source_commit: str | None
    input_digest: str
    file_digests: dict[str, str]
    declared_versions: dict[str, str]


class DecisionType(StrEnum):
    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    REJECT = "REJECT"


class ReasonCode(StrEnum):
    INVALID_PROPOSAL = "INVALID_PROPOSAL"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    PROHIBITED_ACTION = "PROHIBITED_ACTION"
    EVIDENCE_BINDING_MISMATCH = "EVIDENCE_BINDING_MISMATCH"
    NOT_AN_UPGRADE = "NOT_AN_UPGRADE"
    CHANGE_REQUIRES_REVIEW = "CHANGE_REQUIRES_REVIEW"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    LOW_RISK_CRITERIA_MET = "LOW_RISK_CRITERIA_MET"


@dataclass(frozen=True)
class Decision:
    finding_id: str | None
    decision: DecisionType
    reason_codes: tuple[ReasonCode, ...]
    reasons: tuple[str, ...]
    proposal_digest: str | None = None


def digest_json(value: Any) -> str:
    """Stable SHA-256 of JSON data, independent of object key order."""
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def proposal_digest(proposal: dict[str, Any]) -> str:
    """Bind the complete declarative candidate, excluding its evidence locator."""
    return digest_json(
        {key: value for key, value in proposal.items() if key != "evidence_id"}
    )
