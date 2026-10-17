"""Deterministic, fail-closed evaluation of proposals and simulated evidence.

Evidence is supplied by the harness, not by the proposal provider. This module
only inspects values: it neither collects evidence nor authorizes execution.
"""

from datetime import datetime
import hashlib
import re

from pydantic import ConfigDict, TypeAdapter, ValidationError

from .models import (
    Decision,
    DecisionType,
    Finding,
    MANIFEST_PATHS,
    REPO_ID,
    ReasonCode,
    REQUIRED_CHECKS,
    SERVICE_ROOTS,
    Snapshot,
    proposal_digest,
)
from .schemas import EvidenceRecord, InputFiles, NonBlank, Proposal, Sha256

_TEXT = TypeAdapter(NonBlank, config=ConfigDict(strict=True))
_HASH = TypeAdapter(Sha256, config=ConfigDict(strict=True))
_INPUT_FILES = TypeAdapter(InputFiles, config=ConfigDict(strict=True))
_COMMIT = TypeAdapter(NonBlank | None, config=ConfigDict(strict=True))
_NUMERIC_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")


def _safe_service_path(path: str, service: str) -> bool:
    if (
        path.startswith("/")
        or re.match(r"^[A-Za-z]:", path)
        or "\\" in path
        or "\0" in path
    ):
        return False
    parts = path.split("/")
    if any(part in {"", ".", "..", ".git"} for part in parts):
        return False
    return path.startswith(SERVICE_ROOTS[service] + "/")


def _version(value: str) -> tuple[int, int, int] | None:
    if not _NUMERIC_VERSION.fullmatch(value):
        return None
    try:
        parts = [int(part) for part in value.split(".")]
    except ValueError:
        return None
    if len(parts) == 2:
        parts.append(0)
    return tuple(parts)


def _binding_mismatch(record: dict, snapshot: Snapshot, candidate_digest: str) -> bool:
    # Validate each binding independently: malformed unrelated evidence must not
    # hide a valid, explicit mismatch or change the REJECT-before-REVIEW order.
    for key, expected, adapter in (
        ("repo_id", snapshot.repo_id, _TEXT),
        ("source_commit", snapshot.source_commit, _COMMIT),
        ("input_digest", snapshot.input_digest, _HASH),
        ("input_files", snapshot.file_digests, _INPUT_FILES),
        ("proposal_digest", candidate_digest, _HASH),
    ):
        if key not in record:
            continue
        try:
            value = adapter.validate_python(record[key])
        except ValidationError:
            continue
        if value != expected:
            return True
    return False


def _requires_change_review(proposal: Proposal, record: dict) -> bool:
    current = _version(proposal.current_version)
    target = _version(proposal.target_version)
    if current is None or target is None:
        return True
    if current[0] == 0 or target[0] == 0 or current[0] != target[0]:
        return True
    if proposal.change_type != "dependency_version":
        return True
    if any(path != MANIFEST_PATHS[proposal.service] for path in proposal.files):
        return True
    for key, expected in (
        ("scope", "dependency_version_only"),
        ("compatibility", "confirmed"),
    ):
        value = record.get(key)
        if isinstance(value, str) and value.strip() and value != expected:
            return True
    return False


def _failed_check(record: dict) -> bool:
    checks = record.get("checks")
    if not isinstance(checks, dict):
        return False
    return any(
        isinstance(checks.get(name), dict) and checks[name].get("status") == "failed"
        for name in REQUIRED_CHECKS
    )


def _complete_evidence(
    record: EvidenceRecord,
    proposal: Proposal,
    finding: Finding,
    snapshot: Snapshot,
    candidate_digest: str,
) -> bool:
    expected = {
        "repo_id": snapshot.repo_id,
        "source_commit": snapshot.source_commit,
        "input_digest": snapshot.input_digest,
        "input_files": snapshot.file_digests,
        "proposal_digest": candidate_digest,
        "finding_id": finding.id,
        "cve": finding.cve,
        "package": finding.package,
        "current_version": proposal.current_version,
        "target_package": proposal.target_package,
        "target_version": proposal.target_version,
        "resolved_current_version": proposal.current_version,
        "resolved_target_version": proposal.target_version,
        "scope": "dependency_version_only",
        "compatibility": "confirmed",
    }
    if snapshot.repo_id != REPO_ID or any(
        getattr(record, key) != value for key, value in expected.items()
    ):
        return False
    if proposal.current_version != finding.installed_version:
        return False
    declaration = snapshot.declared_versions.get(
        finding.service + "|" + finding.package
    )
    if declaration is not None and declaration != proposal.current_version:
        return False
    advisory = record.advisory
    if (
        advisory.package != finding.package
        or advisory.cve != finding.cve
        or proposal.target_version not in advisory.fixed_versions
        or not advisory.snapshot_text.startswith("MOCK ")
    ):
        return False
    try:
        datetime.fromisoformat(advisory.retrieved_at.replace("Z", "+00:00"))
        digest = hashlib.sha256(advisory.snapshot_text.encode("utf-8")).hexdigest()
    except (ValueError, UnicodeError):
        return False
    if advisory.sha256 != digest:
        return False
    for name in REQUIRED_CHECKS:
        check = getattr(record.checks, name)
        if check.status != "passed":
            return False
        if not check.command.startswith("MOCK: ") or not check.command[6:].strip():
            return False
        if (
            not check.tool_version.startswith("MOCK ")
            or not check.tool_version[5:].strip()
        ):
            return False
    return not record.excluded_tests or record.equivalent_coverage


def evaluate(
    proposal: object,
    finding: Finding | None,
    snapshot: Snapshot,
    evidence: dict[str, object],
) -> Decision:
    """Return the first ADR004 rule matching this declarative candidate.

    An ACCEPT represents simulated eligibility only. The caller must keep the
    independently controlled evidence map separate from model output.
    """
    finding_id = finding.id if finding is not None else None
    candidate_digest = None

    def result(decision: DecisionType, code: ReasonCode, reason: str) -> Decision:
        return Decision(finding_id, decision, (code,), (reason,), candidate_digest)

    if not isinstance(proposal, dict):
        return result(
            DecisionType.REJECT,
            ReasonCode.INVALID_PROPOSAL,
            "Required proposal fields are missing or malformed.",
        )
    try:
        candidate = Proposal.model_validate(proposal)
    except ValidationError:
        return result(
            DecisionType.REJECT,
            ReasonCode.INVALID_PROPOSAL,
            "Required proposal fields are missing or malformed.",
        )
    # finding_id stays the scanner finding's ID: the proposal's claimed ID is
    # untrusted and only checked against it below, never copied into the result.
    # Hash the original fields, never a normalized/default-expanded model dump.
    candidate_digest = proposal_digest(proposal)
    if (
        finding is None
        or snapshot.repo_id != REPO_ID
        or candidate.finding_id != finding.id
        or candidate.service != finding.service
        or candidate.package != finding.package
        or finding.service not in SERVICE_ROOTS
        or any(
            not _safe_service_path(path, finding.service) for path in candidate.files
        )
        or (
            candidate.target_package != finding.package
            and candidate.change_type != "package_migration"
        )
    ):
        return result(
            DecisionType.REJECT,
            ReasonCode.OUT_OF_SCOPE,
            "The finding, repository, package, or affected paths are outside the allowed scope.",
        )
    if any(action != "update_dependency" for action in candidate.actions):
        return result(
            DecisionType.REJECT,
            ReasonCode.PROHIBITED_ACTION,
            "The proposal requests a prohibited action.",
        )
    record = (
        evidence.get(candidate.evidence_id)
        if candidate.evidence_id is not None and isinstance(evidence, dict)
        else None
    )
    if not isinstance(record, dict):
        record = {}
    if _binding_mismatch(record, snapshot, candidate_digest):
        return result(
            DecisionType.REJECT,
            ReasonCode.EVIDENCE_BINDING_MISMATCH,
            "The supplied evidence explicitly belongs to another snapshot or candidate.",
        )
    current = _version(candidate.current_version)
    target = _version(candidate.target_version)
    if (
        candidate.package == candidate.target_package
        and current is not None
        and target is not None
        and target <= current
    ):
        return result(
            DecisionType.REJECT,
            ReasonCode.NOT_AN_UPGRADE,
            "The target version is not newer than the current version of the same package.",
        )
    if _requires_change_review(candidate, record):
        return result(
            DecisionType.REVIEW,
            ReasonCode.CHANGE_REQUIRES_REVIEW,
            "The change is outside stable same-major dependency-only eligibility or compatibility is not confirmed.",
        )
    # Inspect failed statuses before whole-record validation; missing metadata
    # must not downgrade a known failure to merely insufficient evidence.
    if _failed_check(record):
        return result(
            DecisionType.REVIEW,
            ReasonCode.VALIDATION_FAILED,
            "An independently recorded required candidate check failed.",
        )
    try:
        validated_record = EvidenceRecord.model_validate(record)
    except ValidationError:
        return result(
            DecisionType.REVIEW,
            ReasonCode.EVIDENCE_INSUFFICIENT,
            "Independent simulated candidate, dependency, fix, or validation evidence is missing, malformed, or contradictory.",
        )
    if not _complete_evidence(
        validated_record, candidate, finding, snapshot, candidate_digest
    ):
        return result(
            DecisionType.REVIEW,
            ReasonCode.EVIDENCE_INSUFFICIENT,
            "Independent simulated candidate, dependency, fix, or validation evidence is missing, malformed, or contradictory.",
        )
    return result(
        DecisionType.ACCEPT,
        ReasonCode.LOW_RISK_CRITERIA_MET,
        "Low-risk eligibility and all independent simulated evidence requirements are satisfied; no execution is authorized.",
    )
