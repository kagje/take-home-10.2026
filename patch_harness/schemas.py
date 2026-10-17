"""Structural contracts for untrusted data; authorization stays in policy.py."""

from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .models import SERVICE_ROOTS


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("Expected non-blank text")
    return value  # Preserve spelling and whitespace: candidate hashes bind raw values.


def _unique_strings(values: list[str]) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError("Duplicate entries are unsupported")
    return values


NonBlank = Annotated[str, Field(min_length=1), AfterValidator(_not_blank)]
UniqueStrings = Annotated[list[NonBlank], AfterValidator(_unique_strings)]
Sha256 = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]
InputFiles = Annotated[dict[NonBlank, Sha256], Field(min_length=1)]
ChangeType = Literal[
    "dependency_version", "framework_upgrade", "package_migration", "source_change"
]
Action = Literal[
    "update_dependency",
    "suppress_tests",
    "auto_merge",
    "deploy",
    "run_command",
    "read_secrets",
    "modify_policy",
    "modify_ci",
    "bypass_approval",
]


class _Record(BaseModel):
    # Extra metadata in scanner/validator records was historically ignored.
    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)


class FindingRecord(_Record):
    id: NonBlank
    cve: Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
    severity: NonBlank
    service: NonBlank
    package: NonBlank
    installed_version: NonBlank
    fixed_version: NonBlank | None
    notes: str = ""

    @field_validator("service")
    @classmethod
    def supported_service(cls, value: str) -> str:
        if value not in SERVICE_ROOTS:
            raise ValueError("Unsupported service")
        return value


class FindingsDocument(_Record):
    scanner: NonBlank
    generated: NonBlank
    findings: list[FindingRecord]

    @model_validator(mode="after")
    def unique_finding_ids(self) -> Self:
        ids = [finding.id for finding in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate finding IDs")
        return self


class Proposal(_Record):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    finding_id: NonBlank
    service: NonBlank
    package: NonBlank
    current_version: NonBlank
    target_version: NonBlank
    target_package: NonBlank
    change_type: ChangeType
    files: Annotated[UniqueStrings, Field(min_length=1)]
    actions: Annotated[list[Action], AfterValidator(_unique_strings)]
    description: NonBlank
    evidence_id: NonBlank | None  # Required key; null explicitly means no reference.


class CheckRecord(_Record):
    status: Literal["passed", "failed", "not_run"]
    command: NonBlank
    tool_version: NonBlank


class RequiredChecks(_Record):
    dependency_resolution: CheckRecord
    tests: CheckRecord
    security_compatibility: CheckRecord
    change_scope: CheckRecord


class AdvisoryRecord(_Record):
    package: NonBlank
    cve: NonBlank
    fixed_versions: Annotated[UniqueStrings, Field(min_length=1)]
    source_url: NonBlank
    retrieved_at: NonBlank
    snapshot_text: NonBlank
    sha256: Sha256


class EvidenceRecord(_Record):
    mode: Literal["simulated"]
    issuer: Literal["fixture-validator"]
    repo_id: NonBlank
    source_commit: NonBlank | None
    input_digest: Sha256
    input_files: InputFiles
    proposal_digest: Sha256
    finding_id: NonBlank
    cve: NonBlank
    package: NonBlank
    current_version: NonBlank
    target_package: NonBlank
    target_version: NonBlank
    resolved_current_version: NonBlank
    resolved_target_version: NonBlank
    scope: NonBlank
    compatibility: NonBlank
    advisory: AdvisoryRecord
    checks: RequiredChecks
    excluded_tests: UniqueStrings
    equivalent_coverage: bool
