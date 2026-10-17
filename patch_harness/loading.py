"""Read the exercise layout as data; never run repository code or instructions."""

import hashlib
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from typing import Any

from pydantic import ValidationError

from .models import Finding, InputError, REPO_ID, SERVICE_ROOTS, Snapshot, digest_json
from .schemas import FindingsDocument

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_FILES = 1000
GENERATED_DIRS = {"target", "__pycache__", ".pytest_cache", ".venv"}
SOURCE_SUFFIXES = {
    ".py",
    ".java",
    ".xml",
    ".toml",
    ".lock",
    ".yaml",
    ".yml",
    ".json",
    ".properties",
}
REQUIRED_FILES = (
    "findings/findings.json",
    "services/inventory-api/pom.xml",
    "services/report-worker/requirements.lock",
    "services/report-worker/pyproject.toml",
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise InputError(f"Invalid JSON constant: {value}")


def load_json(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise InputError(f"JSON file exceeds {MAX_FILE_BYTES} bytes: {path.name}")
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise InputError(f"Cannot load {path.name}: {exc}") from exc


def _read_file(root: Path, relative: str) -> bytes:
    path = root / relative
    try:
        if not path.resolve().is_relative_to(root):
            raise InputError(f"File escapes repository: {relative}")
        # Reject aliases as well as escapes: one logical path must name one input.
        if any(
            parent.is_symlink()
            for parent in (path, *path.parents)
            if parent != root and parent.is_relative_to(root)
        ):
            raise InputError(f"Symlink inputs are unsupported: {relative}")
        if not path.is_file():
            raise InputError(f"Required input is not a file: {relative}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise InputError(f"Input file exceeds {MAX_FILE_BYTES} bytes: {relative}")
        return path.read_bytes()
    except (OSError, RuntimeError) as exc:
        raise InputError(f"Cannot read repository input: {relative}") from exc


def _source_files(root: Path) -> dict[str, bytes]:
    files = {name: _read_file(root, name) for name in REQUIRED_FILES}

    def walk_error(error: OSError) -> None:
        raise InputError("Cannot enumerate service inputs") from error

    for service_root in SERVICE_ROOTS.values():
        for directory, dirs, names in os.walk(
            root / service_root, followlinks=False, onerror=walk_error
        ):
            directory_path = Path(directory)
            dirs[:] = sorted(
                name
                for name in dirs
                if name not in GENERATED_DIRS and not name.startswith(".")
            )
            for name in dirs:
                child = directory_path / name
                if child.is_symlink():
                    raise InputError(
                        f"Symlink directories are unsupported: {child.relative_to(root).as_posix()}"
                    )
            for name in sorted(names):
                path = directory_path / name
                if name.startswith(".") or path.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                relative = path.relative_to(root).as_posix()
                if relative not in files:
                    files[relative] = _read_file(root, relative)
                if len(files) > MAX_SOURCE_FILES:
                    raise InputError(
                        f"Repository exceeds {MAX_SOURCE_FILES} source files"
                    )
    return dict(sorted(files.items()))


def _findings(data: Any) -> list[Finding]:
    try:
        document = FindingsDocument.model_validate(data)
    except ValidationError as exc:
        error = exc.errors(include_input=False, include_url=False)[0]
        location = ".".join(str(part) for part in error["loc"]) or "document"
        raise InputError(f"Invalid findings at {location}: {error['msg']}") from exc
    findings = [Finding(**record.model_dump()) for record in document.findings]
    return sorted(findings, key=lambda finding: finding.id)


def _declarations(files: dict[str, bytes]) -> dict[str, str]:
    try:
        pom = files["services/inventory-api/pom.xml"].decode("utf-8")
    except UnicodeError as exc:
        raise InputError("Inventory manifest must use UTF-8") from exc
    if "<!DOCTYPE" in pom.upper() or "<!ENTITY" in pom.upper() or "\0" in pom:
        raise InputError(
            "XML declarations with DTDs/entities or NUL bytes are unsupported"
        )
    try:
        project = ET.fromstring(pom)
    except ET.ParseError as exc:
        raise InputError("Malformed inventory-api POM") from exc
    namespace = (
        project.tag.partition("}")[0] + "}" if project.tag.startswith("{") else ""
    )
    if project.tag != namespace + "project":
        raise InputError("Inventory manifest must be a Maven project")
    versions: dict[str, str] = {}
    for dependency in project.findall(f"{namespace}dependencies/{namespace}dependency"):
        group = dependency.findtext(namespace + "groupId")
        artifact = dependency.findtext(namespace + "artifactId")
        version = dependency.findtext(namespace + "version")
        if group and artifact and version:
            key = f"inventory-api|{group.strip()}:{artifact.strip()}"
            if key in versions:
                raise InputError("Duplicate direct dependency in POM")
            versions[key] = version.strip()
    try:
        lock = files["services/report-worker/requirements.lock"].decode("utf-8")
        import tomllib

        project_config = tomllib.loads(
            files["services/report-worker/pyproject.toml"].decode("utf-8")
        )
        if not isinstance(project_config.get("project"), dict):
            raise InputError("Worker pyproject must contain a project table")
    except (UnicodeError, ValueError) as exc:
        raise InputError("Malformed worker manifest or lockfile") from exc
    for line in lock.splitlines():
        match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)==([^\s;#]+)\s*(?:#.*)?", line)
        if match:
            package, version = match.groups()
            # Scanner coordinates use this spelling; Python names are case-insensitive.
            package = "PyYAML" if package.lower() == "pyyaml" else package
            key = f"report-worker|{package}"
            if key in versions:
                raise InputError("Duplicate pinned dependency in worker lockfile")
            versions[key] = version
    return versions


_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_BRANCH_REF = re.compile(r"refs/heads/[A-Za-z0-9._/-]+")


def _git_text(root: Path, relative: str) -> str | None:
    # Same escape/symlink/size checks as other inputs; any problem means "unknown".
    if not (root / relative).is_file():
        return None
    try:
        return _read_file(root, relative).decode("ascii")
    except (InputError, UnicodeError):
        return None


def _commit(root: Path) -> str | None:
    """Read HEAD as plain files. No git process is started.

    Supports a detached HEAD and a branch ref (loose or packed). Anything else,
    such as a linked worktree, reports an unknown commit. The commit is metadata:
    a checkout can write any value here, so content hashes remain the binding.
    """
    if not (root / ".git").is_dir():
        return None
    head = _git_text(root, ".git/HEAD")
    if head is None:
        return None
    head = head.strip()
    if _OBJECT_ID.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    if not _BRANCH_REF.fullmatch(ref) or any(
        part in {"", ".", ".."} for part in ref.split("/")
    ):
        return None
    loose = _git_text(root, ".git/" + ref)
    if loose is not None:
        commit = loose.strip()
        return commit if _OBJECT_ID.fullmatch(commit) else None
    packed = _git_text(root, ".git/packed-refs")
    for line in (packed or "").splitlines():
        if line.startswith(("#", "^")):
            continue
        commit, _, name = line.partition(" ")
        if name.strip() == ref:
            return commit if _OBJECT_ID.fullmatch(commit) else None
    return None


def load_repository(root: Path) -> tuple[Snapshot, list[Finding]]:
    if "://" in str(root):
        raise InputError("--repo-root must be a local directory, not a URL")
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InputError("Repository root does not exist") from exc
    if not root.is_dir():
        raise InputError("Repository root must be a directory")
    files = _source_files(root)
    try:
        data = json.loads(
            files["findings/findings.json"].decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputError("Malformed findings JSON") from exc
    findings = _findings(data)
    versions = _declarations(files)
    hashes = {
        name: hashlib.sha256(content).hexdigest() for name, content in files.items()
    }
    snapshot = Snapshot(
        root=root,
        repo_id=REPO_ID,
        source_commit=_commit(root),
        input_digest=digest_json(hashes),
        file_digests=hashes,
        declared_versions=versions,
    )
    return snapshot, findings
