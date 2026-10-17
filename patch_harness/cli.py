"""Evaluate local input against harness-owned simulation fixtures."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .loading import load_json, load_repository
from .models import InputError, POLICY_VERSION, digest_json
from .policy import evaluate
from .providers import FixtureProposalProvider, ProposalProvider

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InputError(message)


def _validation_evidence_reference(
    proposal: object, evidence: dict[str, object]
) -> dict[str, str | None]:
    # Identify the requested record even when policy rejects before consulting it.
    # A digest is a content reference, not a claim that the record is valid/trusted.
    record_id = proposal.get("evidence_id") if isinstance(proposal, dict) else None
    if not isinstance(record_id, str) or not record_id.strip():
        record_id = None
    record_digest = None
    if record_id is not None and record_id in evidence:
        record_digest = "sha256:" + digest_json(evidence[record_id])
    return {"record_id": record_id, "record_digest": record_digest}


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        description="Evaluate simulated vulnerability proposals offline; never apply changes."
    )
    parser.add_argument(
        "--repo-root",
        required=True,
        help="Local checkout with the exercise layout (not a URL)",
    )
    try:
        args = parser.parse_args(argv)
        if "://" in args.repo_root:
            raise InputError("--repo-root must be a local directory, not a URL")
        snapshot, findings = load_repository(Path(args.repo_root))
        proposals = load_json(FIXTURE_ROOT / "proposals.json")
        evidence = load_json(FIXTURE_ROOT / "evidence.json")
        if not isinstance(proposals, dict) or not isinstance(evidence, dict):
            raise InputError("Harness fixture bundles must be JSON objects")
        try:
            evidence_bundle_digest = "sha256:" + digest_json(evidence)
        except (ValueError, RecursionError) as exc:
            raise InputError(
                "Evidence bundle must be canonicalizable finite JSON"
            ) from exc
        provider: ProposalProvider = FixtureProposalProvider(proposals)
        decisions = []
        for finding in findings:
            proposal = provider.propose(finding)
            decision = evaluate(proposal, finding, snapshot, evidence)
            decisions.append(
                {
                    **asdict(decision),
                    "cve": finding.cve,
                    "service": finding.service,
                    "package": finding.package,
                    "validation_evidence": _validation_evidence_reference(
                        proposal, evidence
                    ),
                }
            )
        report = {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "evidence_mode": "simulated",
            "execution_authorized": False,
            "proposal_provider": "fixture",
            "evidence_bundle": {
                "digest": evidence_bundle_digest,
                "canonicalization": "python-json-v1",
            },
            "repository": {
                "id": snapshot.repo_id,
                "source_commit": snapshot.source_commit,
                "input_digest": snapshot.input_digest,
                "input_files": snapshot.file_digests,
            },
            "decisions": decisions,
        }
        print(
            json.dumps(
                report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
            )
        )
        return 0
    except InputError as exc:
        print(
            json.dumps(
                {"error": {"code": "INPUT_ERROR", "message": str(exc)}}, sort_keys=True
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
