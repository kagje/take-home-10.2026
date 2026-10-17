# Auditor evidence example

[Mock production attestation](mock-production-attestation.json) illustrates the evidence chain for **CVE-2020-14343 in report-worker**, with a fictional remediation observation at **2026-10-17 09:10 UTC**.

**This is not production evidence.** `payload.evidence_mode` is `simulated`, `is_production_evidence` is false, `production_remediation_status` is `NOT_VERIFIED`, and `execution_authorized` is false. All event dates, issuers, approvals, builds, deployments, and runtime observations are fictional. PyYAML 5.4 is an assumed fix, not an independently verified advisory conclusion.

The harness does not produce, ingest, sign, or execute this artifact. It is deliberately separate from `fixtures/evidence.json`, which supplies mock candidate-validation inputs to the evaluator. The shared proposal digest references that demonstration, not a real change or deployment.

Harness evaluation reports separately identify the validation bundle with `evidence_bundle.digest` and requested records with `validation_evidence.record_id` / `record_digest`. Retain the bundle version matching those SHA-256 addresses, not whichever file currently occupies the fixture path. Recompute both digests under the [documented canonicalization](../DESIGN.md#audit-output-and-production-proof) before reproducing a decision. Record presence or hash equality is not validation, trust, or a signature.

## What the structure demonstrates

| Evidence | What an auditor would independently corroborate |
|---|---|
| Proposal | Finding/CVE, original and target package versions, exact candidate-plan digest, and source repository. Recompute the plan digest from `fixtures/proposals.json` excluding only `evidence_id`, using the harness's canonical JSON rules. |
| Validation and build | A trusted validator checked the exact candidate source and plan. Signed build provenance links that source to the image digest; dependency/SBOM evidence links the image to the target version. Required test/security/compatibility and scope checks passed without unaccounted exclusions. |
| Policy | Retrieve the digest-matching validation bundle and selected record from the evaluation report, verify both content addresses, and reproduce the decision under the recorded policy implementation/version using independently controlled evidence. ACCEPT is not merge or deployment approval. |
| Merge approval and merge | Retrieve authenticated approval and source-control records. Approval identifies the human, operation, repository, branch, candidate commit, and plan. The merged source must match validation. This example uses fast-forward merge; a changed merge result requires renewed validation. |
| Deployment approval and deployment | A separate human approval covers the exact image digest, service, clusters, and production environment. The deployment controller actually rolled out that digest, not merely a mutable tag or a desired configuration. |
| Runtime verification | An independent inventory source observed running instances after rollout across the entire declared scope. All instances use the SBOM-validated new image, none use the vulnerable image, and no source is unreachable or omitted. A successful deployment is insufficient by itself. |
| Attestation integrity | Authenticate the event issuers and the assembled payload against an independently maintained trust policy. Retain immutable evidence and verify signatures, identity authorization, timestamps, references, and content digests. An issuer string or checksum alone proves none of this. |

The vulnerable and new images each have a digest-bound example SBOM. The old SBOM attributes PyYAML 5.3.1 to the old image; the new one attributes the assumed target to the new image. In a real assessment, independently corroborate the CVE's affected/fixed versions against maintainer/security advisories and verify the inventories were actually derived from those images.

## Claim scope and time

The example covers only report-worker in `mock-production`, across `mock-cluster-a` and `mock-cluster-b`. It accounts for three expected and three observed running instances. The claimed remediation time is the runtime observation at 09:10, not the rollout completion at 09:00. The attestation is issued at 09:12 with a five-minute maximum inventory age at issuance.

This is a point-in-time claim within an explicit scope, not proof that every repository or environment is remediated forever. For current-state assurance, obtain a new inventory and reconcile later rollbacks, scaling, and deployments. Authenticated historical snapshots can support a historical date; they do not establish today's runtime state.

Missing approvals, failing checks, inconsistent source/image bindings, an unverified advisory, incomplete inventory, unknown images, or stale observations must leave remediation **NOT VERIFIED** and trigger investigation. An inventory query failure is not evidence of zero vulnerable instances. Merely excluding one known old digest is insufficient if other running image digests have not been assessed.

## Mock identities and integrity

- `mock://` issuers/references and `.invalid` registry/advisory hosts are fictional, not external resources to access.
- `mock_candidate_commit` is a synthetic 40-character identifier; `candidate_commit_exists` is explicitly false. The real baseline commit is not represented as a fixed commit.
- Image digests hash the included `mock_digest_input` text, **not real OCI image bytes**. SBOM digests hash their inline mock `content` objects; those objects are simplified examples, not claimed SPDX/CycloneDX documents.
- `integrity.payload_digest` hashes the entire `payload` using the stated canonicalization. It detects accidental inconsistency, not an attacker who can replace both content and checksum.
- `signatures` is empty and authentication is `UNSIGNED_MOCK`. A real system would use authenticated event records and a DSSE/in-toto-style signed envelope with independently trusted issuer keys. No working signer or production verifier is claimed.

You can check JSON syntax offline:

```bash
uv run --locked --offline python -m json.tool evidence/mock-production-attestation.json
```

During development, a throwaway offline consistency check verified payload/image/SBOM digests, event references, source bindings, approval scopes, timestamp order, and inventory completeness/freshness. It detected five deliberately inconsistent variants: wrong deployment image, missing merge approval, stale inventory, missing instance, and an old image still running. This checked the example's internal consistency only; real production remediation remains **NOT VERIFIED**.
