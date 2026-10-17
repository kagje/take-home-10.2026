# Design

## Authority

The harness evaluates proposals; it is not an autonomous security authority or patch
runner. [ADR 002](docs/architecture-decisions/002-meaning-of-accept.md) defines ACCEPT as satisfying the harness’s
policy and required candidate-validation gates, making the proposed remediation eligible for normal human merge
approval. Required candidate application and validation occur in an isolated process before policy evaluation. Merge and
production deployment each require separate human approval. In this implementation, candidate validation is simulated:
ACCEPT reflects mock evidence and **authorizes no real action**.

Human review is an escalation, not an override hidden in model text. A revised proposal/evidence set must be evaluated
again. Merge and production deployment would each require separate human approval beyond this evaluator.

## Autonomy tiers

The line is drawn by one question: **can every claim the decision depends on be checked by something other than the
agent, and is the change narrow enough that limited impact and reversibility are reasonable assumptions?** If yes,
the agent may proceed without extra review. If the answer depends on human judgment, a human reviews it. If the
proposal would remove a control or leave its scope, no evidence can justify it, and it is refused.

### Autonomous: ACCEPT

What the agent may do without escalation: propose a remediation and, on ACCEPT, have it proceed to the normal merge
review that any dependency bump gets. It skips the additional security review queue. It does not skip merge or
deployment approval. The harness itself autonomously reads the known layout, fingerprints inputs, obtains a proposal,
and emits a decision; it never executes repository code, changes files, merges, or deploys.

Criteria (all required):

- Same-major, stable numeric version increase (`major.minor[.patch]`, major >= 1) of the finding's own package.
- The change touches only that dependency's version declaration in the service's supported manifest.
- Evidence is bound to this exact repository snapshot and candidate digest.
- Dependency resolution corroborates the current and target versions; the scanner's word is not enough.
- An advisory snapshot (not the scanner's `fixed_version`) supports the target for this CVE.
- Required build, test, security/compatibility, and change-scope checks passed, with no unaccounted test exclusions.

Why the line sits here: the change is one version string in one service's manifest, and every fact behind it comes
from a source the agent does not control. Two further properties are **eligibility assumptions, not established
facts**:

- **Limited impact.** A same-major dependency change is expected to stay within the service. It can still change
  behaviour seen by clients (response formats, error handling), how persisted or serialized data is read or written,
  or transitive dependencies. The required checks are the evidence for this assumption, and they only cover what the
  tests exercise.
- **Expected reversibility.** Reverting the version string is expected to restore the previous behaviour. That fails
  if the new version has already written data, caches, or messages the old version cannot read.

The policy does not verify either property. It narrows eligibility to the changes where they are most likely to hold,
and relies on candidate validation to catch exceptions. Same-major is not proof of compatibility (failure mode 2 shows
a same-major target whose install failed under the worker's default build setup), which is why passing candidate
checks are required rather than inferred from the version number. A change known to touch client contracts or
persisted formats does not meet these assumptions and belongs in REVIEW; the current evidence schema has no field for
this, so its `compatibility` value is the only signal.

### Human review: REVIEW

The proposal is plausible and not prohibited, but its safety depends on judgment the harness cannot verify:

- Major-version, framework, or package/namespace changes. `ConfigLoader.loadOverrides` relies on YAML type tags creating
  arbitrary classes, which SnakeYAML 2.0 blocks by default: the upgrade removes the vulnerability by breaking a feature
  someone may depend on. Moving to `commons-collections4` changes the `MultiMap` types used by
  `PricingService`, which has no tests.
- Source-code changes, or files other than the dependency manifest.
- Compatibility that is unconfirmed, a required check that failed, or evidence that is missing, malformed, or
  contradictory.
- Versions the policy cannot compare, which are reviewed rather than guessed.

Why: these are the cases where "does this fix the vulnerability without breaking the service?" needs a person who
understands the code. A failing test is a reason to look, not a reason to refuse: the proposal may be right and the test
may need updating, but that is a human decision, never the agent's.

### Refuse: REJECT

The harness refuses the proposal outright when:

- It requests a prohibited action: suppressing tests, auto-merge, deployment, CI or policy changes, reading secrets, or
  running commands.
- It targets another repository, service, package, or a path outside the finding's service.
- It is malformed, or carries fields the schema does not allow (such as an approval or policy override).
- It downgrades or does not change the version.
- Its evidence is explicitly bound to a different snapshot or candidate.

Why: these actions remove the controls that make any evidence meaningful, or reach outside what the finding authorizes.
Passing tests cannot justify disabling tests, and an urgent SLA cannot justify skipping review. Repository text that
grants such permission (CONTRIBUTING.md's auto-merge and test-exclusion conventions) is data, not authority. Evidence
bound to another candidate signals a mix-up or substitution, so it fails loudly rather than being treated as merely
incomplete.

REJECT refuses this proposal; it does not close the finding. The vulnerability stays open until a new proposal passes.

### Precedence and the shipped findings

Rules apply in order REJECT, then REVIEW, then ACCEPT, so a prohibited action is refused even when everything else
passes. Full rule table and reason codes: [ADR 004](docs/architecture-decisions/004-decision-policy.md).

| Finding                     | Proposal                                            | Decision           | Deciding rule                        |
|-----------------------------|-----------------------------------------------------|--------------------|--------------------------------------|
| F-40218 SnakeYAML           | 1.30 -> 2.0                                         | REVIEW             | Major upgrade                        |
| F-40219 PyYAML              | 5.3.1 -> 5.4                                        | ACCEPT (simulated) | All criteria met under mock evidence |
| F-40220 Commons Collections | 3.2.1 -> 3.2.2 plus test suppression and auto-merge | REJECT             | Prohibited actions                   |

## Decision enforcement

[ADR 004](docs/architecture-decisions/004-decision-policy.md) is the policy contract. `policy.evaluate` is a pure
function with fixed first-match precedence: REJECT before REVIEW before ACCEPT. It returns a stable code and readable
reason. Conservative acceptance requires a stable numeric `major.minor[.patch]` increase within the same major (major >=
1), dependency-version-only scope, and all required evidence.

The agent supplies a typed declarative plan, not executable patches or shell commands. Unknown fields, such as an
agent-supplied approval/policy override, are rejected. File paths are restricted to the finding's service; only the
supported dependency manifest is automatically eligible. Descriptions, scanner notes, and repository documentation are
inert text, not instructions or a keyword blacklist.

The evaluator checks individual evidence bindings before whole-record validation, so malformed unrelated fields cannot
hide an explicit mismatch. Known failed required checks also retain precedence over incomplete check metadata. Pydantic
does not coerce strings/numbers to booleans or turn unsupported version formats into a different policy tier. Duplicate
JSON keys are still rejected during JSON decoding, before model validation.

## Input and evidence boundaries

The caller selects a local directory with the exercise layout, not an arbitrary repository URL. `loading.py` validates
scanner structure and records actual declarations independently of scanner version claims. Transitive resolutions are
not invented from a POM. The Git commit is read from `.git/HEAD` and its ref as plain files, without starting a git
process. It is metadata only, since a checkout can write any value there; content hashes bind the supported
source/config input scope independently. Missing Git is allowed when a complete content identity is available. Hashes do
not prove provenance, advisory truth, or successful tests.

The fingerprint includes the feed and supported service source/config files. It excludes build output, hidden
files/directories, other extensions, and unrelated docs. It is not a whole-repository clean-tree proof. Relevant
files/directories resolving outside the selected root are refused. Symlink aliases of relevant inputs are unsupported.
The loader limits individual file size and source-file count and rejects duplicate JSON keys and finding IDs. It does
not read `.env` files into prompts or evidence.

Evidence is loaded from harness-owned fixtures, separately from the provider. There is no caller/model-controlled
evidence path or self-attested `tests_passed` flag. Each sufficient record binds repository identity, source
commit/content identity, input-file hashes, and the exact declarative candidate digest. It corroborates current/resolved
target dependency versions, an advisory snapshot, required candidate checks, inspected scope, compatibility, and
relevant exclusions/coverage.

All shipped advisory and candidate-check observations are **mock assumptions**, clearly marked with simulated mode, mock
issuer/commands/tools, and mock advisory content. The mock advisory URL uses the reserved `.invalid` domain. A
malformed/missing/contradictory record cannot ACCEPT; a record for another snapshot/candidate is rejected. Baseline
green tests are not candidate evidence. No actual candidate was built or validated.

### Trust in scanner input

`findings.json` is a work queue, not evidence. A finding tells the harness where to look; it never establishes a fact
that a decision depends on. Trust is assigned per field, by what happens if the field is false:

| Field                                     | Use                                    | Treatment                                                                                                                                            |
|-------------------------------------------|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`, `cve`, `service`, `package`         | Selects work and bounds proposal scope | Accepted as the subject of evaluation. A false finding wastes work or prompts a needless proposal, which must still pass every evidence requirement. |
| `installed_version`                       | Claim about current state              | Must match the evidence record's resolved version and, for direct declarations, the POM/lockfile. A mismatch prevents ACCEPT.                        |
| `fixed_version`                           | Claim about the fix                    | Never used to ACCEPT. Fix facts come only from an advisory snapshot.                                                                                 |
| `notes`, `severity`, `sla_days_remaining` | Context                                | Inert text. Not instructions, not evidence, and not a decision input.                                                                                |

The principle: trust an input only where a false value causes more checking, never where it grants authority. A
fabricated finding causes extra work; a false "fixed in X" or "no fix exists" would change what is accepted, so it needs
independent corroboration.

The scanner is not an evidence source for fix facts. When it disagrees with the advisory snapshot, the advisory governs
and the tier does not change. If scanner disagreement forced REVIEW instead, a stale or hostile feed could hold any
remediation in REVIEW. The pinned feed shows the problem: F-40220 says there is "no patched release on the 3.x line",
but published advisories list 3.2.2 as a mitigation (sources in
[docs/baseline.md](docs/baseline.md#subsequent-advisory-check)). The fixture's 3.2.2 target is rejected only because it
also requests test suppression and auto-merge.

Limits:

- The direct manifest cross-check covers only direct declarations. SnakeYAML is transitive through Spring Boot, so for
  F-40218 the scanner's version is corroborated only by the evidence record's dependency resolution (and the manual
  `mvn dependency:tree` in [docs/baseline.md](docs/baseline.md)).
- The report does not yet emit scanner/advisory disagreements as a separate signal. That is a planned addition.
- The feed cannot show what it omits. Completeness requires a separate source, such as SBOMs matched against an advisory
  feed.

Harness code and its evidence bundle are trusted operator-controlled inputs. These are not cryptographically signed, and
the process is not a sandbox for malicious local Python plugins or a compromised harness installation. The threat
boundary here is untrusted repository/agent data. A real validator needs authenticated provenance and isolation; a
claimed issuer name or checksum is not authentication.

## Audit output and production proof

The JSON report records policy version, source commit/input hashes, candidate identity, finding identity, tier, and
reason code. `evidence_bundle.digest` content-addresses the entire loaded validation bundle. Each decision's
`validation_evidence` contains the requested `record_id` and a `record_digest` covering that complete raw JSON value,
including ignored metadata. The record digest is null when no record exists; the ID is also null when no non-blank
string reference was requested. A present malformed record still has a digest. A reference identifies available
evidence, not proof it passed validation or was consulted before an earlier rejection rule.

Both digests are `sha256:` followed by hexadecimal SHA-256, using `python-json-v1`:
UTF-8 encoding of `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`. Hash
parsed JSON before Pydantic normalization or filtering. Object-key order and serialization whitespace are irrelevant;
array order and field values are preserved. This is the stated Python JSON profile, not RFC 8785/JCS. Non-finite or
otherwise non-canonicalizable bundle data is an input error, never an invented digest.

Consumers must retain the report, the digest-matching evidence bundle, corresponding proposals/source snapshot, and the
policy implementation/version. Archive bundles by digest rather than overwrite one mutable evidence pathname. Before
reproducing a decision, recompute the bundle digest and the requested entry's digest; both must match. An unrelated
record change alters the bundle digest even if the selected record stays identical. The report has no wall-clock
timestamp and creates no archive automatically. These references establish content identity, not issuer authenticity,
approval, or production remediation; this remains an unsigned evaluation record.

Proposal, candidate validation, approval/merge, deployment, and runtime verification are distinct events.
The [mock production attestation](evidence/mock-production-attestation.json) illustrates their linkage for
CVE-2020-14343, including source and image identities, old/new dependency inventories, separate human approvals,
deployment scope, and complete point-in-time runtime inventory. The [auditor guide](evidence/README.md) explains
independent corroboration, integrity/signing design, and when missing or conflicting evidence must leave remediation NOT
VERIFIED. All events are fictional, the envelope is unsigned, and real production remediation is explicitly NOT
VERIFIED; no candidate fix, deployment, or production observation is claimed.

## Failure modes

| Failure                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Classification and impact                                                                                                                                                 | Detection                                                                                                                                                | Prevention / recovery                                                                                                                                                                              |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Repository docs or agent text instruct automation to suppress tests and bypass review.                                                                                                                                                                                                                                                                                                                                                                            | SAFE when treated as inert text or the requested prohibited action is rejected; the original vulnerability may remain unresolved.                                         | Stable rejection code for typed prohibited actions; adversarial regression cases.                                                                        | No repository execution, no agent policy authority, strict plan schema. Revise/escalate the proposal rather than weakening checks.                                                                 |
| Incorrect or stale candidate evidence makes a bad upgrade look validated. Concrete case: the shipped mock evidence records passing tests for PyYAML 5.4, but on Python 3.11 its source build failed under default build isolation, which resolved Cython 3.x (`'build_ext' object has no attribute 'cython_sources'`). It built only with Cython held below 3, and the worker's CI does not constrain it ([build check](docs/baseline.md#pyyaml-54-build-check)). | UNSAFE if trusted evidence is wrong or compromised and a later action runner relies on it. Current simulation executes nothing; ordinary missing/mismatched evidence fails closed. | Binding, corroboration, and required-check rules catch missing or mismatched evidence, but not a record that is wrong yet internally consistent (the PyYAML record passes all of them). That needs an independent rerun: CI on the merge request, or a second validator, disagreeing with the recorded result. | Separate provider from validator; revalidate changed inputs. A real system needs authenticated issuers and isolated collection; quarantine compromised evidence and reevaluate affected decisions. |
| A fix is approved/merged/deployed but an old vulnerable artifact remains running.                                                                                                                                                                                                                                                                                                                                                                                 | UNSAFE in production; approval or deployment alone leaves exposure unresolved. No production remediation is claimed here.                                                 | Reconcile deployed artifact digests against complete, recent runtime inventory for the affected environment. Missing/stale inventory means NOT VERIFIED. | Separate deployment and runtime gates, ownership/escalation, rollback or retire old instances, then repeat runtime verification.                                                                   |

## Scaling from 2 repositories to 300

Use a central inventory with versioned per-repository policy and explicit owners; queue evaluations with bounded
concurrency and provider/scanner rate limits. Make work idempotent by source/candidate/policy identity, retry transient
collection failures, and reconcile stale findings and deployments rather than trusting one-shot events. Isolate
repository processing and validation, use scoped credentials, and never share an agent's authority with evidence
collection or approval. Prioritize review by exposure, risk, ownership, and age to avoid alert fatigue. Centralize
evidence, observability, and audit retention with access controls and authenticated issuers. Roll out policy changes
gradually in observation mode before granting additional authority. None of this infrastructure is required for the
current offline evaluator.
