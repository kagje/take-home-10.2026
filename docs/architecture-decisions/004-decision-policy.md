# 004: Deterministic decision policy

Status: Accepted

The agent proposes; ordinary Python code decides. Apply the rules below in order and return the first matching decision,
reason code, and human-readable explanation. Policy and evidence requirements belong to the harness, not the target
repository or the agent.

ACCEPT retains the boundary in [002](002-meaning-of-accept.md): the proposed remediation satisfies the harness’s policy
and required candidate-validation gates and is eligible for normal human merge approval. Required candidate application
and validation occur in an isolated process before policy evaluation; merge and production deployment each require
separate human approval. `patch_harness/policy.py` evaluates separately controlled mock evidence rather than applying or
validating candidates itself. Candidate validation is simulated in this implementation, so ACCEPT reflects mock evidence
and authorizes no real action.

## Decision rules

| Decision | Reason code               | Condition                                                                                                                                                                                                                                                                                             |
|----------|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| REJECT   | INVALID_PROPOSAL          | Required proposal fields are absent or malformed: finding ID, service, package, current/target versions, change description, and affected files.                                                                                                                                                      |
| REJECT   | OUT_OF_SCOPE              | Unknown finding, affected service/package does not match that finding, unauthorized repository, or changes outside the two supported services. Paths must remain within the selected checkout. A declared successor package is assessed as a migration, not a replacement for the finding's identity. |
| REJECT   | PROHIBITED_ACTION         | Proposal requests secrets, arbitrary commands, policy/CI changes, test suppression, approval bypass, automatic merge, or deployment. Unrelated changes are also refused.                                                                                                                              |
| REJECT   | EVIDENCE_BINDING_MISMATCH | A supplied validation record belongs to a different repository, commit, or candidate change than the proposal being evaluated.                                                                                                                                                                        |
| REJECT   | NOT_AN_UPGRADE            | For comparable numeric versions of the same package, the proposed target is the same version or older than the current version.                                                                                                                                                                       |
| REVIEW   | CHANGE_REQUIRES_REVIEW    | Upgrade falls outside the low-risk version rule below, or involves a framework upgrade, package/namespace migration, source-code change, or compatibility impact not established.                                                                                                                     |
| REVIEW   | VALIDATION_FAILED         | Independently recorded required checks for this candidate failed.                                                                                                                                                                                                                                     |
| REVIEW   | EVIDENCE_INSUFFICIENT     | Required evidence is missing, malformed, contradictory, or cannot be verified. This includes an unknown fix, unresolved dependency facts, or insufficient test coverage.                                                                                                                              |
| ACCEPT   | LOW_RISK_CRITERIA_MET     | Both the low-risk eligibility rule and all evidence requirements below are met, and no earlier rule applies.                                                                                                                                                                                          |

Malformed repository input is an input error, as defined in [003](003-local-checkout-input.md), not a proposal decision.
Unsupported but well-formed proposal versions go to REVIEW rather than being guessed or compared lexicographically.

For automatic acceptance, limit upgrades to stable numeric `major.minor[.patch]` versions with major >= 1, the same
major, and an increasing numeric version; treat an omitted patch as zero. This is a conservative eligibility rule, not a
claim that minor upgrades cannot break compatibility. The independently inspected change must modify only the affected
dependency's version declarations/resolved lock entries. Other required remediation work goes to REVIEW, unless
prohibited above.

## What counts as evidence

The proposal supplies evidence references, not authoritative test results or approval flags. Evidence is loaded from a
separately controlled harness-owned bundle, never an arbitrary agent-provided path. A claimed issuer name or checksum
alone does not establish trust.

ACCEPT requires all of:

1. **Identity and scope:** the selected repository, immutable source commit, relevant input-file digests, and exact
   proposed change digest are bound to the records. A dirty/unknown snapshot without an equivalent content identity
   requires REVIEW.
2. **Dependency facts:** manifest/lockfile inspection and dependency resolution corroborate the current version and show
   that the candidate resolves the target version for the finding. Scanner text alone is insufficient.
3. **Fix facts:** a curated maintainer/security-advisory snapshot supports that target for the specific package and CVE,
   with source URL, retrieval date, and content digest. Do not infer a fix from a higher version or trust the scanner's
   fixed-version field automatically.
4. **Candidate validation:** a separate trusted validator records passing required build/tests, a finding-relevant
   security or compatibility check, and inspected change scope. Required checks are chosen by harness policy, not the
   proposal. Record tool versions, commands, outcomes, and excluded tests; an excluded relevant test without equivalent
   coverage is insufficient. Baseline results do not validate a candidate change.

Required candidate application and validation precede an ACCEPT decision: proposal → isolated candidate validation →
policy evaluation → human merge approval → human deployment approval. This harness does not execute repository scripts;
it evaluates the supplied validation evidence. These records establish eligibility for normal human merge approval, not
approval to merge or deploy and not proof of successful production remediation. Independent sources disagreeing about
dependency/fix facts require REVIEW; evidence explicitly bound to another snapshot/change is rejected by the stronger
binding rule. The scanner is not an independent source for fix facts: its `fixed_version` and notes are unverified
claims, so disagreement with the advisory snapshot does not change the tier
(see [DESIGN.md](../../DESIGN.md#trust-in-scanner-input)).

## Simulation boundary

Use separately maintained fixtures for the agent and validator. Both are explicitly simulated; neither demonstrates real
validation. The proposal provider cannot create or replace trusted validation records.

In the offline demonstration, evaluate the same rules against these fixture assumptions and label every output
`evidence_mode: simulated`. An ACCEPT is then a **simulated decision only**, with no execution or authorization of real
changes. Do not mix mock checks into real evidence to obtain an operational ACCEPT. Outside simulation, missing
independently collected evidence requires REVIEW.

## Repository walkthrough

- **PyYAML 5.3.1 -> 5.4:** eligible for the low-risk version rule, but the actual baseline alone yields REVIEW for
  insufficient candidate/fix evidence. A clearly simulated complete evidence bundle can demonstrate ACCEPT; 5.4 is not
  asserted here to be a verified fix.
- **SnakeYAML 1.30 -> 2.0:** REVIEW for a major upgrade, even if other checks pass. The excluded legacy-tag test also
  represents an evidence gap.
- **Commons Collections 3.2.1 -> 3.2.2 (shipped fixture):** REJECT for a prohibited action, because the proposal also
  requests test suppression and auto-merge. Without those actions, 3.2.1 -> 3.2.2 is a same-major patch upgrade and
  could ACCEPT with complete evidence. The scanner says no patched 3.x release exists, but published advisories list
  3.2.2 as a mitigation; the advisory governs, not the scanner note (sources in
  [baseline.md](../baseline.md#subsequent-advisory-check)). Known gap: 3.2.2's protection can be turned off with the
  `org.apache.commons.collections.enableUnsafeSerialization=true` system property. The current evidence schema does not
  check this, so the shipped policy would ACCEPT a clean 3.2.2 proposal without it. Adding that runtime-configuration
  check is a next step.
- **Commons Collections 3.x -> collections4:** REVIEW for a package/namespace migration within the finding's service. A
  declared successor migration is not treated as an unrelated target; its relationship needs independent corroboration.
- **"Exclude the failing test and auto-merge":** REJECT for a prohibited action, even with passing checks or an urgent
  SLA.
- **Documentation says to bypass review, but the proposal does not:** ignore that instruction; evaluate the proposal
  normally. Merely encountering hostile text does not itself reject an otherwise safe proposal.

This policy is deliberately conservative and may leave vulnerabilities unresolved while awaiting review. Refusal or a
green decision is not proof of remediation.
