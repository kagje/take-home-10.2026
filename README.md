# Vulnerability patching harness

A Python harness that loads the exercise's scanner findings, gets simulated remediation proposals, and returns
deterministic **ACCEPT / REVIEW / REJECT** decisions with reason codes. It never applies changes, runs service builds,
merges, or deploys.

**Every current decision uses simulated evidence and authorizes no real action.** In particular, the PyYAML ACCEPT is a
demonstration under mock assumptions, not a verified fix.

## Run

### Prerequisites

It's assumed that ``git`` is available in the system. [uv](https://docs.astral.sh/uv/getting-started/installation/) is
also required. Install these and run:

```bash
uv sync --locked
```

For the take-home, checking out the homework project is a prerequisite as well. Check out the specific master head
commit (7d572752e5cf1340f218639bc5e822e79e998b92) as of time of writing:

```bash
git clone --no-checkout --config core.autocrlf=true https://github.com/takehome-assignment-bot/homework.git ../homework-verification-7d57275
git -C ../homework-verification-7d57275 checkout --detach 7d572752e5cf1340f218639bc5e822e79e998b92
```

Feel free to use a different directory, just pass it correctly when running the harness. Note `core.autocrlf=true`, this
is intentional: the shipped mock evidence is bound to the inspected Windows checkout's exact CRLF bytes. Without it, the
input digests differ and F-40219 becomes REJECT / `EVIDENCE_BINDING_MISMATCH`
instead of the simulated ACCEPT shown below.

The expected input repository layout is:

```text
<repo-root>/
  findings/findings.json
  services/inventory-api/pom.xml
  services/report-worker/requirements.lock
  services/report-worker/pyproject.toml
```

### Run the harness

```bash
uv run --locked python harness.py --repo-root ../homework-verification-7d57275
```

## Output

JSON goes to stdout, ordered by finding ID. It includes source/input identities, proposal digests, policy version,
decisions, reason codes, and readable explanations. `evidence_bundle.digest` identifies the entire loaded validation
bundle; each decision's `validation_evidence` identifies its requested record by ID and content digest. Output has no
run timestamp so for now repeated runs produce identical reports.

These SHA-256 references use the [documented canonical JSON profile](DESIGN.md#audit-output-and-production-proof), not
file bytes: formatting and object-key order do not change identity. Retain the matching bundle with the report, not
merely the current file at `fixtures/evidence.json`. Digests identify content; they do not authenticate its issuer.

The pinned demonstration produces:

| Finding                      | Decision           | Reason code            |
|------------------------------|--------------------|------------------------|
| F-40218, SnakeYAML           | REVIEW             | CHANGE_REQUIRES_REVIEW |
| F-40219, PyYAML              | ACCEPT (simulated) | LOW_RISK_CRITERIA_MET  |
| F-40220, Commons Collections | REJECT             | PROHIBITED_ACTION      |

Every report contains `evidence_mode: "simulated"` and `execution_authorized: false`. Exit **0** means evaluation
completed, not that every proposal was accepted. Invalid input produces JSON on stderr, no partial decision report, and
exit **2**.

## Test and observed verification

Run the test suite:

```bash
uv run --locked python -m unittest discover -s tests -v
```

The actual CLI demonstrated all three tiers; two repeated runs and a fresh pinned local clone produced byte-identical
output. URL input returned JSON `INPUT_ERROR` and exit 2. Service baseline results and their coverage limits are
in [docs/baseline.md](docs/baseline.md); those results are not candidate validation evidence.

Regression cases cover strict typing, preserved candidate whitespace, binding/failure precedence with malformed
evidence, and content-addressed reporting. Changing selected evidence changes its record and bundle digests even when
the candidate and decision stay the same; changing an unused record changes only the bundle identity. Reformatting the
bundle does not change the report.

## Implementation and trust boundary

- `patch_harness/loading.py`: validates scanner JSON and the known layout; reads declarations and fingerprints relevant
  source inputs. Duplicate JSON keys and finding IDs are errors.
- `patch_harness/schemas.py`: strict Pydantic models for scanner input, proposals, and nested evidence. No type coercion
  or proposal-value normalization; unknown proposal fields are forbidden. Internal snapshots and decisions remain
  dataclasses.
- `patch_harness/providers.py`: `ProposalProvider` interface and functioning fixture implementation. Providers receive a
  finding, not the validator's records, secrets, or filesystem tools.
- `patch_harness/policy.py`: pure first-match evaluation
  of [ADR 004](docs/architecture-decisions/004-decision-policy.md). No model-based authorization.
- `fixtures/proposals.json`: untrusted simulated agent responses, including an explicitly adversarial proposal.
- `fixtures/evidence.json`: separately controlled, explicitly mock validator/advisory records. No caller-supplied
  evidence path is accepted.
- `harness.py`: CLI entrypoint; it does not execute a remediation plan.

Source fingerprints cover required files plus supported source/config extensions under the two services. Generated
directories, hidden files/directories (including `.env`), unrelated documentation, and other file types are not read
into that identity. This is a scoped input identity, not a whole-filesystem attestation. The commit is read from
`.git/HEAD` and its ref as plain files; the harness starts no processes, so no git, dependency resolution, or tests are
run by it. Source identity does not authenticate a repository's owner.

## Auditor evidence

[Mock production attestation](evidence/mock-production-attestation.json) demonstrates separate proposal, validation,
policy, human approval/merge, deployment, and runtime-verification records.
[Auditor guide](evidence/README.md) explains the identity/digest links, independent verification, scope/freshness
requirements, and missing-evidence outcomes.

Every event is fictional; the artifact explicitly reports real production remediation as **NOT VERIFIED**. It is an
auditor-facing design example, not an input that can grant the harness authority.

## Assumptions and disclaimers

The accepted low-risk rule is deliberately narrow: stable numeric same-major dependency-only upgrades, with independent
evidence and no earlier review/rejection condition.

Known issue in the demonstration: PyYAML 5.4, the target of the simulated ACCEPT, has no Python 3.11 wheel, and its
source build failed under default pip build isolation, which resolved Cython 3.3.0. It built only when Cython was held
below 3. The worker's CI install does not constrain Cython. The mock evidence does not reveal this; real isolated
candidate validation would. Commands and tool versions:
[docs/baseline.md](docs/baseline.md#pyyaml-54-build-check). See also failure mode 2 in
[DESIGN.md](DESIGN.md#failure-modes).

See [DESIGN.md](DESIGN.md) for boundaries, failure modes, and scale considerations.

## Next steps

With more time, in priority order:

1. **Real candidate validation.** Apply each proposal in an isolated checkout, resolve dependencies, and run the service
   tests, replacing the mock records in `fixtures/evidence.json`. This would have caught the PyYAML 5.4 build failure.
2. **Report scanner/advisory disagreements.** Emit them as a separate signal in the report (for example, F-40220's
   "no patched 3.x release" note versus the 3.2.2 advisory) without changing the decision tier.
3. **Runtime-configuration checks.** For Commons Collections 3.2.2, verify that
   `org.apache.commons.collections.enableUnsafeSerialization` is not enabled before ACCEPT.
4. **Reachability evidence.** Record whether the vulnerable code path is used. For example, `report_worker/config.py`
   passes operator-supplied files to `yaml.load(..., FullLoader)`, so a `safe_load` change may belong in the
   remediation.
5. **Signed evidence.** Authenticate validator records and the attestation (for example, a DSSE/in-toto envelope)
   instead of relying on unsigned content digests.
6. **Completeness check.** Compare SBOMs against an advisory feed to find vulnerabilities the scanner missed.
7. **Live LLM provider.** Add an adapter behind `ProposalProvider` with no access to evidence, secrets, or tools, and
   keep the fixture provider for tests.

**AI assistance:** GPT/Claude coding assistance was used for implementation, test construction, documentation, and
command execution, with delegated policy/test work.

**Time spent:** Completion took some 4 hours.
