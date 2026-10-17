# Candidate's Take Home Assignment

## Take-Home Exercise: Vulnerability Patching Harness

This exercise is designed to explore how you think about autonomy boundaries, trust, and evidence in agentic systems.

## Time commitment: 4.5 hours maximum

What we're looking for: Your judgment about where to draw the line between What an agent should do autonomously and what
needs human approval and how you'd prove the right thing happened.

## The Scenario

You're building a harness where an LLM agent proposes fixes for dependency vulnerabilities, and the harness decides
whether to accept, route for review, or reject each proposal.
Repository: [github.com/takehome-assignment-bot/homework](https://github.com/takehome-assignment-bot/homework)

### The repo contains:

- Two services: inventory-api (Java/Spring Boot) and report-worker (Python)
- Both have open dependency findings
- A findings/findings.json file with scanner output

**Important**: The repository contains stale documentation and conflicting guidance. Part Of the exercise is deciding
What to trust and which instructions to follow. Apply the same critical judgment you would in a production environment.

## What to Deliver

### 1. Harness Code

Build a system that:

- Takes the findings as input
- Invokes an agent (or simulates one) to propose fixes
- Decides whether to accept, route for review, or reject each proposal
- Documents how to run it and What you stubbed

### 2. DESIGN.md

Write a design document that explains:

- Where the agent may act autonomously (no human approval)
- Where it must route to a human for review
- Where it should refuse entirely Why the line sits where it does
- What criteria determine each tier?

### 3. Evidence Artifact

Design What you'd hand an auditor to prove:

- CVE-2025-XXXX was remediated in production on (specific datel
- The vulnerable artifact is no longer running
- The fix went through appropriate gates You can mock this or describe the structure - we're evaluating the design, not
  the implementation. Examples: a JSON attestation, an audit log extract, or a structured compliance document.

### 4. Failure Mode Analysis

List three ways this system could fail. For each:

- Describe the failure
- Label it as safe (fails in a way that doesn't cause harm) or unsafe (could cause harm)
- Explain how you'd detect it happened

### 5. Scale Considerations

Write one paragraph on What changes when you scale from 2 repositories to 300. Include this as the final section of your
DESIGN.md.

## Important Guidance

The Agent is the Easy Part

**The decision logic is what we're evaluating**. Don't spend your 4.5 hours building perfect LLM integration. Spend it
on:

- Where you draw the autonomy boundary and why
- How you handle untrusted input (repo content, issues, logs, docs)
- What evidence proves remediation actually happened
- How you detect and handle failures

### What You May Use

- AI tools freely: Claude, GPT, Copilot, whatever you use day-to-day. Just note where you used them.
- Any language or framework: Java, Python, Go, TypeScript, whatever you know well.
- Any substrate: GitHub Actions, local scripts, Argo Workflows, n8n, whatever fits your thinking. A pipeline is as
  valid as an application.
- Mock/stub liberally: A live LLM call is optional. Recorded fixtures with deterministic tests are equally valid (and
  often better)
- Zero-cost constraint: Feel free to avoid paying for API credits, CI minutes, or cloud services. Use free tiers, local
  tools, or stubs

### What's In Scope

- Autonomy boundary design and justification
- Untrusted input handling
- Evidence and audit trail design
- Failure mode analysis
- The "decide whether to accept" logic

### What's Out Of Scope

- Production-ready LLM integration
- A complete CI/CD pipeline
- Real vulnerability scanner integration
- Perfect error handling and retries
- Enterprise-scale infrastructure

## Setup Prerequisites

Before starting:

1. Install Maven 3.9+ (there's deliberately no wrapper in the repo)
2. Verify both services build and test:

```bash
# Java service
(cd services/inventory-api && mvn test)

# python service
(cd services/report-worker && pip install -r requirements.lock pytest && pytest)
```

3. Review the repo structure and understand what's there before you start coding

## Time Management

You have 4.5 hours maximum. If you run long:

- Stop at 4.5 hours
- Document What you'd do next in your README Submit What you have

We're evaluating your judgment and design thinking, not your ability to build a complete system in 4.5 hours.

Suggested time allocation (totals 4.5 hours):

- 30 min: Explore the repo, understand the findings
- 90 min: Build the core harness and decision logic
- 60 min: Write DESIGN.md and failure analysis
- 30 min: Evidence artifact design and scale paragraph
- 30 min: Buffer for testing and documentation

## Submission

When you're done:

1. **Push your work** to a public GitHub repo (or zip it up if you prefer)
2. **Send the link** (or zip) to your recruiting contact
3. **Include a note** on where you used AI tools and approximately how long you spent

We'll review your submission and invite you to the next round, where you'll walk us through your design and we'll
discuss tradeoffs and extensions.

## Questions?

If anything is unclear or you hit a blocker, email your recruiting contact.

## A Note on This Exercise

This exercise reflects the kind of work you'd do in this role: building systems where agents have authority to change
production code, and designing the trust boundaries that make that defensible.

We're not looking for perfect code. We're looking for:

- Clear thinking about autonomy and trust
- Honest analysis of failure modes
- Evidence designs that would hold up to an audit.
- Judgment about What to automate and What not to

Good luck! We're looking forward to seeing your approach.

## Next Steps After Submission:

- Technical round (60 min): Walk us through your design, discuss tradeoffs
- Final round (30 min): Higher-level conversation about the role and team