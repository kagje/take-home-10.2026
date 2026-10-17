# 003: Use a local checkout as input

Status: Accepted

The harness will accept `--repo-root` pointing to a local checkout. It will load `findings/findings.json` and use the
known `services/inventory-api` and `services/report-worker` layout. Missing required files or an unsupported input shape
will produce an input error, not a vulnerability decision.

Repository fetching is a separate setup step. The harness will not accept repository URLs, fetch code, or execute
repository scripts. Reading repository content does not grant it authority over policy.

This keeps evaluation offline and scoped to the supplied exercise repository. Record the checkout's commit with
evaluation evidence; a local directory alone does not establish its identity or integrity. This decision does
not support other repository layouts.
