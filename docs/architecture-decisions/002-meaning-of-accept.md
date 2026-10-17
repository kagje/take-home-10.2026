# 002: Meaning of ACCEPT

Status: Accepted

ACCEPT means the proposed remediation satisfies the harness’s policy and required candidate-validation gates and is
eligible for normal human merge approval.

Required candidate application and validation occur in an isolated process before an ACCEPT decision. Merge and
production deployment each require separate human approval.

In this implementation, candidate validation is simulated. ACCEPT therefore reflects mock evidence and authorizes no
real action.