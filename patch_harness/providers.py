"""Proposal generation is replaceable; providers never receive validation evidence."""

from typing import Protocol

from .models import Finding


class ProposalProvider(Protocol):
    """A future LLM adapter returns the same untrusted JSON-compatible object."""

    def propose(self, finding: Finding) -> object: ...


class FixtureProposalProvider:
    """Recorded agent responses keyed by scanner finding ID."""

    def __init__(self, proposals: dict[str, object]):
        self._proposals = proposals

    def propose(self, finding: Finding) -> object:
        return self._proposals.get(finding.id)
