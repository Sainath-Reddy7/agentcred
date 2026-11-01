"""Core data objects for the AgentCred protocol (v0-draft).

Mirrored by the JSON Schemas in schema/. Fields are deliberately plain
(str/float/bool) so attestations round-trip through JSON without custom
serialization.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ATTESTATION_TYPES = frozenset(
    {
        "task_completed",
        "payment_settled",
        "dispute_opened",
        "dispute_resolved",
        "capability_verified",
    }
)


@dataclass(frozen=True)
class AgentIdentity:
    """A persistent, owner-bound agent identity."""

    did: str
    owner: str
    public_key: dict
    created_at: str
    display_name: str | None = None
    capabilities: tuple[str, ...] = ()
    revoked: bool = False
    version: int = 1


@dataclass(frozen=True)
class Attestation:
    """A signed statement about an agent, issued by a counterparty.

    Self-attestations (attester == agent) are storable but carry zero
    score weight by design.
    """

    id: str
    agent: str
    attester: str
    type: str
    signed_at: str
    payload: dict = field(default_factory=dict)
    signature: str | None = None

    def __post_init__(self) -> None:
        if self.type not in ATTESTATION_TYPES:
            raise ValueError(
                f"unknown attestation type {self.type!r}; "
                f"expected one of {sorted(ATTESTATION_TYPES)}"
            )

    @property
    def is_self_attestation(self) -> bool:
        return self.attester == self.agent
