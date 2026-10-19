"""The shape of a rule of the catalog."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    pillar: str
    severity: str
    title: str
    recommendation: str
    applies_to: tuple
    query: str
    source: str = "builtin"
