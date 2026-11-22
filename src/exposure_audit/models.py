"""Shared data structures for findings and the exposure graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high"].index(self.value)


@dataclass
class Finding:
    check: str                 # which module produced it, e.g. "breaches"
    title: str                 # one-line summary
    severity: Severity
    identifier: str            # the input it relates to (email / phone / username)
    detail: str = ""           # longer explanation
    url: str | None = None     # where the user can see it
    remediation: str = ""      # what to do about it
    data: dict = field(default_factory=dict)


@dataclass
class Edge:
    """A link from one piece of identity to another, e.g. email -> gravatar username."""
    source: str
    target: str
    via: str


@dataclass
class AuditResult:
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def link(self, source: str, target: str, via: str) -> None:
        if not any(e.source == source and e.target == target for e in self.edges):
            self.edges.append(Edge(source, target, via))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.check, f.title))
