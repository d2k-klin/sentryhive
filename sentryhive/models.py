"""Unified finding schema — the common shape every scanner normalizes into.

This is the heart of SentryHive: no matter which tool produced a finding, it is
represented here identically so the aggregator and report layer never need to know
which scanner it came from.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered severities. Higher value == more severe, so findings sort naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int | None) -> Severity:
        """Best-effort mapping from the many severity vocabularies tools emit."""
        if value is None:
            return cls.INFO
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        key = str(value).strip().lower()
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "high": cls.HIGH,
            "error": cls.HIGH,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "low": cls.LOW,
            "minor": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "note": cls.INFO,
        }
        return mapping.get(key, cls.INFO)


@dataclass
class Finding:
    """A single normalized security finding.

    Mirrors the schema in the project plan (id, tool, severity, resource, check,
    description, remediation, compliance_refs) plus a few fields needed for a useful
    report (service, region, status, account_id).
    """

    tool: str
    check: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    resource: str = ""
    service: str = ""
    region: str = ""
    status: str = "fail"  # fail | pass | info
    remediation: str = ""
    compliance_refs: list[str] = field(default_factory=list)
    account_id: str = ""
    id: str = ""  # stable fingerprint, computed in __post_init__ if empty

    def __post_init__(self) -> None:
        if isinstance(self.severity, (str, int)) and not isinstance(self.severity, Severity):
            self.severity = Severity.parse(self.severity)
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable id used for dedup: tool + check + resource."""
        raw = f"{self.tool}|{self.check}|{self.resource}".lower()
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    @property
    def dedup_key(self) -> str:
        """Cross-tool dedup key: same resource + check from different tools collapse."""
        return f"{self.service}|{self.resource}|{self.check}".lower()

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.label
        d["severity_rank"] = int(self.severity)
        return d
