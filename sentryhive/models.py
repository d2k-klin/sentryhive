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


#: Recognized compliance frameworks, mapping the prefix tools emit -> display name.
#: Order matters: longer/more specific prefixes are matched first.
_FRAMEWORKS: dict[str, str] = {
    "pci-dss": "PCI-DSS",
    "pci": "PCI-DSS",
    "nist-800-53": "NIST 800-53",
    "nist800-53": "NIST 800-53",
    "nist": "NIST 800-53",
    "iso-27001": "ISO 27001",
    "iso27001": "ISO 27001",
    "soc2": "SOC 2",
    "hipaa": "HIPAA",
    "gdpr": "GDPR",
    "cis": "CIS",
}

#: Compliance-ref prefixes that are *not* frameworks and must be ignored for posture.
_NON_FRAMEWORK_PREFIXES = ("flagged-by", "cwe", "iam-least-privilege", "eks-best-practices")


def framework_of(ref: str) -> str | None:
    """Map a single compliance ref (e.g. "CIS:2.1.5", "PCI-DSS-8.3") to a framework
    display name, or None if it is not a recognized compliance framework."""
    if not ref:
        return None
    head = ref.strip().lower().split(":", 1)[0]
    if head.startswith(_NON_FRAMEWORK_PREFIXES):
        return None
    # Try the part before the first separator, then progressively shorter prefixes.
    token = head.replace("_", "-")
    for sep in ("-",):
        token_no_num = token
        # Strip a trailing numeric control id like "cis-1.16" -> "cis".
        parts = token.split(sep)
        while parts and (parts[-1].replace(".", "").isdigit() or parts[-1] == ""):
            parts.pop()
        token_no_num = sep.join(parts) if parts else token
        for candidate in (token, token_no_num):
            if candidate in _FRAMEWORKS:
                return _FRAMEWORKS[candidate]
    return _FRAMEWORKS.get(token)


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

    def frameworks(self) -> set[str]:
        """Compliance frameworks this finding maps to (e.g. {"CIS", "PCI-DSS"})."""
        return {fw for ref in self.compliance_refs if (fw := framework_of(ref))}

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.label
        d["severity_rank"] = int(self.severity)
        return d
