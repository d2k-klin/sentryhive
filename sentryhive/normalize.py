"""Per-tool output parsers -> unified `Finding` list.

Each function takes a tool's native JSON (already loaded into Python objects) and
returns normalized findings. Parsers are intentionally defensive: tool output
schemas drift between versions, so we read fields by best-effort and never assume
a key is present. Anything we cannot map degrades to a sensible default rather than
raising.
"""

from __future__ import annotations

from typing import Any

from sentryhive.models import Finding, Severity


def _get(d: dict, *keys: str, default: Any = "") -> Any:
    """Return the first present, truthy-or-explicit value among keys (case-insensitive)."""
    lowered = {k.lower(): v for k, v in d.items()} if isinstance(d, dict) else {}
    for k in keys:
        if k in d:
            return d[k]
        if k.lower() in lowered:
            return lowered[k.lower()]
    return default


# --------------------------------------------------------------------------- #
# Prowler — supports both OCSF (v4 default) and legacy native JSON (v3).
# --------------------------------------------------------------------------- #
def parse_prowler(data: list[dict] | dict) -> list[Finding]:
    rows = data if isinstance(data, list) else data.get("findings", [])
    findings: list[Finding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if "finding_info" in row or "status_code" in row:
            findings.append(_prowler_ocsf(row))
        else:
            findings.append(_prowler_native(row))
    return findings


def _prowler_ocsf(row: dict) -> Finding:
    info = row.get("finding_info", {}) or {}
    resources = row.get("resources", []) or [{}]
    res = resources[0] if resources else {}
    remediation = row.get("remediation", {}) or {}
    cloud = row.get("cloud", {}) or {}
    account = cloud.get("account", {}) or {}
    status_code = str(row.get("status_code", "")).lower()
    return Finding(
        tool="prowler",
        check=str(_get(info, "uid", default=row.get("metadata", {}).get("event_code", ""))),
        title=str(_get(info, "title", default="")),
        description=str(_get(info, "desc", "description", default="")),
        severity=Severity.parse(row.get("severity")),
        resource=str(_get(res, "uid", "name", default="")),
        service=str(res.get("group", {}).get("name", "") if isinstance(res.get("group"), dict) else ""),
        region=str(_get(res, "region", default=cloud.get("region", ""))),
        status="pass" if status_code == "pass" else "fail" if status_code == "fail" else "info",
        remediation=str(_get(remediation, "desc", "description", default="")),
        compliance_refs=_compliance_list(row.get("unmapped", {}).get("compliance")
                                         if isinstance(row.get("unmapped"), dict) else row.get("compliance")),
        account_id=str(account.get("uid", "")),
    )


def _prowler_native(row: dict) -> Finding:
    return Finding(
        tool="prowler",
        check=str(_get(row, "CheckID", "check_id", default="")),
        title=str(_get(row, "CheckTitle", "check_title", default="")),
        description=str(_get(row, "Description", "description", default="")),
        severity=Severity.parse(_get(row, "Severity", "severity")),
        resource=str(_get(row, "ResourceId", "ResourceArn", "resource_id", default="")),
        service=str(_get(row, "ServiceName", "service_name", default="")),
        region=str(_get(row, "Region", "region", default="")),
        status="pass" if str(_get(row, "Status", "status")).lower() in ("pass", "passed") else "fail",
        remediation=str(_remediation_text(_get(row, "Remediation", "remediation"))),
        compliance_refs=_compliance_list(_get(row, "Compliance", "compliance")),
        account_id=str(_get(row, "AccountId", "account_id", default="")),
    )


# --------------------------------------------------------------------------- #
# Cloudsplaining — IAM policy risk analysis. Output is keyed by policy/principal
# with risk categories (PrivilegeEscalation, ResourceExposure, ...).
# --------------------------------------------------------------------------- #
_CLOUDSPLAINING_RISKS = {
    "PrivilegeEscalation": (Severity.HIGH, "Privilege escalation path"),
    "DataExfiltration": (Severity.HIGH, "Data exfiltration risk"),
    "ResourceExposure": (Severity.HIGH, "Resource exposure (permissions management)"),
    "CredentialsExposure": (Severity.MEDIUM, "Credentials exposure"),
    "ServiceWildcard": (Severity.MEDIUM, "Service-level wildcard"),
    "PrivilegeEscalationCount": (Severity.HIGH, "Privilege escalation path"),
}


def parse_cloudsplaining(data: dict, account_id: str = "") -> list[Finding]:
    findings: list[Finding] = []
    items = data.get("results", data) if isinstance(data, dict) else {}
    for policy_name, detail in items.items():
        if not isinstance(detail, dict):
            continue
        for risk_key, (severity, title) in _CLOUDSPLAINING_RISKS.items():
            value = detail.get(risk_key)
            if not value:
                continue
            actions = value if isinstance(value, list) else [str(value)]
            findings.append(
                Finding(
                    tool="cloudsplaining",
                    check=risk_key,
                    title=f"{title}: {policy_name}",
                    description=f"Policy '{policy_name}' grants: {', '.join(map(str, actions[:15]))}",
                    severity=severity,
                    resource=policy_name,
                    service="iam",
                    status="fail",
                    remediation="Apply least privilege: remove the flagged actions or "
                    "scope them with conditions/resources.",
                    compliance_refs=["CIS-1.16", "IAM-least-privilege"],
                    account_id=account_id,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# hardeneks — EKS best-practice checks. We parse its JSON export (list of rules).
# --------------------------------------------------------------------------- #
def parse_hardeneks(data: list[dict] | dict, account_id: str = "", region: str = "") -> list[Finding]:
    rows = data if isinstance(data, list) else data.get("findings", data.get("results", []))
    findings: list[Finding] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        resources = _get(row, "resources", "Resources", default=[])
        resource = ", ".join(map(str, resources)) if isinstance(resources, list) else str(resources)
        findings.append(
            Finding(
                tool="hardeneks",
                check=str(_get(row, "rule", "check", "id", default="")),
                title=str(_get(row, "title", "name", "rule", default="")),
                description=str(_get(row, "description", "desc", default="")),
                severity=Severity.parse(_get(row, "severity", default="medium")),
                resource=resource or str(_get(row, "namespace", default="cluster")),
                service="eks",
                region=region,
                status="fail",
                remediation=str(_get(row, "remediation", "resolution", default="")),
                compliance_refs=["EKS-best-practices"],
                account_id=account_id,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# ASH (Automated Security Helper) — aggregates SAST/IaC/secret scanners.
# Parses the aggregated JSON results.
# --------------------------------------------------------------------------- #
def parse_ash(data: dict | list) -> list[Finding]:
    findings: list[Finding] = []
    rows = data.get("findings", data.get("results", [])) if isinstance(data, dict) else data
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        location = _get(row, "location", "file_path", "path", default="")
        line = _get(row, "line", "line_number", default="")
        resource = f"{location}:{line}" if line else str(location)
        findings.append(
            Finding(
                tool="ash",
                check=str(_get(row, "rule_id", "check_id", "id", default="")),
                title=str(_get(row, "title", "rule", "message", default="")),
                description=str(_get(row, "description", "message", "desc", default="")),
                severity=Severity.parse(_get(row, "severity", default="medium")),
                resource=resource,
                service=str(_get(row, "scanner", "tool", default="iac")),
                status="fail",
                remediation=str(_get(row, "remediation", "guidance", default="")),
                compliance_refs=_compliance_list(_get(row, "compliance")),
                account_id="",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _compliance_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, dict):
        out: list[str] = []
        for framework, controls in value.items():
            if isinstance(controls, list):
                out.extend(f"{framework}:{c}" for c in controls)
            else:
                out.append(f"{framework}:{controls}")
        return out
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _remediation_text(value: Any) -> str:
    if isinstance(value, dict):
        rec = value.get("Recommendation") or value.get("recommendation") or {}
        if isinstance(rec, dict):
            return str(rec.get("Text") or rec.get("text") or "")
        return str(rec)
    return str(value) if value else ""
