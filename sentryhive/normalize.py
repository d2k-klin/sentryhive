"""Per-tool output parsers -> unified `Finding` list.

Each function takes a tool's native JSON (already loaded into Python objects) and
returns normalized findings. Parsers are intentionally defensive: tool output
schemas drift between versions, so we read fields by best-effort and never assume
a key is present. Anything we cannot map degrades to a sensible default rather than
raising.
"""

from __future__ import annotations

import html
import ipaddress
import re
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
        compliance_refs=_compliance_list(
            row.get("unmapped", {}).get("compliance")
            if isinstance(row.get("unmapped"), dict)
            else row.get("compliance")
        ),
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
    if _looks_like_cloudsplaining_native(items):
        return _parse_cloudsplaining_native(items, account_id=account_id)

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


def _looks_like_cloudsplaining_native(items: dict) -> bool:
    sections = {"aws_managed_policies", "customer_managed_policies", "inline_policies"}
    return isinstance(items, dict) and bool(sections & set(items))


def _parse_cloudsplaining_native(items: dict, account_id: str = "") -> list[Finding]:
    findings: list[Finding] = []
    sections = ("customer_managed_policies", "inline_policies", "aws_managed_policies")
    for section in sections:
        policies = items.get(section, {})
        if not isinstance(policies, dict):
            continue
        for policy_id, detail in policies.items():
            if not isinstance(detail, dict):
                continue
            policy_name = str(_get(detail, "PolicyName", "policy_name", default=policy_id))
            resource = str(_get(detail, "Arn", "arn", default=policy_name))
            for risk_key, (default_severity, title) in _CLOUDSPLAINING_RISKS.items():
                risk = detail.get(risk_key)
                risk_findings = _cloudsplaining_risk_findings(risk)
                if not risk_findings:
                    continue
                severity = Severity.parse(risk.get("severity") if isinstance(risk, dict) else None)
                if severity is Severity.INFO:
                    severity = default_severity
                description = _clean_html(risk.get("description", "")) if isinstance(risk, dict) else ""
                actions = ", ".join(map(_stringify_action, risk_findings[:15]))
                findings.append(
                    Finding(
                        tool="cloudsplaining",
                        check=risk_key,
                        title=f"{title}: {policy_name}",
                        description=description or f"Policy '{policy_name}' grants: {actions}",
                        severity=severity,
                        resource=resource,
                        service="iam",
                        status="fail",
                        remediation="Apply least privilege: remove the flagged actions or "
                        "scope them with conditions/resources.",
                        compliance_refs=["CIS-1.16", "IAM-least-privilege"],
                        account_id=account_id,
                    )
                )
    return findings


def _cloudsplaining_risk_findings(value: Any) -> list:
    if isinstance(value, dict):
        findings = value.get("findings", [])
        return findings if isinstance(findings, list) else [findings]
    if isinstance(value, list):
        return value
    return [value] if value else []


def _stringify_action(value: Any) -> str:
    if isinstance(value, dict):
        if value.get("actions"):
            actions = value["actions"]
            return ", ".join(map(str, actions)) if isinstance(actions, list) else str(actions)
        if value.get("type"):
            return str(value["type"])
    return str(value)


def _clean_html(value: str) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(str(value)))).strip()


# --------------------------------------------------------------------------- #
# CloudFox — focused attack-surface observations. CloudFox explicitly does not
# produce findings, so only unambiguous risk markers become failures; endpoints
# and network exposure remain informational observations for human validation.
# --------------------------------------------------------------------------- #
def parse_cloudfox(data: dict[str, list[dict]], account_id: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for row in data.get("workloads", []):
        admin = _yes(_get(row, "IsAdminRole?", "IsAdmin?", default=""))
        privesc = _yes(_get(row, "CanPrivEscToAdmin?", default=""))
        if not admin and not privesc:
            continue
        role = str(_get(row, "Role", default=""))
        resource = str(_get(row, "Arn", "Name", default=role))
        findings.append(
            Finding(
                tool="cloudfox",
                check="workload-privesc" if privesc else "workload-admin-role",
                title=(
                    "Workload role can escalate to administrator" if privesc else "Workload uses an administrator role"
                ),
                description=f"{_get(row, 'Service', default='AWS')} workload is attached to role {role or 'unknown'}.",
                severity=Severity.CRITICAL if privesc else Severity.HIGH,
                resource=resource,
                service=str(_get(row, "Service", default="iam")).lower(),
                region=str(_get(row, "Region", default="")),
                status="fail",
                remediation=(
                    "Replace the workload role with a least-privilege role and remove its path to administrator."
                ),
                compliance_refs=["IAM-least-privilege"],
                account_id=str(_get(row, "Account", default=account_id)),
            )
        )

    for row in data.get("role-trusts-principals-root-trusts-without-external-id", []):
        role = str(_get(row, "Role Arn", "Role Name", default=""))
        principal = str(_get(row, "Trusted Principal", default="external account root"))
        findings.append(
            Finding(
                tool="cloudfox",
                check="root-trust-without-external-id",
                title="IAM role trusts an account root without an external ID",
                description=f"Trusted principal: {principal}. CloudFox identified no sts:ExternalId condition.",
                severity=Severity.HIGH,
                resource=role,
                service="iam",
                status="fail",
                remediation=(
                    "Trust a specific principal where possible; for third parties, require a unique sts:ExternalId."
                ),
                compliance_refs=["IAM-least-privilege"],
                account_id=str(_get(row, "Account", default=account_id)),
            )
        )

    for row in data.get("resource-trusts", []):
        public = _yes(_get(row, "Public", default=""))
        interesting = _yes(_get(row, "Interesting", default=""))
        if not public and not interesting:
            continue
        arn = str(_get(row, "ARN", default=""))
        findings.append(
            Finding(
                tool="cloudfox",
                check="public-resource-policy" if public else "interesting-resource-policy",
                title=(
                    "Resource policy permits public access" if public else "Resource trust requires manual validation"
                ),
                description=str(_get(row, "Resource Policy Summary", default="")),
                severity=Severity.HIGH if public else Severity.MEDIUM,
                resource=arn,
                service=_service_from_arn(arn),
                status="fail" if public else "info",
                remediation=(
                    "Restrict the resource policy to the required principals, actions, resources, and conditions."
                ),
                compliance_refs=[],
                account_id=str(_get(row, "Account", default=account_id)),
            )
        )

    for row in data.get("endpoints", []):
        if not _yes(_get(row, "Public", default="")):
            continue
        endpoint = str(_get(row, "Endpoint", default=""))
        findings.append(
            Finding(
                tool="cloudfox",
                check="public-endpoint-observation",
                title="Public endpoint exposed for validation",
                description=(
                    f"CloudFox observed {str(_get(row, 'Protocol', default='network')).upper()} "
                    f"port {_get(row, 'Port', default='unknown')}. Public reachability is not by itself "
                    "a vulnerability."
                ),
                severity=Severity.MEDIUM,
                resource=endpoint or str(_get(row, "Name", default="")),
                service=str(_get(row, "Service", default="")).lower(),
                region=str(_get(row, "Region", default="")),
                status="info",
                remediation="Validate authentication, intended exposure, TLS, and network controls for this endpoint.",
                compliance_refs=[],
                account_id=str(_get(row, "Account", default=account_id)),
            )
        )

    for row in data.get("network-ports", []):
        host = str(_get(row, "Host", default=""))
        if not _is_public_ip(host):
            continue
        findings.append(
            Finding(
                tool="cloudfox",
                check="public-network-service-observation",
                title="Public network service exposed for validation",
                description=(
                    f"CloudFox observed {str(_get(row, 'Protocol', default='network')).upper()} "
                    f"port(s) {_get(row, 'Ports', default='unknown')} on a public address."
                ),
                severity=Severity.MEDIUM,
                resource=host,
                service=str(_get(row, "Service", default="")).lower(),
                region=str(_get(row, "Region", default="")),
                status="info",
                remediation="Confirm that the service is intentionally public and restrict source ranges and ports.",
                compliance_refs=[],
                account_id=str(_get(row, "Account", default=account_id)),
            )
        )
    return findings


def _yes(value: Any) -> bool:
    return str(value).strip().lower() in {"yes", "true", "public", "1"}


def _service_from_arn(value: str) -> str:
    parts = value.split(":")
    return parts[2] if len(parts) > 2 and parts[0] == "arn" else ""


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return ip.is_global


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
# Kubescape v2 JSON — one compact normalized finding per control. The native
# result can contain a row for every resource/control pair; grouping here keeps
# the combined report useful while retaining affected resource IDs in evidence.
# --------------------------------------------------------------------------- #
def parse_kubescape(
    data: dict,
    cluster: str = "",
    account_id: str = "",
    region: str = "",
) -> list[Finding]:
    summary = data.get("summaryDetails", {}) if isinstance(data, dict) else {}
    controls = summary.get("controls", {}) if isinstance(summary, dict) else {}
    resources_by_control: dict[str, list[str]] = {}
    for result in data.get("results", []) if isinstance(data, dict) else []:
        if not isinstance(result, dict):
            continue
        resource_id = str(_get(result, "resourceID", default=""))
        for control in result.get("controls", []) or []:
            if not isinstance(control, dict):
                continue
            status = _kubescape_status(control.get("status"))
            if status == "fail":
                cid = str(_get(control, "controlID", "id", default=""))
                resources_by_control.setdefault(cid, []).append(resource_id)

    framework_refs: dict[str, set[str]] = {}
    for framework in summary.get("frameworks", []) if isinstance(summary, dict) else []:
        if not isinstance(framework, dict):
            continue
        name = str(_get(framework, "name", default=""))
        for key, control in (framework.get("controls", {}) or {}).items():
            cid = str(_get(control, "controlID", "id", default=key)) if isinstance(control, dict) else str(key)
            if name:
                framework_refs.setdefault(cid, set()).add(f"{name}:{cid}")

    rows = controls.items() if isinstance(controls, dict) else []
    findings: list[Finding] = []
    for key, control in rows:
        if not isinstance(control, dict):
            continue
        cid = str(_get(control, "controlID", "id", default=key))
        status = _kubescape_status(_get(control, "statusInfo", "status", default=""))
        if status not in ("fail", "pass"):
            continue
        counters = _get(control, "ResourceCounters", "resourceCounters", default={})
        failed = int(_get(counters, "failedResources", default=0) or 0) if isinstance(counters, dict) else 0
        passed = int(_get(counters, "passedResources", default=0) or 0) if isinstance(counters, dict) else 0
        affected = sorted({r for r in resources_by_control.get(cid, []) if r})
        evidence = ", ".join(affected[:8])
        if len(affected) > 8:
            evidence += f", +{len(affected) - 8} more"
        description = f"Kubescape evaluated {failed + passed} resources: {failed} failed, {passed} passed."
        if evidence:
            description += f" Affected: {evidence}."
        severity = Severity.parse(_get(control, "severity", default=""))
        if severity is Severity.INFO:
            severity = _kubescape_score_severity(_get(control, "scoreFactor", default=0))
        findings.append(
            Finding(
                tool="kubescape",
                check=cid,
                title=str(_get(control, "name", default=cid)),
                description=description,
                severity=severity,
                resource=f"{cluster or data.get('clusterName') or 'cluster'} ({failed} affected)",
                service="kubernetes",
                region=region,
                status=status,
                remediation=f"Review and remediate Kubescape control {cid} on the affected Kubernetes resources.",
                compliance_refs=sorted(framework_refs.get(cid, set())),
                account_id=account_id,
            )
        )
    return findings


def _kubescape_status(value: Any) -> str:
    if isinstance(value, dict):
        value = _get(value, "status", default="")
    key = str(value).strip().lower()
    return "fail" if key in {"fail", "failed"} else "pass" if key in {"pass", "passed"} else "info"


def _kubescape_score_severity(value: Any) -> Severity:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return Severity.INFO
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


# --------------------------------------------------------------------------- #
# ASH (Automated Security Helper) — aggregates SAST/IaC/secret scanners.
# Parses the aggregated JSON results.
# --------------------------------------------------------------------------- #
def parse_ash(data: dict | list) -> list[Finding]:
    if isinstance(data, dict) and isinstance(data.get("sarif"), dict):
        return _parse_ash_sarif(data["sarif"])

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


def _parse_ash_sarif(sarif: dict) -> list[Finding]:
    """Parse the SARIF embedded in official AWS ASH v3 aggregate reports."""
    findings: list[Finding] = []
    level_severity = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "note": Severity.LOW,
        "none": Severity.INFO,
    }
    for run in sarif.get("runs", []):
        if not isinstance(run, dict):
            continue
        for row in run.get("results", []) or []:
            if not isinstance(row, dict) or row.get("suppressions"):
                continue
            properties = row.get("properties", {}) or {}
            message = row.get("message", {}) or {}
            location = next(iter(row.get("locations", []) or []), {}) or {}
            physical = location.get("physicalLocation", {}) or {}
            artifact = physical.get("artifactLocation", {}) or {}
            region = physical.get("region", {}) or {}
            path = str(artifact.get("uri", ""))
            line = region.get("startLine")
            resource = f"{path}:{line}" if path and line else path
            severity = Severity.parse(properties.get("issue_severity"))
            if severity is Severity.INFO:
                severity = level_severity.get(str(row.get("level", "")).lower(), Severity.INFO)

            findings.append(
                Finding(
                    tool="ash",
                    check=str(row.get("ruleId", "")),
                    title=str(row.get("ruleId") or message.get("text") or "ASH finding"),
                    description=str(message.get("markdown") or message.get("text") or ""),
                    severity=severity,
                    resource=resource,
                    service=str(
                        properties.get("scanner_name")
                        or (properties.get("scanner_details", {}) or {}).get("tool_name")
                        or "iac"
                    ),
                    status="fail",
                    remediation=_sarif_remediation(row),
                    compliance_refs=[],
                    account_id="",
                )
            )
    return findings


def _sarif_remediation(row: dict) -> str:
    for fix in row.get("fixes", []) or []:
        description = fix.get("description", {}) if isinstance(fix, dict) else {}
        text = description.get("text") if isinstance(description, dict) else ""
        if text:
            return str(text)
    return ""


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
