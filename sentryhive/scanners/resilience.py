"""Backup & recovery posture — the control area no wrapped scanner answers.

Prowler asks "is backup enabled". An auditor asks whether backups meet the recovery
objective, whether they can be tampered with, whether a copy survives losing the
account, and whether a restore was ever actually proven. Those need the AWS Backup
APIs directly, so this is the one scanner that calls AWS itself rather than shelling
out to another tool — `binary = ""`, so the base class treats it as always available.

Everything here is read-only (List*/Get*/Describe*). A check that could not be read
emits `info` ("could not verify"), never `pass`: an unverifiable control is unknown,
not satisfied, and only pass/fail feed the compliance posture rollup.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from sentryhive import __version__
from sentryhive.auth import AwsContext
from sentryhive.models import Finding, Severity
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus

DEFAULT_RPO_HOURS = 24.0
DEFAULT_RETENTION_DAYS = 35

#: How recently a restore must have been proven for the control to pass.
# ponytail: fixed window rather than a third threshold flag. A --restore-test-days
# option is the upgrade path if a client's policy states something other than quarterly.
RESTORE_TEST_MAX_AGE_DAYS = 90

#: Safety net for the manual pagination loop.
_MAX_PAGES = 50

_BACKUP_REFS = ["SOC2:A1.2", "ISO-27001:A.8.13", "NIST-800-53:CP-9", "HIPAA:164.308(a)(7)(ii)(A)"]
_IMMUTABILITY_REFS = ["SOC2:A1.2", "ISO-27001:A.8.13", "NIST-800-53:CP-9(5)"]
_OFFSITE_REFS = ["SOC2:A1.2", "NIST-800-53:CP-9(3)", "HIPAA:164.308(a)(7)(ii)(B)"]
_RESTORE_REFS = ["SOC2:A1.3", "ISO-27001:A.5.30", "NIST-800-53:CP-10", "HIPAA:164.308(a)(7)(ii)(D)"]

_FAILED_JOB_STATES = {"FAILED", "EXPIRED", "ABORTED"}


def _collect(fn: Callable[..., dict], key: str, token_field: str = "NextToken", **kwargs) -> list[dict]:
    """Page through a list_*/describe_* API on the token contract botocore exposes."""
    items: list[dict] = []
    token = None
    for _ in range(_MAX_PAGES):
        resp = fn(**kwargs, **({token_field: token} if token else {}))
        items.extend(resp.get(key, []))
        token = resp.get(token_field)
        if not token:
            break
    return items


def _days(count: int) -> str:
    return f"{count} day" if count == 1 else f"{count} days"


def _age_hours(when: Any) -> float | None:
    """Age of a boto3 timestamp in hours, or None if it is not a datetime."""
    if not isinstance(when, dt.datetime):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - when).total_seconds() / 3600


def _is_denied(exc: BaseException) -> bool:
    if not isinstance(exc, ClientError):
        return False
    code = exc.response.get("Error", {}).get("Code", "")
    return "AccessDenied" in code or "Unauthorized" in code or "Authorization" in code


def _is_offsite(vault_arn: str, region: str, account_id: str) -> bool:
    """Whether a copy destination survives losing this region or this account."""
    parts = vault_arn.split(":")
    if len(parts) < 5:
        return False
    return parts[3] != region or parts[4] != account_id


def schedule_interval_hours(expression: str) -> float | None:
    """Backup cadence in hours, or None when the expression is not machine-readable.

    None is deliberate: an unparsed schedule becomes an `info` finding for manual
    review. This never invents a failure it cannot substantiate.
    """
    expr = (expression or "").strip().lower()
    rate = re.fullmatch(r"rate\((\d+)\s*(minute|hour|day)s?\)", expr)
    if rate:
        count, unit = int(rate.group(1)), rate.group(2)
        return count * {"minute": 1 / 60, "hour": 1.0, "day": 24.0}[unit]
    cron = re.fullmatch(r"cron\((.+)\)", expr)
    if not cron:
        return None
    fields = cron.group(1).split()
    if len(fields) < 5:
        return None
    hours, day_of_month, day_of_week = fields[1], fields[2], fields[4]
    if day_of_month not in ("*", "?") or day_of_week not in ("*", "?"):
        return None  # weekly/monthly cadence — surfaced for manual review, not failed
    if hours == "*":
        return 1.0
    if hours.startswith("*/") and hours[2:].isdigit():
        return float(hours[2:])
    slots = [h for h in hours.split(",") if h.isdigit()]
    return 24.0 / len(slots) if slots else None


class ResilienceScanner(Scanner):
    """Native AWS Backup / RDS recovery checks."""

    name = "resilience"
    binary = ""  # native boto3 checks — nothing to install, always available
    requires_aws = True

    def __init__(
        self,
        rpo_hours: float = DEFAULT_RPO_HOURS,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        self.rpo_hours = rpo_hours
        self.retention_days = retention_days

    def version(self) -> str:
        return f"sentryhive-native {__version__}"

    # --- orchestration ---------------------------------------------------
    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        if ctx is None:
            return ScanResult(self.name, ScanStatus.SKIPPED, message="resilience checks need an AWS account context.")
        findings: list[Finding] = []
        for region in ctx.regions:
            findings.extend(self._scan_region(ctx, region))
        return ScanResult(self.name, ScanStatus.OK, findings=findings)

    def _scan_region(self, ctx: AwsContext, region: str) -> list[Finding]:
        backup = ctx.client("backup", region=region)
        rds = ctx.client("rds", region=region)
        out: list[Finding] = []

        plans = self._fetch(
            out,
            lambda: self._load_plans(backup),
            check="resilience-backup-plan-exists",
            control="AWS Backup plans",
            region=region,
            ctx=ctx,
            refs=_BACKUP_REFS,
        )
        if plans is not None:
            out.extend(self._check_plans(plans, region, ctx))

        vaults = self._fetch(
            out,
            lambda: _collect(backup.list_backup_vaults, "BackupVaultList"),
            check="resilience-vault-lock",
            control="backup vault immutability",
            region=region,
            ctx=ctx,
            refs=_IMMUTABILITY_REFS,
        )
        if vaults is not None:
            out.extend(self._check_vault_lock(vaults, region, ctx))

        if plans is None:
            # Plans were unreadable, so job and restore evidence cannot be judged either.
            # Falling through silently would drop the restore-testing control from the report
            # entirely — the one control an auditor is most likely to look for.
            cascade = "backup plans could not be read"
            out.append(
                self._unknown(
                    check="resilience-backup-freshness",
                    control="recent backup jobs",
                    reason=cascade,
                    region=region,
                    ctx=ctx,
                    refs=_BACKUP_REFS,
                )
            )
            out.append(
                self._unknown(
                    check="resilience-restore-tested",
                    control="restore testing",
                    reason=cascade,
                    region=region,
                    ctx=ctx,
                    refs=_RESTORE_REFS,
                )
            )
        # Otherwise only meaningful once AWS Backup is in use; absence is reported above.
        elif plans:
            window = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2 * self.rpo_hours)
            jobs = self._fetch(
                out,
                lambda: _collect(backup.list_backup_jobs, "BackupJobs", ByCreatedAfter=window),
                check="resilience-backup-freshness",
                control="recent backup jobs",
                region=region,
                ctx=ctx,
                refs=_BACKUP_REFS,
            )
            if jobs is not None:
                out.extend(self._check_freshness(jobs, region, ctx))

            restore_window = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=RESTORE_TEST_MAX_AGE_DAYS)
            restores = self._fetch(
                out,
                lambda: _collect(backup.list_restore_jobs, "RestoreJobs", ByCreatedAfter=restore_window),
                check="resilience-restore-tested",
                control="restore testing",
                region=region,
                ctx=ctx,
                refs=_RESTORE_REFS,
            )
            if restores is not None:
                out.append(self._check_restore_tested(restores, backup, region, ctx))

        instances = self._fetch(
            out,
            lambda: _collect(rds.describe_db_instances, "DBInstances", token_field="Marker"),
            check="resilience-rds-retention",
            control="RDS backup retention",
            region=region,
            ctx=ctx,
            refs=_BACKUP_REFS,
        )
        if instances is not None:
            out.extend(self._check_rds_retention(instances, region, ctx))

        return out

    # --- checks ----------------------------------------------------------
    def _check_plans(self, plans: list[dict], region: str, ctx: AwsContext) -> list[Finding]:
        if not plans:
            return [
                self._finding(
                    check="resilience-backup-plan-exists",
                    title="No AWS Backup plan defined",
                    description=(
                        f"No AWS Backup plan exists in {region}. Any backups that do exist are "
                        "service-local and unmanaged, so retention, copy and restore behaviour "
                        "cannot be evidenced centrally."
                    ),
                    remediation="Define an AWS Backup plan covering the account's protected resources.",
                    severity=Severity.HIGH,
                    region=region,
                    ctx=ctx,
                    refs=_BACKUP_REFS,
                )
            ]

        out = [
            self._finding(
                check="resilience-backup-plan-exists",
                title=f"{len(plans)} AWS Backup plan(s) defined",
                description="Backup is centrally managed by AWS Backup: " + ", ".join(p["name"] for p in plans) + ".",
                status="pass",
                severity=Severity.INFO,
                region=region,
                ctx=ctx,
                refs=_BACKUP_REFS,
            )
        ]
        for plan in plans:
            for rule in plan["rules"]:
                resource = f"{plan['name']}/{rule.get('RuleName') or 'rule'}"
                out.append(self._check_offsite_copy(rule, resource, region, ctx))
                out.append(self._check_retention(rule, resource, region, ctx))
                out.append(self._check_cadence(rule, resource, region, ctx))
        return out

    def _check_offsite_copy(self, rule: dict, resource: str, region: str, ctx: AwsContext) -> Finding:
        account_id = ctx.identity.account_id
        offsite = [
            copy
            for copy in rule.get("CopyActions", [])
            if _is_offsite(copy.get("DestinationBackupVaultArn", ""), region, account_id)
        ]
        if offsite:
            targets = ", ".join(c.get("DestinationBackupVaultArn", "") for c in offsite)
            return self._finding(
                check="resilience-offsite-copy",
                title="Backup rule copies to a separate region or account",
                description=f"Copy destinations outside this region/account: {targets}.",
                status="pass",
                severity=Severity.INFO,
                resource=resource,
                region=region,
                ctx=ctx,
                refs=_OFFSITE_REFS,
            )
        return self._finding(
            check="resilience-offsite-copy",
            title="Backup rule keeps every copy in this account and region",
            description=(
                "The rule defines no copy action to another account or region, so a region "
                "outage, or compromise of this account, takes the backups with it."
            ),
            remediation="Add a CopyAction targeting a backup vault in a separate account or region.",
            severity=Severity.MEDIUM,
            resource=resource,
            region=region,
            ctx=ctx,
            refs=_OFFSITE_REFS,
        )

    def _check_retention(self, rule: dict, resource: str, region: str, ctx: AwsContext) -> Finding:
        delete_after = (rule.get("Lifecycle") or {}).get("DeleteAfterDays")
        if delete_after is None:
            return self._finding(
                check="resilience-retention-meets-policy",
                title="Backup rule retains recovery points indefinitely",
                description="No DeleteAfterDays lifecycle is set, so recovery points are not expired.",
                status="pass",
                severity=Severity.INFO,
                resource=resource,
                region=region,
                ctx=ctx,
                refs=_BACKUP_REFS,
            )
        if delete_after < self.retention_days:
            return self._finding(
                check="resilience-retention-meets-policy",
                title=f"Backup retention is {_days(delete_after)}, below the {self.retention_days}-day target",
                description=(
                    f"Recovery points are deleted after {_days(delete_after)}. Incidents discovered "
                    "later than that have no recoverable state."
                ),
                remediation=f"Raise DeleteAfterDays to at least {self.retention_days} on this rule.",
                severity=Severity.MEDIUM,
                resource=resource,
                region=region,
                ctx=ctx,
                refs=_BACKUP_REFS,
            )
        return self._finding(
            check="resilience-retention-meets-policy",
            title=f"Backup retention is {_days(delete_after)}, meeting the {self.retention_days}-day target",
            description=f"Recovery points are retained for {_days(delete_after)}.",
            status="pass",
            severity=Severity.INFO,
            resource=resource,
            region=region,
            ctx=ctx,
            refs=_BACKUP_REFS,
        )

    def _check_cadence(self, rule: dict, resource: str, region: str, ctx: AwsContext) -> Finding:
        expression = rule.get("ScheduleExpression", "")
        interval = schedule_interval_hours(expression)
        if interval is None:
            return self._finding(
                check="resilience-backup-cadence",
                title="Backup cadence could not be derived from the schedule",
                description=(
                    f"Schedule '{expression or 'none'}' is not a plain rate/daily cron expression. "
                    f"Confirm by hand that it meets the {self.rpo_hours}h recovery point objective."
                ),
                status="info",
                severity=Severity.INFO,
                resource=resource,
                region=region,
                ctx=ctx,
                refs=_BACKUP_REFS,
            )
        if interval > self.rpo_hours:
            return self._finding(
                check="resilience-backup-cadence",
                title=f"Backup runs every {interval:g}h, exceeding the {self.rpo_hours:g}h RPO",
                description=(
                    f"Schedule '{expression}' produces a recovery point every {interval:g} hours, so up "
                    f"to {interval:g} hours of data is unrecoverable — more than the stated objective."
                ),
                remediation=f"Increase the schedule frequency to at least every {self.rpo_hours:g} hours.",
                severity=Severity.MEDIUM,
                resource=resource,
                region=region,
                ctx=ctx,
                refs=_BACKUP_REFS,
            )
        return self._finding(
            check="resilience-backup-cadence",
            title=f"Backup runs every {interval:g}h, within the {self.rpo_hours:g}h RPO",
            description=f"Schedule '{expression}' produces a recovery point every {interval:g} hours.",
            status="pass",
            severity=Severity.INFO,
            resource=resource,
            region=region,
            ctx=ctx,
            refs=_BACKUP_REFS,
        )

    def _check_vault_lock(self, vaults: list[dict], region: str, ctx: AwsContext) -> list[Finding]:
        out: list[Finding] = []
        for vault in vaults:
            name = vault.get("BackupVaultName", "")
            locked = bool(vault.get("Locked") or vault.get("LockDate"))
            if locked:
                out.append(
                    self._finding(
                        check="resilience-vault-lock",
                        title="Backup vault is locked (immutable)",
                        description=f"Vault Lock is in effect on {name}; recovery points cannot be deleted early.",
                        status="pass",
                        severity=Severity.INFO,
                        resource=name,
                        region=region,
                        ctx=ctx,
                        refs=_IMMUTABILITY_REFS,
                    )
                )
                continue
            out.append(
                self._finding(
                    check="resilience-vault-lock",
                    title="Backup vault is not locked — recovery points are deletable",
                    description=(
                        f"Vault {name} has no Vault Lock, so anyone with backup delete permissions "
                        "(or ransomware operating with them) can remove the recovery points."
                    ),
                    remediation="Apply AWS Backup Vault Lock in compliance mode with a minimum retention period.",
                    severity=Severity.MEDIUM,
                    resource=name,
                    region=region,
                    ctx=ctx,
                    refs=_IMMUTABILITY_REFS,
                )
            )
        return out

    def _check_freshness(self, jobs: list[dict], region: str, ctx: AwsContext) -> list[Finding]:
        out: list[Finding] = []
        failed = [j for j in jobs if j.get("State") in _FAILED_JOB_STATES]
        if failed:
            out.append(
                self._finding(
                    check="resilience-backup-job-failures",
                    title=f"{len(failed)} backup job(s) failed in the last {2 * self.rpo_hours:g}h",
                    description=(
                        "Failed or expired backup jobs: "
                        + ", ".join(sorted({j.get("ResourceArn", "unknown") for j in failed}))
                        + ". A plan that runs but does not complete produces no recovery point."
                    ),
                    remediation="Investigate the failing backup jobs and confirm a recovery point now exists.",
                    severity=Severity.HIGH,
                    region=region,
                    ctx=ctx,
                    refs=_BACKUP_REFS,
                )
            )

        ages = [
            age
            for j in jobs
            if j.get("State") == "COMPLETED" and (age := _age_hours(j.get("CompletionDate"))) is not None
        ]
        newest = min(ages) if ages else None
        if newest is None:
            out.append(
                self._finding(
                    check="resilience-backup-freshness",
                    title=f"No backup completed in the last {2 * self.rpo_hours:g}h",
                    description=(
                        "A backup plan exists but no job completed within twice the recovery point "
                        "objective. The control is configured, not operating."
                    ),
                    remediation="Confirm the plan's resource selection matches live resources and that jobs run.",
                    severity=Severity.HIGH,
                    region=region,
                    ctx=ctx,
                    refs=_BACKUP_REFS,
                )
            )
        elif newest > self.rpo_hours:
            out.append(
                self._finding(
                    check="resilience-backup-freshness",
                    title=f"Most recent backup is {newest:.0f}h old, beyond the {self.rpo_hours:g}h RPO",
                    description="The newest completed backup job is older than the stated recovery point objective.",
                    remediation="Investigate why the schedule is not producing recovery points at the expected rate.",
                    severity=Severity.HIGH,
                    region=region,
                    ctx=ctx,
                    refs=_BACKUP_REFS,
                )
            )
        else:
            out.append(
                self._finding(
                    check="resilience-backup-freshness",
                    title=f"Most recent backup is {newest:.0f}h old, within the {self.rpo_hours:g}h RPO",
                    description="A backup job completed inside the recovery point objective window.",
                    status="pass",
                    severity=Severity.INFO,
                    region=region,
                    ctx=ctx,
                    refs=_BACKUP_REFS,
                )
            )
        return out

    def _check_restore_tested(self, restores: list[dict], backup, region: str, ctx: AwsContext) -> Finding:
        completed = [r for r in restores if r.get("Status") == "COMPLETED"]
        scheduled = self._restore_testing_plan_count(backup)
        plan_note = (
            f" {scheduled} restore testing plan(s) are configured."
            if scheduled
            else " No scheduled restore testing plan is configured."
        )
        if completed:
            return self._finding(
                check="resilience-restore-tested",
                title=f"{len(completed)} restore(s) completed in the last {RESTORE_TEST_MAX_AGE_DAYS} days",
                description="Recovery has been demonstrated, not just configured." + plan_note,
                status="pass",
                severity=Severity.INFO,
                region=region,
                ctx=ctx,
                refs=_RESTORE_REFS,
            )
        return self._finding(
            check="resilience-restore-tested",
            title=f"No restore completed in the last {RESTORE_TEST_MAX_AGE_DAYS} days",
            description=(
                "Backups exist but no restore job proves they are recoverable. An untested "
                "backup is an assumption, not a control." + plan_note
            ),
            remediation="Restore into an isolated target on a recurring schedule and retain the job as evidence.",
            severity=Severity.MEDIUM,
            region=region,
            ctx=ctx,
            refs=_RESTORE_REFS,
        )

    def _restore_testing_plan_count(self, backup) -> int:
        """Scheduled restore-testing plans, if this botocore version exposes the API."""
        api = getattr(backup, "list_restore_testing_plans", None)
        if api is None:
            return 0
        try:
            return len(_collect(api, "RestoreTestingPlans"))
        except (ClientError, BotoCoreError):
            return 0

    def _check_rds_retention(self, instances: list[dict], region: str, ctx: AwsContext) -> list[Finding]:
        out: list[Finding] = []
        for db in instances:
            # Aurora instances report the cluster's retention, so cluster coverage comes free.
            days = db.get("BackupRetentionPeriod", 0) or 0
            resource = db.get("DBInstanceArn") or db.get("DBInstanceIdentifier", "")
            if days == 0:
                out.append(
                    self._finding(
                        check="resilience-rds-retention",
                        title="RDS automated backups are disabled",
                        description="BackupRetentionPeriod is 0: no automated backup or point-in-time recovery exists.",
                        remediation=f"Set BackupRetentionPeriod to at least {_days(self.retention_days)}.",
                        severity=Severity.HIGH,
                        resource=resource,
                        region=region,
                        ctx=ctx,
                        refs=_BACKUP_REFS,
                        service="rds",
                    )
                )
            elif days < self.retention_days:
                out.append(
                    self._finding(
                        check="resilience-rds-retention",
                        title=f"RDS retention is {_days(days)}, below the {self.retention_days}-day target",
                        description=(
                            f"Point-in-time recovery reaches back {_days(days)} only; anything discovered "
                            "later than that is unrecoverable."
                        ),
                        remediation=f"Raise BackupRetentionPeriod to at least {_days(self.retention_days)}.",
                        severity=Severity.MEDIUM,
                        resource=resource,
                        region=region,
                        ctx=ctx,
                        refs=_BACKUP_REFS,
                        service="rds",
                    )
                )
            else:
                out.append(
                    self._finding(
                        check="resilience-rds-retention",
                        title=f"RDS retention is {_days(days)}, meeting the {self.retention_days}-day target",
                        description=f"Point-in-time recovery covers the last {_days(days)}.",
                        status="pass",
                        severity=Severity.INFO,
                        resource=resource,
                        region=region,
                        ctx=ctx,
                        refs=_BACKUP_REFS,
                        service="rds",
                    )
                )
        return out

    # --- helpers ---------------------------------------------------------
    def _load_plans(self, backup) -> list[dict]:
        """Backup plan summaries joined with their rule definitions."""
        plans = []
        for summary in _collect(backup.list_backup_plans, "BackupPlansList"):
            detail = backup.get_backup_plan(BackupPlanId=summary["BackupPlanId"]).get("BackupPlan", {})
            plans.append(
                {
                    "name": detail.get("BackupPlanName") or summary.get("BackupPlanName", ""),
                    "rules": detail.get("Rules", []),
                }
            )
        return plans

    def _fetch(
        self,
        out: list[Finding],
        fn: Callable[[], Any],
        *,
        check: str,
        control: str,
        region: str,
        ctx: AwsContext,
        refs: list[str],
    ) -> Any:
        """Run one API group, recording an explicit 'unknown' finding if it cannot be read.

        Reporting the control as unverified rather than swallowing the error is the point:
        an `info` finding is excluded from the compliance posture, so a permission gap can
        never masquerade as a passing control.
        """
        try:
            return fn()
        except (ClientError, BotoCoreError) as exc:
            reason = "access denied" if _is_denied(exc) else str(exc)
            out.append(self._unknown(check=check, control=control, reason=reason, region=region, ctx=ctx, refs=refs))
            return None

    def _unknown(
        self,
        *,
        check: str,
        control: str,
        reason: str,
        region: str,
        ctx: AwsContext,
        refs: list[str],
    ) -> Finding:
        """An explicitly unverified control: reported, excluded from posture, never a pass."""
        return self._finding(
            check=check,
            title=f"Could not verify {control} — {reason}",
            description=(
                f"SentryHive could not read {control} in {region}, so this control is "
                "unknown rather than passing. Grant the read-only permissions in "
                "iam/least-privilege-policy.json and re-run."
            ),
            status="info",
            severity=Severity.INFO,
            region=region,
            ctx=ctx,
            refs=refs,
        )

    def _finding(
        self,
        *,
        check: str,
        title: str,
        description: str,
        region: str,
        ctx: AwsContext,
        refs: list[str],
        status: str = "fail",
        severity: Severity = Severity.MEDIUM,
        resource: str = "",
        remediation: str = "",
        service: str = "backup",
    ) -> Finding:
        return Finding(
            tool=self.name,
            check=check,
            title=title,
            description=description,
            severity=severity,
            resource=resource or region,
            service=service,
            region=region,
            status=status,
            remediation=remediation,
            compliance_refs=list(refs),
            account_id=ctx.identity.account_id,
        )
