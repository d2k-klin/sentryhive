import datetime as dt

from botocore.exceptions import ClientError

from sentryhive.models import Finding, Severity, framework_of
from sentryhive.resilience import is_resilience
from sentryhive.scanners import build_scanners
from sentryhive.scanners.base import ScanStatus
from sentryhive.scanners.resilience import ResilienceScanner, schedule_interval_hours

ACCOUNT = "111122223333"
REGION = "eu-central-1"


def _ago(hours=0, days=0):
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours, days=days)


def _denied():
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "ListBackupPlans")


class FakeBackup:
    """Minimal stand-in for the AWS Backup client — canned pages, no botocore."""

    def __init__(self, plans=None, rules=None, vaults=None, jobs=None, restores=None, deny=()):
        self._plans = plans if plans is not None else [{"BackupPlanId": "p1", "BackupPlanName": "daily"}]
        self._rules = rules if rules is not None else []
        self._vaults = vaults or []
        self._jobs = jobs or []
        self._restores = restores or []
        self._deny = set(deny)

    def _guard(self, name):
        if name in self._deny:
            raise _denied()

    def list_backup_plans(self, **kwargs):
        self._guard("plans")
        return {"BackupPlansList": self._plans}

    def get_backup_plan(self, BackupPlanId):  # noqa: N803 - boto3 parameter name
        self._guard("plans")
        return {"BackupPlan": {"BackupPlanName": "daily", "Rules": self._rules}}

    def list_backup_vaults(self, **kwargs):
        self._guard("vaults")
        return {"BackupVaultList": self._vaults}

    def list_backup_jobs(self, **kwargs):
        self._guard("jobs")
        return {"BackupJobs": self._jobs}

    def list_restore_jobs(self, **kwargs):
        self._guard("restores")
        return {"RestoreJobs": self._restores}


class FakeRds:
    def __init__(self, instances=None, deny=False):
        self._instances = instances or []
        self._deny = deny

    def describe_db_instances(self, **kwargs):
        if self._deny:
            raise _denied()
        return {"DBInstances": self._instances}


class FakeIdentity:
    account_id = ACCOUNT
    arn = f"arn:aws:iam::{ACCOUNT}:role/audit"
    user_id = "AIDA"


class FakeCtx:
    """Mimics AwsContext.client() dispatch without touching boto3."""

    def __init__(self, backup=None, rds=None, regions=(REGION,)):
        self.identity = FakeIdentity()
        self.regions = list(regions)
        self._backup = backup or FakeBackup()
        self._rds = rds or FakeRds()

    def client(self, service, region=None):
        return self._backup if service == "backup" else self._rds


def _run(ctx, **kwargs):
    scanner = ResilienceScanner(**kwargs)
    result = scanner.run(ctx, "/tmp")
    return result, {f.check: f for f in result.findings}


def _by_check(result, check):
    return [f for f in result.findings if f.check == check]


# --- schedule parsing ------------------------------------------------------
def test_schedule_interval_parsing():
    assert schedule_interval_hours("rate(12 hours)") == 12
    assert schedule_interval_hours("rate(1 day)") == 24
    assert schedule_interval_hours("cron(0 */6 * * ? *)") == 6
    assert schedule_interval_hours("cron(0 0,12 * * ? *)") == 12
    assert schedule_interval_hours("cron(0 5 * * ? *)") == 24


def test_unparseable_schedule_returns_none_rather_than_guessing():
    assert schedule_interval_hours("cron(0 5 ? * MON *)") is None  # weekly
    assert schedule_interval_hours("") is None
    assert schedule_interval_hours("whenever") is None


# --- backup plans ----------------------------------------------------------
def test_no_backup_plan_fails():
    result, by_check = _run(FakeCtx(backup=FakeBackup(plans=[])))
    assert result.status is ScanStatus.OK
    plan = by_check["resilience-backup-plan-exists"]
    assert plan.status == "fail"
    assert plan.severity is Severity.HIGH


def test_offsite_copy_to_other_account_passes():
    rules = [
        {
            "RuleName": "daily",
            "CopyActions": [{"DestinationBackupVaultArn": f"arn:aws:backup:{REGION}:999988887777:backup-vault:dr"}],
        }
    ]
    _, by_check = _run(FakeCtx(backup=FakeBackup(rules=rules)))
    assert by_check["resilience-offsite-copy"].status == "pass"


def test_copy_within_same_account_and_region_fails():
    rules = [
        {
            "RuleName": "daily",
            "CopyActions": [{"DestinationBackupVaultArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:local"}],
        }
    ]
    _, by_check = _run(FakeCtx(backup=FakeBackup(rules=rules)))
    assert by_check["resilience-offsite-copy"].status == "fail"


def test_retention_below_target_fails_and_above_passes():
    short = [{"RuleName": "r", "Lifecycle": {"DeleteAfterDays": 7}}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(rules=short)), retention_days=35)
    assert by_check["resilience-retention-meets-policy"].status == "fail"

    long = [{"RuleName": "r", "Lifecycle": {"DeleteAfterDays": 90}}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(rules=long)), retention_days=35)
    assert by_check["resilience-retention-meets-policy"].status == "pass"


def test_cadence_slower_than_rpo_fails():
    rules = [{"RuleName": "r", "ScheduleExpression": "rate(2 days)"}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(rules=rules)), rpo_hours=24)
    assert by_check["resilience-backup-cadence"].status == "fail"


def test_unreadable_cadence_is_info_not_fail():
    rules = [{"RuleName": "r", "ScheduleExpression": "cron(0 5 ? * MON *)"}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(rules=rules)))
    assert by_check["resilience-backup-cadence"].status == "info"


# --- vaults ----------------------------------------------------------------
def test_vault_lock_state():
    vaults = [
        {"BackupVaultName": "locked", "Locked": True, "LockDate": _ago(days=10)},
        {"BackupVaultName": "open"},
    ]
    result, _ = _run(FakeCtx(backup=FakeBackup(vaults=vaults)))
    statuses = {f.resource: f.status for f in _by_check(result, "resilience-vault-lock")}
    assert statuses == {"locked": "pass", "open": "fail"}


# --- job freshness ---------------------------------------------------------
def test_stale_backup_fails_and_fresh_backup_passes():
    stale = [{"State": "COMPLETED", "CompletionDate": _ago(hours=50)}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(jobs=stale)), rpo_hours=24)
    assert by_check["resilience-backup-freshness"].status == "fail"

    fresh = [{"State": "COMPLETED", "CompletionDate": _ago(hours=2)}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(jobs=fresh)), rpo_hours=24)
    assert by_check["resilience-backup-freshness"].status == "pass"


def test_failed_backup_jobs_are_reported_separately():
    jobs = [
        {"State": "FAILED", "ResourceArn": "arn:aws:rds:::db/prod"},
        {"State": "COMPLETED", "CompletionDate": _ago(hours=1)},
    ]
    _, by_check = _run(FakeCtx(backup=FakeBackup(jobs=jobs)), rpo_hours=24)
    assert by_check["resilience-backup-job-failures"].severity is Severity.HIGH
    assert by_check["resilience-backup-freshness"].status == "pass"


# --- restore testing -------------------------------------------------------
def test_untested_restore_fails():
    _, by_check = _run(FakeCtx(backup=FakeBackup(restores=[])))
    restore = by_check["resilience-restore-tested"]
    assert restore.status == "fail"
    assert "SOC2:A1.3" in restore.compliance_refs


def test_completed_restore_passes():
    restores = [{"Status": "COMPLETED", "CompletionDate": _ago(days=10)}]
    _, by_check = _run(FakeCtx(backup=FakeBackup(restores=restores)))
    assert by_check["resilience-restore-tested"].status == "pass"


# --- RDS -------------------------------------------------------------------
def test_rds_retention_states():
    instances = [
        {"DBInstanceArn": "arn:db:none", "BackupRetentionPeriod": 0},
        {"DBInstanceArn": "arn:db:short", "BackupRetentionPeriod": 7},
        {"DBInstanceArn": "arn:db:ok", "BackupRetentionPeriod": 35},
    ]
    result, _ = _run(FakeCtx(rds=FakeRds(instances)), retention_days=35)
    found = {f.resource: (f.status, f.severity) for f in _by_check(result, "resilience-rds-retention")}
    assert found["arn:db:none"] == ("fail", Severity.HIGH)
    assert found["arn:db:short"] == ("fail", Severity.MEDIUM)
    assert found["arn:db:ok"][0] == "pass"


# --- unknown, never a silent pass ------------------------------------------
def test_access_denied_yields_info_and_other_checks_still_run():
    ctx = FakeCtx(
        backup=FakeBackup(vaults=[{"BackupVaultName": "v"}], deny={"vaults"}),
        rds=FakeRds([{"DBInstanceArn": "arn:db:ok", "BackupRetentionPeriod": 35}]),
    )
    result, by_check = _run(ctx)
    vault = by_check["resilience-vault-lock"]
    assert vault.status == "info"
    assert "Could not verify" in vault.title
    # The permission gap must not stop, or silently pass, the remaining controls.
    assert by_check["resilience-rds-retention"].status == "pass"
    assert result.status is ScanStatus.OK


def test_unreadable_plans_still_report_restore_testing_as_unknown():
    """A denied plan read must not silently drop the restore-testing control.

    Regression: `if plans:` treated None (unreadable) the same as [] (none exist), so
    freshness and restore evidence vanished from the report instead of reporting unknown.
    """
    result, by_check = _run(FakeCtx(backup=FakeBackup(deny={"plans"})))
    for check in ("resilience-backup-plan-exists", "resilience-backup-freshness", "resilience-restore-tested"):
        assert by_check[check].status == "info", f"{check} must be reported as unknown"
    assert "could not be read" in by_check["resilience-restore-tested"].title
    assert result.status is ScanStatus.OK


def test_no_plans_at_all_does_not_emit_cascade_unknowns():
    """Genuinely having no backup plan is a fail, not an unknown — the opposite case."""
    _, by_check = _run(FakeCtx(backup=FakeBackup(plans=[])))
    assert by_check["resilience-backup-plan-exists"].status == "fail"
    assert "resilience-restore-tested" not in by_check


def test_unknown_findings_are_excluded_from_compliance_posture():
    from sentryhive.aggregate import compliance_posture

    ctx = FakeCtx(backup=FakeBackup(deny={"plans", "vaults", "jobs", "restores"}), rds=FakeRds(deny=True))
    result, _ = _run(ctx)
    assert all(f.status == "info" for f in result.findings)
    assert compliance_posture(result.findings) == []


# --- wiring ----------------------------------------------------------------
def test_scanner_needs_no_binary_and_reports_a_version():
    [scanner] = build_scanners(["resilience"], rpo_hours=6, retention_days=14)
    assert scanner.is_available() is True
    assert scanner.version().startswith("sentryhive-native")
    assert (scanner.rpo_hours, scanner.retention_days) == (6, 14)


def test_scanner_skips_without_an_aws_context():
    [scanner] = build_scanners(["resilience"])
    assert scanner.run(None, "/tmp").status is ScanStatus.SKIPPED


def test_compliance_refs_resolve_to_frameworks():
    assert framework_of("SOC2:A1.3") == "SOC 2"
    assert framework_of("ISO-27001:A.5.30") == "ISO 27001"
    assert framework_of("NIST-800-53:CP-9(5)") == "NIST 800-53"
    assert framework_of("HIPAA:164.308(a)(7)(ii)(D)") == "HIPAA"


# --- the lens over other tools' findings ------------------------------------
def test_lens_recognizes_other_tools_backup_findings():
    versioning = Finding(
        tool="prowler",
        check="s3_bucket_object_versioning",
        title="S3 bucket versioning",
        description="",
        service="s3",
    )
    pitr = Finding(
        tool="prowler",
        check="dynamodb_tables_pitr_enabled",
        title="PITR",
        description="",
        service="dynamodb",
    )
    iam = Finding(tool="prowler", check="iam_root_mfa_enabled", title="Root MFA", description="", service="iam")
    assert is_resilience(versioning)
    assert is_resilience(pitr)
    assert not is_resilience(iam)


def test_lens_excludes_confidentiality_checks_on_backup_resources():
    """Regression from a live scan: 34 of 117 gathered findings were exposure/auth checks.

    Both check ids below are real Prowler output — they matched on "snapshot" and
    "replication" while actually being about who can read the data, not recovery.
    """
    public_snapshot = Finding(
        tool="prowler",
        check="prowler-aws-documentdb_cluster_public_snapshot-254038622216-eu-west-1-handyhive-prod-docdb",
        title="DocumentDB cluster snapshot is not public",
        description="",
        service="documentdb",
        status="pass",
    )
    redis_auth = Finding(
        tool="prowler",
        check="prowler-aws-elasticache_redis_replication_group_auth_enabled-254038622216-eu-west-1-cache",
        title="ElastiCache Redis replication group has AUTH enabled",
        description="",
        service="elasticache",
    )
    assert not is_resilience(public_snapshot)
    assert not is_resilience(redis_auth)

    # …while the genuine recovery checks from the same scan still land in the section.
    for check, service in (
        ("prowler-aws-s3_bucket_cross_region_replication-254038622216-eu-west-1-bucket", "s3"),
        ("prowler-aws-dynamodb_table_protected_by_backup_plan-254038622216-eu-west-1-table", "dynamodb"),
        ("prowler-aws-elasticache_redis_cluster_backup_enabled-254038622216-eu-west-1-cache", "elasticache"),
        ("prowler-aws-documentdb_cluster_backup_enabled-254038622216-eu-west-1-docdb", "documentdb"),
    ):
        assert is_resilience(Finding(tool="prowler", check=check, title="", description="", service=service)), check


def test_lens_ignores_unrelated_checks_in_resilience_services():
    encryption = Finding(
        tool="prowler",
        check="rds_instance_storage_encrypted",
        title="RDS storage encryption",
        description="",
        service="rds",
    )
    assert not is_resilience(encryption)
