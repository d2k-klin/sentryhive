"""Backup & recovery classification.

Several wrapped scanners already produce backup-relevant evidence (Prowler alone
covers RDS automated backups, S3 versioning, DynamoDB PITR, EFS backup). Until now
those rows dissolved into the general register with nothing tying them together.
This recognizes them so the report can present recovery as one control area.
"""

from __future__ import annotations

from sentryhive.models import Finding

#: Services whose findings can constitute backup/recovery evidence.
_RESILIENCE_SERVICES = frozenset(
    {
        "backup",
        "rds",
        "s3",
        "dynamodb",
        "efs",
        "ec2",
        "elasticache",
        "documentdb",
        "neptune",
        "redshift",
        "fsx",
    }
)

#: Terms that mark a check as being about *who can read* a backup rather than whether it
#: can restore. Confidentiality controls on backup resources are not recovery evidence:
#: `documentdb_cluster_public_snapshot` is an exposure finding that happens to say
#: "snapshot", and `..._replication_group_auth_enabled` is authentication that happens to
#: say "replication". Checked before the include terms below.
_EXCLUDED_TERMS = ("public", "auth")

#: Terms that mark a check as recovery-related.
# ponytail: substring match over check ids, not a curated per-check allowlist. Scanner
# check ids are already self-describing snake_case, and a pinned list would rot on every
# Prowler release. If this ever misfires, pin an explicit id set in this module.
_RESILIENCE_TERMS = (
    "backup",
    "snapshot",
    "pitr",
    "point_in_time",
    "point-in-time",
    "versioning",
    "object_lock",
    "objectlock",
    "replication",
    "retention",
    "deletion_protection",
    "multi_az",
    "recovery",
    "restore",
)


def is_resilience(finding: Finding) -> bool:
    """Whether this finding is backup/recovery evidence, whichever tool produced it."""
    if finding.tool == "resilience":
        return True
    if finding.service.lower() not in _RESILIENCE_SERVICES:
        return False
    haystack = f"{finding.check} {finding.title}".lower()
    if any(term in haystack for term in _EXCLUDED_TERMS):
        return False
    return any(term in haystack for term in _RESILIENCE_TERMS)
