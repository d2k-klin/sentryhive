"""AWS credential resolution and identity verification.

Supports, in priority order (see project plan §5):
  1. AWS profile      -> --profile
  2. Static keys      -> env AWS_ACCESS_KEY_ID / SECRET / SESSION_TOKEN
  3. Assume role      -> --role-arn (+ optional --external-id), via STS

Always calls sts:GetCallerIdentity first so the user sees exactly which account
and identity is about to be scanned.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AuthError(Exception):
    """Raised when credentials cannot be resolved or verified."""


@dataclass
class Identity:
    account_id: str
    arn: str
    user_id: str


@dataclass
class AwsContext:
    """A resolved, verified AWS session plus the identity behind it."""

    session: boto3.Session
    identity: Identity
    regions: list[str]

    def client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region)


def resolve_session(
    profile: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
    role_session_name: str = "sentryhive",
) -> boto3.Session:
    """Build a boto3 Session from the chosen auth strategy.

    A profile (or ambient env keys) establishes the base session. If a role ARN is
    given, that base session is used to assume the role and a new session is built
    from the temporary credentials.
    """
    base = boto3.Session(profile_name=profile, region_name=region)

    if not role_arn:
        return base

    try:
        sts = base.client("sts")
        params: dict = {"RoleArn": role_arn, "RoleSessionName": role_session_name}
        if external_id:
            params["ExternalId"] = external_id
        resp = sts.assume_role(**params)
    except (ClientError, BotoCoreError) as exc:
        raise AuthError(f"Failed to assume role {role_arn}: {exc}") from exc

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def verify_identity(session: boto3.Session) -> Identity:
    """Call sts:GetCallerIdentity; raise AuthError with a clear message on failure."""
    try:
        resp = session.client("sts").get_caller_identity()
    except (ClientError, BotoCoreError) as exc:
        raise AuthError(
            "Could not verify AWS credentials via sts:GetCallerIdentity. "
            f"Check your profile/keys/role. Underlying error: {exc}"
        ) from exc
    return Identity(
        account_id=resp["Account"],
        arn=resp["Arn"],
        user_id=resp["UserId"],
    )


def default_regions(session: boto3.Session) -> list[str]:
    """Region the session resolved to, falling back to us-east-1."""
    region = session.region_name or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    return [region]


def build_context(
    profile: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    regions: list[str] | None = None,
) -> AwsContext:
    """One-stop: resolve credentials, verify identity, settle on regions."""
    primary = regions[0] if regions else None
    session = resolve_session(
        profile=profile,
        role_arn=role_arn,
        external_id=external_id,
        region=primary,
    )
    identity = verify_identity(session)
    resolved_regions = regions or default_regions(session)
    return AwsContext(session=session, identity=identity, regions=resolved_regions)
