"""Common scanner interface.

Every scanner wraps one underlying OSS tool behind the same contract:

    scanner.run(ctx, workdir) -> ScanResult   # normalized findings + metadata

Adding a 5th tool is just a new subclass — the orchestrator, normalizer schema,
aggregator and report layer never change.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum

from sentryhive.auth import AwsContext
from sentryhive.models import Finding


def session_env(ctx: AwsContext | None) -> dict:
    """Export the resolved (possibly assumed-role) credentials into a child-process
    environment, so a wrapped tool authenticates as exactly the identity SentryHive
    verified — including temporary STS credentials from an assumed role."""
    env = dict(os.environ)
    if not ctx:
        return env
    creds = ctx.session.get_credentials()
    if creds:
        frozen = creds.get_frozen_credentials()
        env["AWS_ACCESS_KEY_ID"] = frozen.access_key
        env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
        if frozen.token:
            env["AWS_SESSION_TOKEN"] = frozen.token
        else:
            env.pop("AWS_SESSION_TOKEN", None)
    if ctx.regions:
        env["AWS_DEFAULT_REGION"] = ctx.regions[0]
    return env


class ScanStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"  # tool not installed or not applicable
    ERROR = "error"  # tool ran but failed


@dataclass
class ScanResult:
    scanner: str
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    raw: dict | list | None = None


class Scanner:
    """Base class. Subclasses set `name`/`binary` and implement `_scan`."""

    name: str = "scanner"
    binary: str = ""  # CLI executable that must be on PATH
    #: True if this scanner inspects a live AWS account; False if it scans local files.
    requires_aws: bool = True

    def is_available(self) -> bool:
        """Whether the underlying tool can be invoked."""
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    def run(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        if not self.is_available():
            return ScanResult(
                scanner=self.name,
                status=ScanStatus.SKIPPED,
                message=f"'{self.binary}' not found on PATH — install it or use the Docker image.",
            )
        try:
            return self._scan(ctx, workdir)
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, ScanStatus.ERROR, message="scanner timed out")
        except Exception as exc:  # noqa: BLE001 - one tool failing must not abort the run
            return ScanResult(self.name, ScanStatus.ERROR, message=str(exc))

    # --- subclass hook ---------------------------------------------------
    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        raise NotImplementedError

    # --- helpers ---------------------------------------------------------
    @staticmethod
    def _exec(cmd: list[str], env: dict | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
        """Run a subprocess, capturing output. Does not raise on non-zero exit;
        many scanners use exit codes to signal 'findings present'."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
