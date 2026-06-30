"""Common scanner interface.

Every scanner wraps one underlying OSS tool behind the same contract:

    scanner.run(ctx, workdir) -> ScanResult   # normalized findings + metadata

Adding a 5th tool is just a new subclass — the orchestrator, normalizer schema,
aggregator and report layer never change.
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

from sentryhive.auth import AwsContext
from sentryhive.models import Finding

DEFAULT_SCANNER_TIMEOUT_SECONDS = 3600


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
    version: str = ""  # version of the underlying tool, for evidence/reproducibility


class Scanner:
    """Base class. Subclasses set `name`/`binary` and implement `_scan`."""

    name: str = "scanner"
    binary: str = ""  # CLI executable that must be on PATH
    #: True if this scanner inspects a live AWS account; False if it scans local files.
    requires_aws: bool = True

    #: Flag passed to the binary to print its version (override if non-standard).
    version_flag: str = "--version"
    #: If enabled, scanner stdout/stderr lines are also printed while they run.
    show_scanner_output: bool = False
    #: Elapsed-time heartbeat interval for long-running scanner commands.
    heartbeat_interval: float = 30.0

    def is_available(self) -> bool:
        """Whether the underlying tool can be invoked."""
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    def version(self) -> str:
        """Best-effort version string of the underlying tool (for evidence/repro)."""
        if not self.binary or not self.is_available():
            return ""
        try:
            proc = self._exec([self.binary, self.version_flag], timeout=30)
        except Exception:  # noqa: BLE001
            return ""
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        return out[0].strip() if out else ""

    def run(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        if not self.is_available():
            return ScanResult(
                scanner=self.name,
                status=ScanStatus.SKIPPED,
                message=f"'{self.binary}' not found on PATH — install it or use the Docker image.",
            )
        version = self.version()
        try:
            result = self._scan(ctx, workdir)
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, ScanStatus.ERROR, message="scanner timed out", version=version)
        except Exception as exc:  # noqa: BLE001 - one tool failing must not abort the run
            return ScanResult(self.name, ScanStatus.ERROR, message=str(exc), version=version)
        result.version = result.version or version
        return result

    # --- subclass hook ---------------------------------------------------
    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        raise NotImplementedError

    # --- helpers ---------------------------------------------------------
    def _exec(
        self,
        cmd: list[str],
        env: dict | None = None,
        timeout: int = DEFAULT_SCANNER_TIMEOUT_SECONDS,
        progress: bool = False,
        progress_label: str | None = None,
        stream_output: bool | None = None,
        heartbeat_interval: float | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess, capturing output and optionally showing progress.

        The return shape intentionally matches subprocess.run(). Many scanner
        wrappers need stderr/stdout after completion, while users need assurance
        that long scans are still active.
        """
        if not progress:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
                check=False,
            )
        return self._exec_with_progress(
            cmd,
            env=env,
            timeout=timeout,
            progress_label=progress_label or self.name,
            stream_output=self.show_scanner_output if stream_output is None else stream_output,
            heartbeat_interval=heartbeat_interval or self.heartbeat_interval,
        )

    def _exec_with_progress(
        self,
        cmd: list[str],
        env: dict | None,
        timeout: int,
        progress_label: str,
        stream_output: bool,
        heartbeat_interval: float,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess with captured output plus elapsed-time heartbeats."""
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,
        )

        output_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        readers: list[threading.Thread] = []

        def reader(name: str, stream):
            try:
                for line in iter(stream.readline, ""):
                    output_queue.put((name, line))
            finally:
                stream.close()

        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            if stream is None:
                continue
            thread = threading.Thread(target=reader, args=(name, stream), daemon=True)
            thread.start()
            readers.append(thread)

        started = time.monotonic()
        next_heartbeat = started + heartbeat_interval
        lines_seen = 0
        last_output_at: float | None = None
        poll_interval = min(0.2, max(0.02, heartbeat_interval / 5))

        while True:
            now = time.monotonic()
            if timeout is not None and now - started > timeout:
                proc.kill()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                for thread in readers:
                    thread.join(timeout=0.2)
                self._drain_output_queue(output_queue, stdout_chunks, stderr_chunks, progress_label, stream_output)
                raise subprocess.TimeoutExpired(
                    cmd=cmd,
                    timeout=timeout,
                    output="".join(stdout_chunks),
                    stderr="".join(stderr_chunks),
                )

            try:
                stream_name, line = output_queue.get(timeout=poll_interval)
            except queue.Empty:
                stream_name = ""
                line = ""

            if line:
                lines_seen += 1
                last_output_at = time.monotonic()
                self._record_scanner_line(
                    stream_name,
                    line,
                    stdout_chunks,
                    stderr_chunks,
                    progress_label,
                    stream_output,
                )

            now = time.monotonic()
            if now >= next_heartbeat and proc.poll() is None:
                last_output_age = None if last_output_at is None else now - last_output_at
                self._print_progress_heartbeat(progress_label, now - started, lines_seen, last_output_age)
                next_heartbeat = now + heartbeat_interval

            if proc.poll() is not None:
                for thread in readers:
                    thread.join(timeout=0.2)
                self._drain_output_queue(output_queue, stdout_chunks, stderr_chunks, progress_label, stream_output)
                break

        return subprocess.CompletedProcess(
            cmd,
            proc.returncode,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
        )

    def _drain_output_queue(
        self,
        output_queue: queue.Queue[tuple[str, str]],
        stdout_chunks: list[str],
        stderr_chunks: list[str],
        progress_label: str,
        stream_output: bool,
    ) -> None:
        while True:
            try:
                stream_name, line = output_queue.get_nowait()
            except queue.Empty:
                return
            self._record_scanner_line(
                stream_name,
                line,
                stdout_chunks,
                stderr_chunks,
                progress_label,
                stream_output,
            )

    def _record_scanner_line(
        self,
        stream_name: str,
        line: str,
        stdout_chunks: list[str],
        stderr_chunks: list[str],
        progress_label: str,
        stream_output: bool,
    ) -> None:
        if stream_name == "stdout":
            stdout_chunks.append(line)
        else:
            stderr_chunks.append(line)
        if stream_output:
            cleaned = line.rstrip()
            if cleaned:
                print(f"  [{progress_label}] {cleaned}", file=sys.stdout, flush=True)

    @staticmethod
    def _print_progress_heartbeat(
        progress_label: str,
        elapsed_seconds: float,
        lines_seen: int,
        last_output_age: float | None,
    ) -> None:
        activity = (
            f"last scanner output {_format_elapsed(last_output_age)} ago"
            if lines_seen and last_output_age is not None
            else "waiting for scanner output"
        )
        print(
            f"  ... {progress_label} still running ({_format_elapsed(elapsed_seconds)}, {activity})",
            file=sys.stdout,
            flush=True,
        )


def _format_elapsed(seconds: float) -> str:
    seconds = int(seconds)
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
