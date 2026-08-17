import json
import os
import subprocess
import sys

import pytest

from sentryhive.scanners import ALL_SCANNERS, build_scanners
from sentryhive.scanners.base import DEFAULT_SCANNER_TIMEOUT_SECONDS, Scanner, ScanStatus
from sentryhive.scanners.cloudfox import CloudfoxScanner
from sentryhive.scanners.cloudsplaining import CloudsplainingScanner


class DummyScanner(Scanner):
    binary = ""

    def _scan(self, ctx, workdir):
        raise NotImplementedError


def test_registry_has_all_scanners():
    assert set(ALL_SCANNERS) == {
        "prowler",
        "cloudsplaining",
        "cloudfox",
        "resilience",
        "hardeneks",
        "kubescape",
        "ash",
    }


def test_build_unknown_scanner_raises():
    with pytest.raises(KeyError):
        build_scanners(["does-not-exist"])


def test_ash_does_not_require_aws():
    [ash] = build_scanners(["ash"], source_dir=".")
    assert ash.requires_aws is False


def test_missing_binary_is_skipped(monkeypatch):
    [prowler] = build_scanners(["prowler"])
    # Force "not installed".
    monkeypatch.setattr(prowler, "binary", "definitely-not-a-real-binary-xyz")
    result = prowler.run(None, "/tmp")
    assert result.status is ScanStatus.SKIPPED
    assert "not found" in result.message


def test_hardeneks_skips_without_cluster():
    [hardeneks] = build_scanners(["hardeneks"], eks_cluster=None)
    # is_available() checks PATH; force available so we reach the no-cluster guard.
    hardeneks.binary = ""  # empty binary => is_available() True
    result = hardeneks.run(None, "/tmp")
    assert result.status is ScanStatus.SKIPPED
    assert "cluster" in result.message.lower()


def test_default_scanner_timeout_is_one_hour():
    assert DEFAULT_SCANNER_TIMEOUT_SECONDS == 60 * 60


def test_exec_with_progress_emits_heartbeat(capsys):
    scanner = DummyScanner()
    proc = scanner._exec(
        [sys.executable, "-c", "import time; time.sleep(0.12)"],
        progress=True,
        progress_label="dummy",
        heartbeat_interval=0.02,
    )

    assert proc.returncode == 0
    assert "dummy still running" in capsys.readouterr().out


def test_exec_with_progress_can_stream_scanner_output(capsys):
    scanner = DummyScanner()
    scanner.show_scanner_output = True
    proc = scanner._exec(
        [sys.executable, "-c", "print('scanner says hi')"],
        progress=True,
        progress_label="dummy",
        heartbeat_interval=1,
    )

    captured = capsys.readouterr().out
    assert proc.returncode == 0
    assert proc.stdout.strip() == "scanner says hi"
    assert "[dummy] scanner says hi" in captured


def test_progress_heartbeat_reports_last_output_age(capsys):
    DummyScanner._print_progress_heartbeat("dummy", elapsed_seconds=90, lines_seen=3, last_output_age=35)

    captured = capsys.readouterr().out
    assert "dummy still running" in captured
    assert "1m 30s" in captured
    assert "last scanner output 35s ago" in captured


def test_cloudsplaining_uses_download_directory_and_results_file(tmp_path):
    scanner = CloudsplainingScanner()
    commands = []

    def fake_exec(cmd, **kwargs):
        commands.append(cmd)
        out_dir = tmp_path / "cloudsplaining"
        if cmd[:2] == ["cloudsplaining", "download"]:
            (out_dir / "default.json").write_text("{}")
        elif cmd[:2] == ["cloudsplaining", "scan"]:
            (out_dir / "iam-results-default.json").write_text(
                '{"results":{"AdminPolicy":{"PrivilegeEscalation":["iam:CreateAccessKey"]}}}'
            )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    scanner._exec = fake_exec

    result = scanner._scan(None, str(tmp_path))

    assert result.status is ScanStatus.OK
    assert len(result.findings) == 1
    assert commands[0] == ["cloudsplaining", "download", "--output", str(tmp_path / "cloudsplaining")]
    assert commands[1] == [
        "cloudsplaining",
        "scan",
        "--input-file",
        str(tmp_path / "cloudsplaining" / "default.json"),
        "--output",
        str(tmp_path / "cloudsplaining"),
        "--skip-open-report",
    ]


class _Proc:
    def __init__(self, returncode=0, stderr="", stdout=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


def _write_module_output(out_dir, module):
    json_dir = os.path.join(out_dir, "cloudfox-output", "aws", "acct", "json")
    os.makedirs(json_dir, exist_ok=True)
    with open(os.path.join(json_dir, f"{module}.json"), "w") as fh:
        json.dump([], fh)


def _cloudfox_with(monkeypatch, failing_module, stderr, returncode=1):
    """CloudFox scanner whose named module exits non-zero with the given stderr.

    Successful modules write an (empty) JSON file into CloudFox's real output tree, so
    the wrapper sees the same "some modules produced evidence" state as a live run.
    """
    scanner = CloudfoxScanner()

    def fake_exec(cmd, **_kwargs):
        out_dir, module = cmd[3], cmd[-1]
        if module == failing_module:
            return _Proc(returncode, stderr=stderr)
        _write_module_output(out_dir, module)
        return _Proc(0)

    monkeypatch.setattr(scanner, "_exec", fake_exec)
    return scanner


def test_cloudfox_surfaces_the_reason_a_module_failed(monkeypatch, tmp_path):
    """Regression: only the exit code survived, so 'endpoints (exit 1)' was unactionable."""
    stderr = "Error: AccessDeniedException: User is not authorized to perform apprunner:ListServices"
    scanner = _cloudfox_with(monkeypatch, "endpoints", stderr)

    result = scanner._scan(None, str(tmp_path))

    assert result.status is ScanStatus.ERROR  # could not do its whole job
    assert "endpoints" in result.message
    assert "access denied" in result.message
    assert "apprunner:ListServices" in result.message  # the actual missing permission
    assert "least-privilege-policy.json" in result.message  # what to do about it
    assert "4 of 5 modules completed" in result.message


def test_cloudfox_non_permission_failure_reports_its_own_stderr(monkeypatch, tmp_path):
    scanner = _cloudfox_with(monkeypatch, "workloads", "panic: runtime error: index out of range")

    result = scanner._scan(None, str(tmp_path))

    assert "index out of range" in result.message
    assert "access denied" not in result.message
    assert "least-privilege-policy.json" not in result.message  # no IAM hint when IAM isn't the cause


def test_cloudfox_clean_run_has_no_failure_message(monkeypatch, tmp_path):
    scanner = _cloudfox_with(monkeypatch, "none-of-them", "")

    result = scanner._scan(None, str(tmp_path))

    assert result.status is ScanStatus.OK
    assert result.message == ""


def test_cloudfox_decodes_signal_deaths(monkeypatch, tmp_path):
    """Regression: 'endpoints: exit -11' was meaningless. -11 is SIGSEGV, not an exit code."""
    scanner = _cloudfox_with(monkeypatch, "endpoints", "", returncode=-11)

    result = scanner._scan(None, str(tmp_path))

    assert "SIGSEGV" in result.message
    assert "signal 11" in result.message
    assert "exit -11" not in result.message
    assert "least-privilege-policy.json" not in result.message  # not an IAM problem


def test_cloudfox_names_upstream_defects_as_not_operator_fixable(monkeypatch, tmp_path):
    """The real failure from a live scan: CloudFox parses IAM policy JSON as YAML."""
    stderr = "2026/08/17 14:12:52 error unmarshalling YAML: yaml: line 3: could not find expected ':'"
    scanner = _cloudfox_with(monkeypatch, "role-trusts", stderr)

    result = scanner._scan(None, str(tmp_path))

    assert "unmarshalling YAML" in result.message
    assert "defect inside CloudFox" in result.message
    assert "--scanners prowler,cloudsplaining,resilience" in result.message  # the way out
    assert "least-privilege-policy.json" not in result.message  # never blame IAM for a crash


def test_cloudfox_reports_both_failure_kinds_at_once(monkeypatch, tmp_path):
    """An account can hit a permissions gap and an upstream crash in the same run."""
    scanner = CloudfoxScanner()

    def fake_exec(cmd, **_kwargs):
        module = cmd[-1]
        if module == "endpoints":
            return _Proc(-11)
        if module == "role-trusts":
            return _Proc(1, stderr="error unmarshalling YAML: yaml: line 3")
        if module == "workloads":
            return _Proc(1, stderr="AccessDeniedException: not authorized to perform apprunner:ListServices")
        _write_module_output(cmd[3], module)
        return _Proc(0)

    monkeypatch.setattr(scanner, "_exec", fake_exec)
    result = scanner._scan(None, str(tmp_path))

    assert "2 of 5 modules completed" in result.message
    assert "least-privilege-policy.json" in result.message  # the fixable half
    assert "defect inside CloudFox" in result.message  # the unfixable half
