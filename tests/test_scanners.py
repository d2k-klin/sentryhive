import sys

import pytest

from sentryhive.scanners import ALL_SCANNERS, build_scanners
from sentryhive.scanners.base import Scanner, ScanStatus


class DummyScanner(Scanner):
    binary = ""

    def _scan(self, ctx, workdir):
        raise NotImplementedError


def test_registry_has_all_four():
    assert set(ALL_SCANNERS) == {"prowler", "cloudsplaining", "hardeneks", "ash"}


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
