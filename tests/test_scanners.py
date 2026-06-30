import pytest

from sentryhive.scanners import ALL_SCANNERS, build_scanners
from sentryhive.scanners.base import ScanStatus


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
