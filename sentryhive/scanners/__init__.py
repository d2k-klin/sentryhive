"""Scanner registry — maps names to scanner factories.

Adding a 5th scanner is one entry here plus a wrapper module.
"""

from __future__ import annotations

from collections.abc import Callable

from sentryhive.scanners.ash import AshScanner
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus, session_env
from sentryhive.scanners.cloudsplaining import CloudsplainingScanner
from sentryhive.scanners.hardeneks import HardeneksScanner
from sentryhive.scanners.prowler import ProwlerScanner

#: Registered scanners. Values are factories so per-run options can be injected.
REGISTRY: dict[str, Callable[..., Scanner]] = {
    "prowler": ProwlerScanner,
    "cloudsplaining": CloudsplainingScanner,
    "hardeneks": HardeneksScanner,
    "ash": AshScanner,
}

ALL_SCANNERS = list(REGISTRY.keys())


def build_scanners(
    names: list[str],
    *,
    eks_cluster: str | None = None,
    kubeconfig: str | None = None,
    source_dir: str | None = None,
) -> list[Scanner]:
    """Instantiate the requested scanners, passing through per-scanner options."""
    scanners: list[Scanner] = []
    for name in names:
        factory = REGISTRY.get(name)
        if factory is None:
            raise KeyError(f"unknown scanner '{name}'. Available: {', '.join(ALL_SCANNERS)}")
        if name == "hardeneks":
            scanners.append(factory(cluster=eks_cluster, kubeconfig=kubeconfig))
        elif name == "ash":
            scanners.append(factory(source_dir=source_dir))
        else:
            scanners.append(factory())
    return scanners


__all__ = [
    "REGISTRY",
    "ALL_SCANNERS",
    "build_scanners",
    "Scanner",
    "ScanResult",
    "ScanStatus",
    "session_env",
]
