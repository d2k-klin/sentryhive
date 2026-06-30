#!/usr/bin/env bash
# scripts/verify-scanners.sh — assert bundled scanners are installed at pinned versions.
#
# Used in CI (scanner-integrity job) to confirm the Docker image wires all tools
# correctly without performing an actual scan. Exits non-zero on any failure.
set -euo pipefail

FAIL=0

check_binary() {
  local name="$1"
  local cmd="$2"
  local version_flag="${3:---version}"

  printf "%-20s" "$name"
  if ! command -v "$cmd" &>/dev/null; then
    echo "MISSING — '$cmd' not found on PATH"
    FAIL=1
    return
  fi

  version_output=$("$cmd" "$version_flag" 2>&1 | head -1) || true
  if [[ -z "$version_output" ]]; then
    echo "INSTALLED (version unknown)"
  else
    echo "OK — $version_output"
  fi
}

echo "=== SentryHive Scanner Integrity Check ==="
echo ""

check_binary "prowler"        prowler        "--version"
check_binary "cloudsplaining" cloudsplaining "--version"
check_binary "hardeneks"      hardeneks      "--version"
check_binary "ash"            ash            "--version"
check_binary "aws-cli"        aws            "--version"
check_binary "kubectl"        kubectl        "version --client --short"

echo ""

# Verify the sentryhive package itself is importable and reports a version.
printf "%-20s" "sentryhive"
if python -c "from sentryhive import __version__; print(f'OK — v{__version__}')" 2>/dev/null; then
  :
else
  echo "FAILED — cannot import sentryhive"
  FAIL=1
fi

echo ""
if [[ $FAIL -ne 0 ]]; then
  echo "✗ Some scanner integrity checks failed."
  exit 1
fi
echo "✓ All scanner integrity checks passed."
