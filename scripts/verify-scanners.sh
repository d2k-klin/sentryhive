#!/usr/bin/env bash
# scripts/verify-scanners.sh — assert bundled tools are installed at Dockerfile pins.
#
# Used in CI (scanner-integrity job) to confirm the Docker image wires all tools
# correctly without performing an actual scan. Exits non-zero on any failure.
set -euo pipefail

FAIL=0
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${SENTRYHIVE_DOCKERFILE:-$ROOT_DIR/Dockerfile}"
SCANNER_PYTHON="${SENTRYHIVE_SCANNER_PYTHON:-python}"

pin() {
  sed -n "s/^ARG $1=//p" "$DOCKERFILE"
}

check_python_tool() {
  local name="$1"
  local cmd="$2"
  local package="$3"
  local expected="$4"

  printf "%-20s" "$name"
  if ! command -v "$cmd" &>/dev/null; then
    echo "MISSING — '$cmd' not found on PATH"
    FAIL=1
    return
  fi

  local actual
  actual="$("$SCANNER_PYTHON" -c "from importlib.metadata import version; print(version('$package'))")"
  if [[ "$actual" == "$expected" ]]; then
    echo "OK — $actual"
  else
    echo "WRONG VERSION — expected $expected, got $actual"
    FAIL=1
  fi
}

check_binary_version() {
  local name="$1"
  local cmd="$2"
  local expected="$3"
  shift 3

  printf "%-20s" "$name"
  if ! command -v "$cmd" &>/dev/null; then
    echo "MISSING — '$cmd' not found on PATH"
    FAIL=1
    return
  fi

  local output
  output="$("$cmd" "$@" 2>&1 | head -1)" || true
  if [[ "$output" == *"$expected"* ]]; then
    echo "OK — $output"
  else
    echo "WRONG VERSION — expected $expected, got ${output:-unknown}"
    FAIL=1
  fi
}

echo "=== SentryHive Scanner Integrity Check ==="
echo

check_python_tool "prowler" prowler prowler "$(pin PROWLER_VERSION)"
check_python_tool "cloudsplaining" cloudsplaining cloudsplaining "$(pin CLOUDSPLAINING_VERSION)"
check_python_tool "hardeneks" hardeneks hardeneks "$(pin HARDENEKS_VERSION)"
check_python_tool "ash" ash automated-security-helper "$(pin ASH_VERSION)"
check_binary_version "cloudfox" cloudfox "$(pin CLOUDFOX_VERSION)" --version
check_binary_version "kubescape" kubescape "$(pin KUBESCAPE_VERSION)" version
check_binary_version "aws-cli" aws "aws-cli/$(pin AWSCLI_VERSION)" --version
check_binary_version "kubectl" kubectl "$(pin KUBECTL_VERSION)" version --client

echo

# Verify the sentryhive package itself is importable and reports a version.
printf "%-20s" "sentryhive"
if python -c "from sentryhive import __version__; print(f'OK — v{__version__}')" 2>/dev/null; then
  :
else
  echo "FAILED — cannot import sentryhive"
  FAIL=1
fi

echo
if [[ $FAIL -ne 0 ]]; then
  echo "✗ Some scanner integrity checks failed."
  exit 1
fi
echo "✓ All scanner integrity checks passed."
