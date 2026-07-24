---
description: >
  Weekly check for new releases of the scanners SentryHive bundles (Prowler,
  Cloudsplaining, CloudFox, HardenEKS, Kubescape, AWS ASH) plus aws-cli and
  kubectl. Bumps the pinned ARGs in the Dockerfile, adapts
  sentryhive/scanners/*.py + normalize.py if a release changed CLI flags or
  output format, validates, and opens a draft PR. No-op if nothing's outdated.
on:
  schedule: weekly on monday around 06:00
  workflow_dispatch:
permissions:
  contents: read
  copilot-requests: write
engine: copilot
tools:
  edit:
  bash: ["*"]
network:
  allowed:
    - defaults
    - github
    - python
    - "dl.k8s.io"
    - "awscli.amazonaws.com"
timeout-minutes: 45
safe-outputs:
  create-pull-request:
    title-prefix: "tools: "
    labels: [dependencies]
    if-no-changes: ignore
---

# Tool Watch

SentryHive bundles six OSS scanner CLIs plus aws-cli and kubectl, pinned as
`ARG` lines at the top of `./Dockerfile` (`PROWLER_VERSION`,
`CLOUDSPLAINING_VERSION`, `HARDENEKS_VERSION`, `ASH_VERSION`,
`CLOUDFOX_VERSION`, `KUBESCAPE_VERSION`, `AWSCLI_VERSION`, `KUBECTL_VERSION`). Each tool's CLI output is parsed by a
matching wrapper in `sentryhive/scanners/` (`prowler.py`, `cloudsplaining.py`,
`cloudfox.py`, `hardeneks.py`, `kubescape.py`, `ash.py`) and normalized in `sentryhive/normalize.py`.

1. Read the current pins from the Dockerfile.
2. For each tool, find the latest released version:
   - prowler, cloudsplaining, hardeneks: PyPI JSON API
     (`https://pypi.org/pypi/<name>/json` → `info.version`)
   - AWS ASH: latest GitHub release for `awslabs/automated-security-helper`
     (the similarly named PyPI package is unrelated; never install it)
   - CloudFox: latest GitHub release for `BishopFox/cloudfox`
   - Kubescape: latest GitHub release for `kubescape/kubescape`
   - aws-cli: GitHub tags for `aws/aws-cli`
   - kubectl: `https://dl.k8s.io/release/stable.txt`
3. If every pin is already current, say so and stop — do not edit anything.
4. Otherwise, for each outdated tool, read its release notes / changelog
   between the current pin and the new version, looking specifically for: CLI
   flag changes, output format/schema changes (JSON structure, exit codes),
   or new dependency version requirements (e.g. a scanner bumping its `boto3`
   pin) — anything that could break the corresponding wrapper in
   `sentryhive/scanners/`, the parsing in `sentryhive/normalize.py`, or
   compatibility between the Python tools installed into the same venv.
5. Bump the `ARG` pin(s) in the Dockerfile. Install ASH from its official
   GitHub release tag. Install CloudFox and Kubescape from their official
   architecture-specific release assets and update the pinned SHA-256 values.
   If a release changed something
   the wrapper/normalizer depends on, update that code to match — don't bump
   a pin blind if it would silently break parsing. If two tools' new
   versions have a dependency conflict (as happened between prowler and
   cloudsplaining before), hold the conflicting one back to the newest
   version that's still compatible and note why in the PR description.
6. Validate before finishing:
   - `pip install -e ".[dev]"` then `ruff check .` and `ruff format --check .`
   - `pytest --cov=sentryhive --cov-report=term-missing`
   - Install the newly-pinned scanner CLI versions into a fresh venv
     (matching how the Dockerfile installs them) and run
     `./scripts/verify-scanners.sh` to confirm they're still on `PATH` and
     reporting versions correctly.
   - Run `pip-audit` against both the app and scanner environments. The scanner
     environment may temporarily ignore `GHSA-537c-gmf6-5ccf` only while the
     latest Prowler still pins `cryptography==46.0.7`; remove the exception as
     soon as Prowler permits `cryptography>=48.0.1`.
7. If validation passes, commit your changes so a PR titled
   "tools: bump toolname x.y.z -> x.y.z" (or similar for multiple tools) gets
   opened, with a description listing each bump, a link to its release
   notes, and any code changes made in response.
8. If validation fails and you can't safely resolve it (e.g. the new release
   needs AWS credentials to fully exercise, or the breaking change needs a
   bigger redesign than is safe to automate), still commit what you have and
   clearly describe in the PR description exactly what's failing and why, so
   a human can finish it. Never leave the working tree edited without
   something to show for it.
