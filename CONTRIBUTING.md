# Contributing to SentryHive

Thanks for helping make AWS security scanning less painful.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
```

## Adding a scanner

SentryHive is built so a fifth scanner is a small, self-contained change:

1. **Parser** — add `parse_<tool>()` to [`sentryhive/normalize.py`](sentryhive/normalize.py) that turns the tool's native output into a list of `Finding` objects. Be defensive: tool output schemas drift, so read fields best-effort and degrade gracefully rather than raising.
2. **Wrapper** — add `sentryhive/scanners/<tool>.py` subclassing `Scanner`. Set `name`, `binary`, and `requires_aws`; implement `_scan(ctx, workdir)` to run the tool via `self._exec(...)`, load its output, and return a `ScanResult`.
3. **Register** — add it to `REGISTRY` in [`sentryhive/scanners/__init__.py`](sentryhive/scanners/__init__.py) (and wire any per-scanner options in `build_scanners`).
4. **Image** — add the tool to the [`Dockerfile`](Dockerfile).
5. **Tests** — add a parser test with a representative fixture in `tests/`.

You should not need to touch the aggregator, report layer, or CLI.

## Conventions

- Code style is enforced by `ruff` (config in `pyproject.toml`). Run `ruff check --fix .`.
- Keep one scanner failure from aborting a run — exceptions in `_scan` are caught by the base class and surfaced as an `error` status. Don't swallow them yourself.
- New findings must populate `severity`, `tool`, `check`, and `resource` so dedup and ranking work.
- **Docs change in the same PR as the code.** If you change a flag or behavior, update the relevant `docs/` page and the README.

## Commit & PR conventions

- Write imperative commit subjects ("Add hardeneks preflight check"), present tense.
- Each PR should be focused and reviewable. Fill in the PR template checklist.
- **Add a `CHANGELOG.md` entry** under `## [Unreleased]` for any user-facing change,
  in the right group (`Added`/`Changed`/`Deprecated`/`Removed`/`Fixed`/`Security`).
  Flag permission/credential/scanner-behavior changes under `Security`.

## PR checklist

- [ ] Tests added/updated and `pytest` passes
- [ ] `ruff check .` is clean
- [ ] Docs updated (README + relevant `docs/` page)
- [ ] `CHANGELOG.md` `[Unreleased]` entry added

## Tests

```bash
pytest                      # all tests
pytest --cov=sentryhive     # with coverage
```

CI runs lint, tests, a Docker build, and a docs link-check on every PR.

## Reporting bugs / features

Open an issue with the bug-report or feature-request template. For security issues,
see [SECURITY.md](SECURITY.md) — do **not** open a public issue. Be a good community
member: see the [Code of Conduct](CODE_OF_CONDUCT.md).
