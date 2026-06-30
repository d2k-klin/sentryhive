# Installation

SentryHive runs three ways. **Docker is recommended** — it bundles every scanner so
you install nothing else.

Platform support: Linux and macOS (and Windows via WSL2). The bundled scanners and
WeasyPrint are not supported on native Windows.

## Docker (recommended)

The image bundles Prowler, Cloudsplaining, hardeneks, ASH, the AWS CLI, kubectl, and
WeasyPrint (for PDF).

```bash
git clone https://github.com/d2k-klin/sentryhive
cd sentryhive
docker compose build
docker compose run --rm sentryhive --version
```

Or build the image directly:

```bash
docker build -t sentryhive:latest .
docker run --rm sentryhive:latest --version
```

Image tags follow the release version (e.g. `sentryhive:0.1.0`) plus `latest`.

## From source

For contributors and anyone who wants to read the code before running it.

```bash
git clone https://github.com/d2k-klin/sentryhive
cd sentryhive
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"
sentryhive --version
```

The underlying scanners (`prowler`, `cloudsplaining`, `hardeneks`, `ash`) must be on
your `PATH` for the corresponding scans to run; SentryHive reports any that are
missing as `skipped`. PDF output additionally needs WeasyPrint's system libraries
(`pango`, `cairo`) — on macOS: `brew install pango`; on Debian/Ubuntu:
`apt-get install libpango-1.0-0 libpangocairo-1.0-0 libcairo2`.

## PyPI

> Planned. When published:

```bash
pip install sentryhive          # core
pip install "sentryhive[pdf]"   # with PDF output
sentryhive --version
```

## Verify

Every method ends the same way:

```bash
sentryhive --version
sentryhive scanners      # lists bundled scanners and their roles
```
