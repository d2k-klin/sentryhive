# Configuration

SentryHive is configured primarily through CLI flags ([usage](usage.md)). A few
behaviors can also be set via environment variables — useful in CI and Docker.

## Environment variables

### AWS (standard SDK variables)

| Variable | Purpose |
|----------|---------|
| `AWS_PROFILE` | Profile to use (equivalent to `--profile`). |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Static credentials. |
| `AWS_SESSION_TOKEN` | Session token for temporary credentials. |
| `AWS_DEFAULT_REGION` | Default region if `--regions` is not given. |

### SentryHive

| Variable | Equivalent flag | Purpose |
|----------|-----------------|---------|
| `SENTRYHIVE_EKS_CLUSTER` | `--clusters` (single) | Default EKS cluster for hardeneks. |
| `SENTRYHIVE_SOURCE_DIR` | `--source-dir` | Default directory for ASH. |
| `KUBECONFIG` | `--kubeconfig` | kubeconfig path for EKS access. |

CLI flags always override environment variables.

## Example: CI environment

```bash
export AWS_DEFAULT_REGION=eu-central-1
sentryhive scan --role-arn "$AUDIT_ROLE_ARN" --yes --fail-on high --pdf
```

An example env file is provided at
[`examples/configs/sentryhive.env.example`](../examples/configs/sentryhive.env.example).

## Config file

> A declarative config file (e.g. `sentryhive.yml`) is planned. For now, drive runs
> with flags and environment variables. Track this in the project roadmap.
