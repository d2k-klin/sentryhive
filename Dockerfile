# SentryHive — single image bundling all scanners so users install nothing but Docker.
FROM python:3.12-slim

# Pinned tool versions — bumped weekly by .github/workflows/tool-watch.yml.
ARG PROWLER_VERSION=5.33.1
ARG CLOUDSPLAINING_VERSION=0.8.2
ARG HARDENEKS_VERSION=1.1.0
ARG ASH_VERSION=11.0.2
ARG AWSCLI_VERSION=2.35.21
ARG KUBECTL_VERSION=v1.36.2

LABEL org.opencontainers.image.title="SentryHive" \
      org.opencontainers.image.description="AWS security scanning toolkit — one image, one report." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/d2k-klin/sentryhive"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/sentryhive-venv/bin:/opt/scanner-venv/bin:$PATH"

# System deps:
#  - git: ASH/IaC checks
#  - curl/unzip: AWS CLI & kubectl install
#  - libpango/cairo/gdk-pixbuf + fonts: WeasyPrint PDF rendering (kept local, no network)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl unzip ca-certificates \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev \
        fonts-dejavu fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 (needed by hardeneks for `aws eks update-kubeconfig`).
RUN ARCH="$(uname -m)" \
    && curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}-${AWSCLI_VERSION}.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip

# kubectl (hardeneks talks to the cluster API).
RUN KARCH="$(dpkg --print-architecture)" \
    && curl -sSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${KARCH}/kubectl" \
       -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# Isolate scanner CLIs from SentryHive's app dependencies. Several scanners pin
# older boto3/typer versions that conflict with the orchestrator's dependencies.
RUN python -m venv /opt/scanner-venv \
    && /opt/scanner-venv/bin/pip install --upgrade pip "setuptools<81" \
    && /opt/scanner-venv/bin/pip install \
        "prowler==${PROWLER_VERSION}" \
        "cloudsplaining==${CLOUDSPLAINING_VERSION}" \
        "hardeneks==${HARDENEKS_VERSION}" \
        "automated-security-helper==${ASH_VERSION}"

RUN python -m venv /opt/sentryhive-venv \
    && /opt/sentryhive-venv/bin/pip install --upgrade pip

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentryhive ./sentryhive
RUN /opt/sentryhive-venv/bin/pip install ".[pdf]"

# Reports land here; mount a host volume over it (see docker-compose.yml).
VOLUME ["/app/reports"]

ENTRYPOINT ["sentryhive"]
CMD ["--help"]
