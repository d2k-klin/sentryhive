# SentryHive — single image bundling all scanners so users install nothing but Docker.
FROM python:3.12-slim

# Pinned tool versions — bumped weekly by .github/workflows/tool-watch.yml.
ARG PROWLER_VERSION=5.36.0
# 0.9.x requires boto3>=1.41, while Prowler 5.36.0 pins boto3==1.40.61.
ARG CLOUDSPLAINING_VERSION=0.8.2
ARG HARDENEKS_VERSION=1.1.1
ARG ASH_VERSION=3.5.8
ARG CLOUDFOX_VERSION=2.0.5
ARG KUBESCAPE_VERSION=4.0.11
ARG AWSCLI_VERSION=2.36.7
ARG KUBECTL_VERSION=v1.36.3
ARG PROWLER_VERSION=5.33.1
ARG CLOUDSPLAINING_VERSION=0.9.1
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
#  - gcc/libc6-dev: build Prowler's zstd dependency on ARM
#  - curl/unzip: AWS CLI & kubectl install
#  - libpango/cairo/gdk-pixbuf + fonts: WeasyPrint PDF rendering (kept local, no network)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git gcc libc6-dev curl unzip ca-certificates \
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

# CloudFox and Kubescape publish architecture-specific binaries. Verify the
# official release digests before installing either one.
RUN BARCH="$(dpkg --print-architecture)" \
    && case "$BARCH" in \
         amd64) CLOUDFOX_SHA="3cdc5a1a94ff14eb8df04d3dc8f9eca7db232a1315ceb8a7de26e4cb13e32fd5"; \
                KUBESCAPE_SHA="9f3fd186dfddd9147668b520a0ca7a513e1ff74ee399047c91d29420b0e5c0a9" ;; \
         arm64) CLOUDFOX_SHA="fcebd90329a8bb2f61c00cfb131572a44483251da532f1363a0ceb56541cd4ca"; \
                KUBESCAPE_SHA="eb58720f835823db498496a7f32896d68d92e948a8f50361642ab8266022e16b" ;; \
         *) echo "unsupported architecture: $BARCH" >&2; exit 1 ;; \
       esac \
    && curl -sSL "https://github.com/BishopFox/cloudfox/releases/download/v${CLOUDFOX_VERSION}/cloudfox-linux-${BARCH}.zip" \
       -o /tmp/cloudfox.zip \
    && echo "${CLOUDFOX_SHA}  /tmp/cloudfox.zip" | sha256sum -c - \
    && unzip -q /tmp/cloudfox.zip -d /tmp/cloudfox \
    && install -m 0755 /tmp/cloudfox/cloudfox/cloudfox /usr/local/bin/cloudfox \
    && curl -sSL "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_${BARCH}" \
       -o /tmp/kubescape \
    && echo "${KUBESCAPE_SHA}  /tmp/kubescape" | sha256sum -c - \
    && install -m 0755 /tmp/kubescape /usr/local/bin/kubescape \
    && rm -rf /tmp/cloudfox /tmp/cloudfox.zip /tmp/kubescape

# Isolate scanner CLIs from SentryHive's app dependencies. Several scanners pin
# older boto3/typer versions that conflict with the orchestrator's dependencies.
RUN python -m venv /opt/scanner-venv \
    && /opt/scanner-venv/bin/pip install --upgrade pip "setuptools>=83" \
    && /opt/scanner-venv/bin/pip install \
        "prowler==${PROWLER_VERSION}" \
        "cloudsplaining==${CLOUDSPLAINING_VERSION}" \
        "hardeneks==${HARDENEKS_VERSION}" \
        "automated-security-helper @ git+https://github.com/awslabs/automated-security-helper.git@v${ASH_VERSION}"

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
