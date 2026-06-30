# SentryHive — single image bundling all scanners so users install nothing but Docker.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="SentryHive" \
      org.opencontainers.image.description="AWS security scanning toolkit — one image, one report." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/d2k-klin/sentryhive"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

# System deps: git for ASH/IaC checks, curl/unzip for the AWS CLI & kubectl.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 (needed by hardeneks for `aws eks update-kubeconfig`).
RUN ARCH="$(uname -m)" \
    && curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip

# kubectl (hardeneks talks to the cluster API).
RUN KARCH="$(dpkg --print-architecture)" \
    && curl -sSL "https://dl.k8s.io/release/$(curl -sSL https://dl.k8s.io/release/stable.txt)/bin/linux/${KARCH}/kubectl" \
       -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# Isolated venv for all the Python scanners + SentryHive itself.
RUN python -m venv /opt/venv
RUN pip install --upgrade pip \
    && pip install \
        "prowler" \
        "cloudsplaining" \
        "hardeneks" \
        "automated-security-helper"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentryhive ./sentryhive
RUN pip install .

# Reports land here; mount a host volume over it (see docker-compose.yml).
VOLUME ["/app/reports"]

ENTRYPOINT ["sentryhive"]
CMD ["--help"]
