# ── Stage 1: Download security tools (pinned versions) ───────────────────
FROM debian:bookworm-slim AS tooling

ARG COSIGN_VERSION=v2.4.1
ARG TRIVY_VERSION=0.69.3
ARG SYFT_VERSION=v1.19.0
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# cosign — pinned release
RUN curl -sSfL \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" \
    -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

# trivy — pinned release via official install script
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# syft — pinned release
RUN curl -sSfL \
    "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_$(echo ${SYFT_VERSION} | tr -d v)_linux_${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin syft \
    && chmod +x /usr/local/bin/syft


# ── Stage 2: Runtime image ────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Copy pinned tools from tooling stage
COPY --from=tooling /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=tooling /usr/local/bin/trivy  /usr/local/bin/trivy
COPY --from=tooling /usr/local/bin/syft   /usr/local/bin/syft

# Install skopeo from debian packages (version pinned via apt)
# and jq for debugging / scripting
RUN apt-get update && apt-get install -y --no-install-recommends \
    skopeo \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install tif Python package
COPY . /src
RUN pip install --no-cache-dir /src && rm -rf /src

# Non-root user
RUN useradd -m -s /bin/bash tif
USER tif

# OCI image labels
LABEL org.opencontainers.image.title="tif" \
      org.opencontainers.image.description="The Trust Gate for Container Images — verify signatures, SBOMs, vulnerabilities, and compliance in one command" \
      org.opencontainers.image.source="https://github.com/cvemula1/tif" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.documentation="https://github.com/cvemula1/tif#readme"

ENTRYPOINT ["tif"]
CMD ["--help"]
