<div align="center">

# TIF

**The Trust Gate for Container Images**

One command. One artifact. Zero noise.

[![PyPI](https://img.shields.io/pypi/v/tif?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/tif/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fcvemula1%2Ftif-blue?logo=docker)](https://ghcr.io/cvemula1/tif)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/cvemula1/tif?style=social)](https://github.com/cvemula1/tif)

</div>

**TIF (Trusted Image Framework)** is an open-source CLI that verifies container image trust -- signer identity, provenance, digest immutability, SBOM, and policy -- before build or deployment.

## Why TIF?

Scanner alert fatigue is real. 70% of CVE alerts are false positives. 85% are in packages never loaded at runtime. Teams stop looking.

TIF cuts through the noise: one command produces a **compliance-ready Trust Card** -- a signed, scored JSON artifact stored with your image -- showing only the vulnerabilities you can actually fix.

> For teams with SOC 2, FedRAMP, or NIST 800-190 requirements: TIF's Trust Card is the auditable proof your compliance team needs.

## Quick Start

### Docker (recommended — all tools included, zero setup)

Multi-arch images for **linux/amd64** and **linux/arm64** (Apple Silicon). All trust tools (cosign, trivy, syft, skopeo) are pre-installed.

```bash
# Primary registry: GHCR (signed, SBOM-attested)
docker run --rm ghcr.io/cvemula1/tif verify alpine:3.20 --only-fixable
docker run --rm ghcr.io/cvemula1/tif verify python:3.12-slim --policy-pack nist-800-190 --ci
docker run --rm ghcr.io/cvemula1/tif demo
```

### Alias for convenience

```bash
alias tif='docker run --rm ghcr.io/cvemula1/tif'
tif verify registry.io/myapp:1.0 --only-fixable --policy-pack cis-l2 --ci
```

### pip (lightweight — some gates need external tools)

```bash
pip install tif
tif demo                                          # works immediately (no tools needed)
tif verify registry.io/myapp:1.0 --only-fixable  # full verification (needs cosign + trivy)
```

## Verify TIF Itself

TIF signs its own Docker images and generates SBOMs — we eat our own dog food.

```bash
# Verify TIF's image signature before running it
cosign verify \
  --certificate-identity-regexp=https://github.com/cvemula1/tif/.* \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/cvemula1/tif:latest

# Retrieve TIF's own SBOM
cosign verify-attestation --type spdx ghcr.io/cvemula1/tif:latest \
  | jq -r '.payload' | base64 -d | jq .
```

### What `tif verify` checks

| Gate | What It Does | Tool Used |
|------|-------------|-----------|
| **Signature** | Verify image is signed by trusted identity | Cosign (keyless or key-based) |
| **Vulnerabilities** | Scan for CVEs, gate on severity thresholds | Trivy or Grype |
| **SBOM** | Check SBOM is attached and complete | Cosign + Trivy/Syft |
| **Attestation** | Verify SLSA provenance and build origin | slsa-verifier / Cosign |
| **Image Security** | Check rootless, FROM scratch, read-only rootfs | Docker / Skopeo |
| **End-of-Life** | Check base image EOL status via endoflife.date API | endoflife.date / NIST |
| **Policy** | Evaluate against compliance frameworks | OPA/Rego or built-in |

### Example Output

```
╭──────────────────── TIF Trust Card ─────────────────────╮
│  [PASS]  Trust Score: 87/100  —  PASS                   │
│  registry.example.com/myapp:1.2.0                       │
╰─────────────────────────────────────────────────────────╯

  Trust Gates
  ┌───────────────────┬─────────┬──────────────────────────────────────┐
  │ Gate              │ Verdict │ Reason                               │
  ├───────────────────┼─────────┼──────────────────────────────────────┤
  │ Signature         │ [PASS]  │ Image signature verified via Cosign  │
  │ Vulnerabilities   │ [WARN]  │ 2 high CVEs within threshold         │
  │ SBOM              │ [PASS]  │ spdx-2.3: 127 packages, 95%         │
  │ Attestation       │ [PASS]  │ SLSA Level 3 provenance verified     │
  │ Image Security    │ [PASS]  │ rootless, FROM scratch, read-only    │
  │ End-of-Life       │ [PASS]  │ python 3.12 supported (EOL 2028-10)  │
  │ Policy            │ [PASS]  │ All policy checks passed             │
  └───────────────────┴─────────┴──────────────────────────────────────┘

  Signature:       [PASS] Verified  Signer: cosign
  Vulnerabilities: 2 high, 5 medium, 12 low (trivy)
    ↳ 38 additional CVEs suppressed (no fix available)
  Top fixable CVEs:
    CVE-2024-3094 openssl@3.0.1 → 3.0.2 (CVSS 9.8)
    CVE-2024-1234 libcurl@8.4.0 → 8.5.0 (CVSS 7.5)
  SBOM:            spdx-2.3 — 127 packages, completeness 95%
  Security:        rootless, FROM scratch, read-only rootfs
  EOL:             python 3.12 supported (EOL: 2028-10-01)
```

## Reducing Alert Fatigue

85% of CVEs flagged by scanners are in packages never loaded at runtime. Use `--only-fixable` to count only CVEs that have an available patch — the ones your team can actually act on today:

```bash
# Without --only-fixable: 183 findings, team ignores scanner
tif verify myapp:latest
# → Vulnerabilities: 12 critical, 47 high, 124 medium (trivy)

# With --only-fixable: only counts actionable CVEs
tif verify myapp:latest --only-fixable
# → Vulnerabilities: 1 critical, 3 high, 8 medium (trivy)
# → ↳ 50 additional CVEs suppressed (no fix available)
# → Top fixable CVEs:
# →   CVE-2024-3094 openssl@3.0.1 → 3.0.2 (CVSS 9.8)
```

## Storing the Trust Card with Your Image

After verification, use `tif push` to enrich your image with trust labels and push to a registry. The Trust Card travels with the image — visible to anyone via `docker inspect`, retrievable by compliance teams via `tif inspect`.

```bash
# Step 1: Verify and save Trust Card
tif verify myapp:v1.0.0 --policy-pack nist-800-190 --only-fixable -o trust-card.json

# Step 2: Push enriched image to your registry
tif push myapp:v1.0.0 trust-card.json --to registry.io/myapp:v1.0.0

# What gets added to the image:
# docker inspect registry.io/myapp:v1.0.0 | jq '.[0].Config.Labels'
# {
#   "tif.trust-score": "87",
#   "tif.verdict": "PASS",
#   "tif.policy": "nist-800-190",
#   "tif.scanned-at": "2026-03-21T10:00:00Z",
#   "tif.critical-cves": "0",
#   "tif.fixable-highs": "2",
#   "tif.signed": "true",
#   "tif.sbom-attached": "true"
# }

# Step 3: Anyone can retrieve the full audit artifact later
tif inspect registry.io/myapp:v1.0.0
```

## Run in Your CI/CD Pipeline

### GitHub Actions

```yaml
# .github/workflows/trust-gate.yml
name: Image Trust Gate
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cvemula1/tif@main
        with:
          image: ghcr.io/${{ github.repository }}:${{ github.sha }}
          policy-pack: "nist-800-190"
          fail-on: "high"
          require-sbom: "true"
```

### GitLab CI

```yaml
tif-verify:
  stage: verify
  image: ghcr.io/cvemula1/tif:latest
  script:
    - tif verify $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
        --only-fixable
        --policy-pack nist-800-190
        --ci
        -o trust-card.json
    - tif push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA trust-card.json
        --to $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    paths:
      - trust-card.json
    expire_in: 90 days
```

### Docker

```bash
docker run --rm ghcr.io/cvemula1/tif verify registry.io/myapp:1.0
```

## Trust Card

The Trust Card is a portable JSON artifact that captures the complete trust posture of a container image. Use it to:

- **Gate deployments** — fail CI if trust score drops below threshold
- **Audit trail** — store Trust Cards alongside images in your registry
- **Compare over time** — track trust score trends across releases
- **Share with auditors** — machine-readable compliance evidence

```bash
tif verify registry.io/myapp:1.0 --output trust-card.json  # save Trust Card
tif policy check trust-card.json --policy-pack dod-stig     # evaluate offline
```

<details>
<summary><b>Trust Card schema</b></summary>

```json
{
  "schema_version": "1.0",
  "image": "registry.io/myapp",
  "digest": "sha256:...",
  "tag": "1.0",
  "tier": "hardened",
  "signature":       { "verified": true, "signer": "cosign", ... },
  "sbom":            { "present": true, "format": "spdx-2.3", "packages": 127, ... },
  "attestation":     { "present": true, "slsa_level": 3, "builder": "github-actions", ... },
  "vulnerabilities": { "scanned": true, "critical": 0, "high": 2, ... },
  "security":        { "rootless": true, "from_scratch": true, "read_only_rootfs": true, ... },
  "compliance":      [{ "framework": "CIS-L2", "passed": true, ... }],
  "gates":           [{ "name": "Signature", "verdict": "PASS", ... }],
  "verdict": "PASS",
  "trust_score": 87,
  "created_at": "2026-03-20T12:00:00Z"
}
```

</details>

## Policy Packs

Built-in compliance policy packs — no OPA installation required:

| Pack | Framework | Key Checks |
|------|-----------|------------|
| `default` | Baseline | Signature verified, no critical CVEs |
| `cis-l1` | CIS Docker Benchmark L1 | Non-root user, HEALTHCHECK, no critical CVEs |
| `cis-l2` | CIS Docker Benchmark L2 | L1 + signature, read-only rootfs, no-new-privileges |
| `nist-800-190` | NIST SP 800-190 | Signature, SBOM, non-root, vuln thresholds |
| `dod-stig` | DISA STIG / FedRAMP | All of the above + SLSA L2+, FROM scratch (requires OPA) |

Custom policies:

```bash
tif verify myimage:1.0 --policy my-policy.rego   # custom OPA/Rego policy
tif policy list                                    # list available packs
tif policy check trust-card.json --policy-pack cis-l2  # offline evaluation
```

## Trust Scoring (NIST SP 800-190 Aligned)

TIF computes a 0-100 trust score mapped to NIST SP 800-190 control families with CVSS-weighted vulnerability penalties:

| NIST Family | Control | What It Measures | Max Pts |
|-------------|---------|------------------|---------|
| CM (Config Mgmt) | CM-3, CM-5 | Signature verification + transparency log | 20 |
| RA (Risk Assessment) | RA-5 | Vulnerability scan, CVSS-weighted penalties | 25 |
| SA (Supply Chain) | SA-12 | SBOM completeness + SLSA attestation level | 20 |
| AC (Access Control) | AC-6 | Rootless, no-new-privileges, healthcheck | 15 |
| SI (Sys Integrity) | SI-7 | FROM scratch, read-only rootfs | 10 |
| MA (Maintenance) | MA-6 | Base image EOL status via endoflife.date | 10 |

Vulnerability penalties use CVSS base score averages:
- **Critical** (CVSS 9.0-10.0): -10 pts each
- **High** (CVSS 7.0-8.9): -4 pts each
- **Medium** (CVSS 4.0-6.9): -1.5 pts each
- **Low** (CVSS 0.1-3.9): -0.3 pts each

## End-of-Life Checking

TIF checks if your base image has reached or is approaching End-of-Life using the [endoflife.date API](https://endoflife.date/):

```bash
tif verify python:3.8-slim    # warns if Python 3.8 is near EOL
tif verify node:16             # fails if Node 16 is past EOL
```

Supported base images: Alpine, Ubuntu, Debian, CentOS, Node.js, Python, Go, Ruby, PHP, Java, .NET, Nginx, PostgreSQL, MySQL, Redis, MongoDB, and 30+ more.

## Signing and Key Management

TIF supports both **keyless** (Sigstore/Fulcio) and **key-based** (cosign) signature verification:

```bash
# Keyless (default) - uses Sigstore OIDC + Fulcio certificates
tif verify registry.io/app:1.0

# User-provided key - pass your cosign public key
tif verify registry.io/app:1.0 --key cosign.pub

# Push with a signing key
tif push registry.io/app:1.0 trust-card.json --key cosign.key
```

- **No key**: TIF uses keyless Sigstore verification (OIDC identity, Fulcio certificate, Rekor transparency log)
- **`--key PATH`**: TIF uses your cosign public key for verification; private key for signing attestations

## Dockerfile Security

TIF can also analyze and harden Dockerfiles directly -- no image build needed.

### Scan a Dockerfile

```bash
tif scan-dockerfile Dockerfile
```

```
[WARN]  WARN: 3 high findings in Dockerfile

  [    HIGH] DF-001 (line 5): Running as root. Use a non-root user.
  [CRITICAL] DF-010 (line 3): Secrets in ENV are baked into the image.
  [    HIGH] DF-006 (line 7): Exposing SSH port 22.
```

### Generate a Hardened Dockerfile

```bash
tif harden Dockerfile -o Dockerfile.hardened
```

TIF applies automatic fixes:
- Replaces `ADD` with `COPY`
- Adds `USER 65532` (nonroot)
- Adds `HEALTHCHECK`
- Removes `EXPOSE 22`
- Strips hardcoded secrets from `ENV`
- Fixes `chmod 777` to `chmod 755`
- Adds `--no-install-recommends` to `apt-get`
- Adds OCI labels

### Push Trust Card to Registry

```bash
tif verify registry.io/app:1.0 --output trust-card.json
tif push registry.io/app:1.0 trust-card.json --to registry.io/app:1.0
```

OCI labels (`tif.trust-score`, `tif.verdict`, `tif.critical-cves`, etc.) are baked into the image and a cosign attestation is attached. See [Storing the Trust Card with Your Image](#storing-the-trust-card-with-your-image) for the full workflow.

## CLI Reference

<details>
<summary><b>Full CLI flags</b></summary>

```
tif verify IMAGE [OPTIONS]        Run all trust gates on a container image
  --key PATH                      Cosign public key (default: keyless Sigstore)
  --scanner {trivy,grype}         Vulnerability scanner (default: trivy)
  --policy PATH                   Custom .rego policy file
  --policy-pack NAME              Built-in policy pack (default: default)
  --fail-on {critical,high,medium,low}  Vulnerability severity gate
  --max-high N                    Max high CVEs before failing (default: 10)
  --only-fixable                  Count only CVEs with an available fix (reduces noise)
  --require-sbom                  Fail if no SBOM attached
  --require-provenance            Fail if no SLSA provenance
  --min-slsa-level {0,1,2,3,4}   Minimum SLSA level (default: 0)
  --skip GATE [GATE ...]          Skip gates: signature vulnerabilities sbom attestation image eol policy
  -f, --format {table,json,card}  Output format (default: table)
  -o, --output FILE               Write Trust Card JSON to file
  --ascii                         ASCII-safe output (no emoji)
  --ci                            Exit code 1 on FAIL verdict

tif inspect IMAGE [OPTIONS]       Inspect image trust (read-only, never fails)
tif scan-dockerfile DOCKERFILE    Analyze a Dockerfile for security issues
tif harden DOCKERFILE [-o FILE]   Generate a hardened Dockerfile
tif push IMAGE CARD_FILE          Enrich image with OCI labels + cosign attestation
  --to DESTINATION                Target registry reference (default: same as IMAGE)
  --no-labels                     Skip OCI label injection, attach attestation only
  --key PATH                      Cosign private key for attestation signing
tif policy list                   List available policy packs
tif policy check FILE [OPTIONS]   Evaluate Trust Card against a policy
tif demo                          Show sample Trust Card (no tools needed)
tif version                       Show version
```

</details>

## How It Works

```mermaid
graph LR
  image["Container Image"]

  subgraph "TIF Trust Gates"
    sig["Signature<br/>Cosign / Notary"]
    vuln["Vulnerabilities<br/>Trivy / Grype"]
    sbom["SBOM<br/>SPDX / CycloneDX"]
    attest["Attestation<br/>SLSA Provenance"]
    sec["Image Security<br/>Rootless / Scratch"]
    eol["End-of-Life<br/>endoflife.date"]
    policy["Policy<br/>OPA / Built-in"]
  end

  card["Trust Card<br/>JSON artifact"]
  verdict{{"PASS / FAIL"}}

  image --> sig & vuln & sbom & attest & sec & eol
  sig & vuln & sbom & attest & sec & eol --> policy
  policy --> card --> verdict

  style image fill:#326CE5,stroke:#1a3a6e,color:#fff
  style card fill:#2d7d46,stroke:#1a5c30,color:#fff
  style verdict fill:#FF9900,stroke:#cc7a00,color:#000
```

## Architecture

```
tif/
├── cli.py                        # CLI entry point (argparse)
├── core/
│   ├── trust_card.py             # Trust Card schema (dataclasses)
│   ├── verifier.py               # Orchestrator — runs all gates
│   └── output.py                 # Rich table, JSON formatters
├── validators/
│   ├── signature.py              # Cosign signature verification
│   ├── vulnerability.py          # Trivy/Grype scanning
│   ├── sbom.py                   # SPDX/CycloneDX validation
│   ├── attestation.py            # SLSA provenance verification
│   ├── image.py                  # Image security inspection
│   ├── dockerfile.py             # Dockerfile static analysis (12 rules)
│   └── eol.py                    # End-of-Life check (endoflife.date API)
├── generators/
│   └── harden.py                 # Hardened Dockerfile generator
├── publishers/
│   └── registry.py               # Push Trust Card as OCI attestation
└── policies/
    ├── engine.py                 # OPA/Rego + built-in evaluator
    └── packs/                    # Starter policy packs
        ├── default.rego
        ├── cis-l1.rego
        ├── cis-l2.rego
        ├── nist-800-190.rego
        └── dod-stig.rego
```

## Comparison

| Feature | TIF | Cosign | Trivy | Grype | Kyverno |
|---------|-----|--------|-------|-------|---------|
| Signature verification | Yes | Yes | -- | -- | Yes |
| Vulnerability scanning | Yes | -- | Yes | Yes | -- |
| SBOM validation | Yes | Partial | Yes | -- | -- |
| SLSA attestation | Yes | Yes | -- | -- | Yes |
| Image hardening checks | Yes | -- | -- | -- | -- |
| Policy compliance | Yes | -- | -- | -- | Yes |
| Unified Trust Card | Yes | -- | -- | -- | -- |
| EOL checking | Yes | -- | -- | -- | -- |
| NIST-aligned scoring | Yes | -- | -- | -- | -- |
| Dockerfile analysis | Yes | -- | -- | -- | -- |
| Hardened Dockerfile gen | Yes | -- | -- | -- | -- |
| Standalone CLI | Yes | Yes | Yes | Yes | -- (K8s only) |
| CI/CD native | Yes | Yes | Yes | Yes | -- |

## Roadmap

- [x] **v0.1** — Trust Card schema, verifier CLI, 5 policy packs, 7 validators (incl. EOL), NIST-aligned scoring, Dockerfile scanner, hardener, registry push, CI/CD pipelines, GitHub Action
- [ ] **v0.2** — Notary v2 signing, SARIF output format
- [ ] **v0.3** — Trust Card registry (store/query Trust Cards), webhook notifications
- [ ] **v0.4** — ML-based image risk scoring, auto-remediation suggestions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Related Projects

- [NHInsight](https://github.com/cvemula1/NHInsight) — discover risky non-human identities across cloud and CI/CD
- [ChangeTrail](https://github.com/cvemula1/ChangeTrail) — unified timeline of infrastructure changes

## License

[Apache License 2.0](LICENSE)
