# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| < 0.1.0 | No        |

## Reporting a Vulnerability

**Do not report security vulnerabilities via public GitHub issues.**

Report vulnerabilities privately via:
- [GitHub Private Security Advisory](https://github.com/cvemula1/tif/security/advisories/new)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours. We aim to release patches within 7 days of confirmation.

## Supply Chain Security

TIF's own Docker images are:
- **Signed** with cosign keyless signing (GitHub OIDC)
- **SBOM-attested** (SPDX format via syft)
- **SLSA provenance** attached via `actions/attest-build-provenance`

Verify before running:
```bash
cosign verify \
  --certificate-identity-regexp=https://github.com/cvemula1/tif/.* \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/cvemula1/tif:latest
```
