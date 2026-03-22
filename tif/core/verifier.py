# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Verifier — orchestrates all trust gates into a single Trust Card

from __future__ import annotations

import logging
from typing import Optional

from tif.core.trust_card import TrustCard, Verdict

logger = logging.getLogger(__name__)


def verify_image(
    image: str,
    # Gate toggles
    check_signature: bool = True,
    check_vulnerabilities: bool = True,
    check_sbom: bool = True,
    check_attestation: bool = True,
    check_image: bool = True,
    check_eol: bool = True,
    check_policy: bool = True,
    # Options
    cosign_key: Optional[str] = None,
    scanner: str = "trivy",
    fail_on_critical: bool = True,
    max_high: int = 10,
    only_fixable: bool = False,
    require_sbom: bool = False,
    require_provenance: bool = False,
    min_slsa_level: int = 0,
    policy_path: Optional[str] = None,
    policy_pack: str = "default",
) -> TrustCard:
    """
    Run all trust gates on a container image and produce a Trust Card.

    Args:
        image: Full image reference (e.g. registry.io/app:1.0 or @sha256:...)
        check_*: Toggle individual gates
        cosign_key: Path to cosign public key (None = keyless)
        scanner: Vulnerability scanner (trivy or grype)
        fail_on_critical: Fail vuln gate on any critical CVE
        max_high: Max high CVEs before vuln gate fails
        only_fixable: Only count CVEs that have a fix available (reduces alert fatigue)
        require_sbom: Whether SBOM is mandatory
        require_provenance: Whether SLSA provenance is mandatory
        min_slsa_level: Minimum SLSA level (0-4)
        policy_path: Custom .rego policy file
        policy_pack: Built-in policy pack name

    Returns:
        Populated TrustCard with all gate results and trust score.
    """
    card = TrustCard(image=image)

    # Parse tag from image reference
    if ":" in image and "@" not in image:
        parts = image.rsplit(":", 1)
        if len(parts) == 2 and "/" in parts[0]:
            card.tag = parts[1]

    # ── Gate 1: Signature ────────────────────────────────────────────
    if check_signature:
        logger.info("Checking signature for %s", image)
        try:
            from tif.validators.signature import verify_signature
            card.signature, gate = verify_signature(image, key=cosign_key)
            card.gates.append(gate)
        except Exception as e:
            logger.warning("Signature check failed: %s", e)
            card.errors.append(f"Signature check error: {e}")

    # ── Gate 2: Vulnerabilities ──────────────────────────────────────
    if check_vulnerabilities:
        logger.info("Scanning vulnerabilities for %s", image)
        try:
            from tif.validators.vulnerability import scan_vulnerabilities
            card.vulnerabilities, gate = scan_vulnerabilities(
                image,
                scanner=scanner,
                fail_on_critical=fail_on_critical,
                max_high=max_high,
                only_fixable=only_fixable,
            )
            card.gates.append(gate)
        except Exception as e:
            logger.warning("Vulnerability scan failed: %s", e)
            card.errors.append(f"Vulnerability scan error: {e}")

    # ── Gate 3: SBOM ─────────────────────────────────────────────────
    if check_sbom:
        logger.info("Validating SBOM for %s", image)
        try:
            from tif.validators.sbom import validate_sbom
            card.sbom, gate = validate_sbom(
                image, require_sbom=require_sbom,
            )
            card.gates.append(gate)
        except Exception as e:
            logger.warning("SBOM validation failed: %s", e)
            card.errors.append(f"SBOM validation error: {e}")

    # ── Gate 4: Attestation ──────────────────────────────────────────
    if check_attestation:
        logger.info("Verifying attestation for %s", image)
        try:
            from tif.validators.attestation import verify_attestation
            card.attestation, gate = verify_attestation(
                image,
                require_provenance=require_provenance,
                min_slsa_level=min_slsa_level,
            )
            card.gates.append(gate)
        except Exception as e:
            logger.warning("Attestation check failed: %s", e)
            card.errors.append(f"Attestation check error: {e}")

    # ── Gate 5: Image Security ───────────────────────────────────────
    if check_image:
        logger.info("Inspecting image security for %s", image)
        try:
            from tif.validators.image import inspect_image
            card.security, gate = inspect_image(image)
            card.gates.append(gate)
        except Exception as e:
            logger.warning("Image inspection failed: %s", e)
            card.errors.append(f"Image inspection error: {e}")

    # ── Gate 6: End-of-Life ────────────────────────────────────────
    if check_eol:
        logger.info("Checking EOL status for %s", image)
        try:
            from tif.validators.eol import check_eol as _check_eol
            card.eol, gate = _check_eol(image)
            card.gates.append(gate)
        except Exception as e:
            logger.warning("EOL check failed: %s", e)
            card.errors.append(f"EOL check error: {e}")

    # ── Gate 7: Policy ───────────────────────────────────────────────
    if check_policy:
        logger.info("Evaluating policy for %s", image)
        try:
            from tif.policies.engine import evaluate_policy
            card.compliance, gate = evaluate_policy(
                card,
                policy_path=policy_path,
                policy_pack=policy_pack,
            )
            card.gates.append(gate)
        except Exception as e:
            logger.warning("Policy evaluation failed: %s", e)
            card.errors.append(f"Policy evaluation error: {e}")

    # ── Compute score & verdict ──────────────────────────────────────
    card.compute_score()
    card.compute_verdict()

    return card


def build_demo_card() -> TrustCard:
    """
    Build a sample Trust Card with realistic data for demo purposes.
    No external tools required.
    """
    from tif.core.trust_card import (
        AttestationInfo,
        BuildInfo,
        ComplianceResult,
        EOLInfo,
        GateResult,
        ImageSecurity,
        SBOMInfo,
        Severity,
        SignatureInfo,
        VulnerabilityInfo,
    )

    card = TrustCard(
        image="registry.example.com/myapp",
        tag="1.2.0",
        digest="sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
        tier="hardened",
    )

    # Signature — verified via cosign
    card.signature = SignatureInfo(
        verified=True,
        signer="cosign",
        key_id="https://github.com/login/oauth",
        transparency_log=True,
    )

    # SBOM — SPDX with 127 packages
    card.sbom = SBOMInfo(
        present=True,
        format="spdx-2.3",
        packages=127,
        licenses=["Apache-2.0", "MIT", "BSD-3-Clause"],
        completeness_score=0.95,
    )

    # Attestation — SLSA Level 3 from GitHub Actions
    card.attestation = AttestationInfo(
        present=True,
        slsa_level=3,
        builder="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml",
        build_type="https://slsa.dev/container/v1",
    )

    # Vulnerabilities — 0 critical, 2 high, 5 medium
    card.vulnerabilities = VulnerabilityInfo(
        scanned=True,
        scanner="trivy",
        critical=0,
        high=2,
        medium=5,
        low=12,
        fixed_available=4,
    )

    # Image security
    card.security = ImageSecurity(
        from_scratch=True,
        rootless=True,
        user="65532",
        read_only_rootfs=True,
        no_new_privileges=True,
        healthcheck=True,
        layers=4,
        size_bytes=12_582_912,
    )

    # EOL — base image is supported
    card.eol = EOLInfo(
        product="python",
        version="3.12",
        cycle="3.12",
        eol=False,
        eol_date="2028-10-01",
        lts=False,
        latest_version="3.12.8",
        release_date="2023-10-02",
        days_until_eol=925,
        support_ended=False,
    )

    # Build info
    card.build = BuildInfo(
        pipeline_url="https://github.com/myorg/myapp/actions/runs/12345",
        git_repo="https://github.com/myorg/myapp",
        git_commit="a1b2c3d4e5f6",
        git_branch="main",
    )

    # Gates
    card.gates = [
        GateResult(name="Signature", verdict=Verdict.PASS, reason="Image signature verified via Cosign"),
        GateResult(name="Vulnerabilities", verdict=Verdict.WARN, reason="2 high CVEs within threshold", severity=Severity.HIGH),
        GateResult(name="SBOM", verdict=Verdict.PASS, reason="SBOM present (spdx-2.3): 127 packages, completeness 95%"),
        GateResult(name="Attestation", verdict=Verdict.PASS, reason="SLSA Level 3 provenance verified (builder: github-actions)"),
        GateResult(name="Image Security", verdict=Verdict.PASS, reason="Image security OK: rootless, FROM scratch, read-only rootfs"),
        GateResult(name="End-of-Life", verdict=Verdict.PASS, reason="python 3.12 is supported (EOL: 2028-10-01)"),
        GateResult(name="Policy", verdict=Verdict.PASS, reason="All policy checks passed (1 frameworks)"),
    ]

    # Compliance
    card.compliance = [
        ComplianceResult(
            framework="CIS-L2",
            passed=True,
            checks_total=6,
            checks_passed=6,
            checks_failed=0,
        ),
    ]

    card.compute_score()
    card.compute_verdict()
    return card
