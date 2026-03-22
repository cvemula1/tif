# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Attestation validation — SLSA provenance, in-toto

from __future__ import annotations

import json
import logging
import subprocess
from typing import Optional

from tif.core.trust_card import AttestationInfo, GateResult, Verdict

logger = logging.getLogger(__name__)


def verify_attestation(
    image: str,
    require_provenance: bool = False,
    min_slsa_level: int = 0,
) -> tuple[AttestationInfo, GateResult]:
    """
    Verify SLSA provenance attestation for a container image.

    Args:
        image: Full image reference
        require_provenance: Whether provenance is mandatory
        min_slsa_level: Minimum SLSA level required (0–4)

    Returns:
        Tuple of (AttestationInfo, GateResult)
    """
    info = AttestationInfo()
    gate = GateResult(name="Attestation", verdict=Verdict.UNKNOWN)

    # Try slsa-verifier first
    provenance = _verify_slsa(image)

    # Fallback: cosign verify-attestation
    if provenance is None:
        provenance = _verify_cosign_attestation(image)

    if provenance is None:
        info.present = False
        info.error = "No provenance attestation found"
        if require_provenance:
            gate.verdict = Verdict.FAIL
            gate.reason = "No SLSA provenance attestation found (required)"
        else:
            gate.verdict = Verdict.WARN
            gate.reason = "No provenance attestation found"
        return info, gate

    # Parse provenance
    info.present = True
    _parse_provenance(provenance, info)

    # Evaluate SLSA level gate
    if info.slsa_level >= min_slsa_level:
        gate.verdict = Verdict.PASS
        gate.reason = (
            f"SLSA Level {info.slsa_level} provenance verified"
            f" (builder: {info.builder})"
        )
    else:
        gate.verdict = Verdict.FAIL
        gate.reason = (
            f"SLSA Level {info.slsa_level} below required Level {min_slsa_level}"
        )

    return info, gate


def _verify_slsa(image: str) -> Optional[dict]:
    """Verify provenance using slsa-verifier."""
    try:
        # --print-provenance dumps the predicate; --source-uri is required by slsa-verifier
        # but we use a regexp to accept any source (informational verification)
        cmd = [
            "slsa-verifier", "verify-image", image,
            "--print-provenance",
            "--source-uri-regexp", ".*",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def _verify_cosign_attestation(image: str) -> Optional[dict]:
    """Verify provenance attestation using cosign."""
    try:
        cmd = [
            "cosign", "verify-attestation",
            "--type", "slsaprovenance",
            "--certificate-identity-regexp", ".*",
            "--certificate-oidc-issuer-regexp", ".*",
            image,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            # cosign outputs one JSON per line
            first_line = result.stdout.strip().split("\n")[0]
            return json.loads(first_line)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def _parse_provenance(data: dict, info: AttestationInfo) -> None:
    """Extract provenance metadata from attestation payload."""
    # In-toto envelope
    predicate_type = data.get("predicateType", "")
    predicate = data.get("predicate", {})

    # SLSA v1.0 provenance
    if "slsa" in predicate_type.lower() or "provenance" in predicate_type.lower():
        build_def = predicate.get("buildDefinition", {})
        run_details = predicate.get("runDetails", {})

        info.build_type = build_def.get("buildType", predicate_type)

        # Builder
        builder = run_details.get("builder", {})
        info.builder = builder.get("id", "")

        # Determine SLSA level from builder
        builder_id = info.builder.lower()
        if "github.com/slsa-framework/slsa-github-generator" in builder_id:
            info.slsa_level = 3
        elif "github" in builder_id:
            info.slsa_level = 2
        elif builder_id:
            info.slsa_level = 1
        else:
            info.slsa_level = 0

        # Source
        materials = build_def.get("resolvedDependencies", [])
        for mat in materials:
            uri = mat.get("uri", "")
            if "git" in uri:
                info.provenance_url = uri
                break

    # SLSA v0.2 provenance
    elif "buildConfig" in predicate or "builder" in predicate:
        info.builder = predicate.get("builder", {}).get("id", "")
        info.build_type = predicate.get("buildType", "")

        materials = predicate.get("materials", [])
        for mat in materials:
            uri = mat.get("uri", "")
            if "git" in uri:
                info.provenance_url = uri
                break

        if info.builder:
            info.slsa_level = 1
