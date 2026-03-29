# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# SBOM validation — SPDX, CycloneDX

from __future__ import annotations

import json
import logging
import subprocess
import urllib.request
import urllib.error
from typing import Optional

from tif.core.trust_card import GateResult, SBOMInfo, Verdict

logger = logging.getLogger(__name__)


def validate_sbom(
    image: str,
    require_sbom: bool = True,
    min_completeness: float = 0.5,
) -> tuple[SBOMInfo, GateResult]:
    """
    Check if a container image has an attached SBOM and validate it.

    Uses cosign to download SBOM attestation, or syft to generate one.

    Args:
        image: Full image reference
        require_sbom: Whether SBOM is mandatory
        min_completeness: Minimum completeness score (0.0–1.0)

    Returns:
        Tuple of (SBOMInfo, GateResult)
    """
    info = SBOMInfo()
    gate = GateResult(name="SBOM", verdict=Verdict.UNKNOWN)

    # Try: download attached SBOM via cosign
    sbom_data = _fetch_sbom_cosign(image)

    # Fallback: generate SBOM via syft
    if sbom_data is None:
        sbom_data = _generate_sbom_syft(image)

    # Fallback: check OCI registry for attached SBOMs (pure Python)
    if sbom_data is None:
        sbom_data = _fetch_sbom_registry(image)

    if sbom_data is None:
        info.present = False
        info.error = "No SBOM found or generated"
        if require_sbom:
            gate.verdict = Verdict.FAIL
            gate.reason = "No SBOM attached or generated for image"
        else:
            gate.verdict = Verdict.WARN
            gate.reason = "No SBOM found (not required)"
        return info, gate

    # Parse SBOM
    info.present = True
    _parse_sbom(sbom_data, info)

    # Evaluate completeness: score based on packages with license info declared
    if info.packages > 0:
        licensed = len([l for l in info.licenses if l and l != "NOASSERTION"])
        # Heuristic: ratio of distinct licenses declared vs packages (capped at 1.0)
        # A well-formed SBOM has license info for most packages
        info.completeness_score = min(1.0, (licensed + 1) / max(info.packages * 0.5, 1))
    else:
        info.completeness_score = 0.0

    if info.completeness_score >= min_completeness:
        gate.verdict = Verdict.PASS
        gate.reason = (
            f"SBOM present ({info.format}): {info.packages} packages, "
            f"completeness {info.completeness_score:.0%}"
        )
    else:
        gate.verdict = Verdict.WARN
        gate.reason = (
            f"SBOM completeness {info.completeness_score:.0%} "
            f"below threshold {min_completeness:.0%}"
        )

    return info, gate


def _fetch_sbom_cosign(image: str) -> Optional[dict]:
    """Try to download SBOM attestation via cosign."""
    try:
        cmd = [
            "cosign", "verify-attestation",
            "--type", "spdxjson",
            "--certificate-identity-regexp", ".*",
            "--certificate-oidc-issuer-regexp", ".*",
            image,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            payload = json.loads(result.stdout)
            if isinstance(payload, list) and payload:
                return payload[0]
            return payload
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def _generate_sbom_syft(image: str) -> Optional[dict]:
    """Generate SBOM using syft."""
    try:
        cmd = ["syft", image, "-o", "spdx-json", "--quiet"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    return None


# ── Pure Python OCI registry SBOM detection ────────────────────────────

def _fetch_sbom_registry(image: str) -> Optional[dict]:
    """Check for SBOM via OCI Referrers API or cosign tag convention."""
    try:
        from tif.validators.image import (
            _parse_image_reference,
            _get_auth_token,
            _registry_get,
        )

        registry, repository, tag = _parse_image_reference(image)
        token = _get_auth_token(registry, repository)
        base = f"https://{registry}/v2/{repository}"

        # Step 1: Get manifest digest for referrers lookup
        manifest_accept = ", ".join([
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
        ])
        manifest = _registry_get(f"{base}/manifests/{tag}", token, manifest_accept)
        if not manifest:
            return None

        # Handle manifest list (pick linux/amd64)
        media_type = manifest.get("mediaType", "")
        digest = None
        if "manifest.list" in media_type or "image.index" in media_type:
            for m in manifest.get("manifests", []):
                platform = m.get("platform", {})
                if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
                    digest = m["digest"]
                    break
            if not digest and manifest.get("manifests"):
                digest = manifest["manifests"][0]["digest"]
        else:
            # Compute digest from tag — check headers
            try:
                headers = {"Accept": manifest_accept}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                req = urllib.request.Request(
                    f"{base}/manifests/{tag}",
                    headers=headers,
                    method="HEAD",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    digest = resp.headers.get("Docker-Content-Digest")
            except Exception:
                pass

        if not digest:
            return None

        # Step 2: Try OCI Referrers API
        sbom_types = [
            "application/spdx+json",
            "application/vnd.cyclonedx+json",
            "application/vnd.in-toto+json",
        ]
        try:
            referrers = _registry_get(
                f"{base}/referrers/{digest}",
                token,
                "application/vnd.oci.image.index.v1+json",
            )
            if referrers and "manifests" in referrers:
                for ref in referrers["manifests"]:
                    art_type = ref.get("artifactType", ref.get("mediaType", ""))
                    if any(t in art_type for t in sbom_types):
                        ref_digest = ref["digest"]
                        # Fetch the SBOM manifest, then the blob
                        ref_manifest = _registry_get(
                            f"{base}/manifests/{ref_digest}", token, manifest_accept
                        )
                        if ref_manifest and ref_manifest.get("layers"):
                            blob_digest = ref_manifest["layers"][0]["digest"]
                            sbom = _registry_get(f"{base}/blobs/{blob_digest}", token)
                            if sbom:
                                return sbom
        except Exception:
            pass

        # Step 3: Try cosign tag convention (sha256-<hash>.sbom)
        digest_hex = digest.replace("sha256:", "")
        sbom_tag = f"sha256-{digest_hex}.sbom"
        try:
            sbom_manifest = _registry_get(f"{base}/manifests/{sbom_tag}", token, manifest_accept)
            if sbom_manifest and sbom_manifest.get("layers"):
                blob_digest = sbom_manifest["layers"][0]["digest"]
                sbom = _registry_get(f"{base}/blobs/{blob_digest}", token)
                if sbom:
                    return sbom
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"Registry SBOM check failed: {e}")

    return None


def _parse_sbom(data: dict, info: SBOMInfo) -> None:
    """Extract metadata from an SBOM document."""
    # SPDX format
    if "spdxVersion" in data:
        info.format = data.get("spdxVersion", "spdx")
        packages = data.get("packages", [])
        info.packages = len(packages)
        licenses = set()
        for pkg in packages:
            lic = pkg.get("licenseDeclared", "")
            if lic and lic != "NOASSERTION":
                licenses.add(lic)
        info.licenses = sorted(licenses)
        info.supplier = data.get("creationInfo", {}).get("creators", [""])[0] if data.get("creationInfo") else ""
        return

    # CycloneDX format
    if "bomFormat" in data:
        info.format = f"cyclonedx-{data.get('specVersion', '1.5')}"
        components = data.get("components", [])
        info.packages = len(components)
        licenses = set()
        for comp in components:
            for lic_entry in comp.get("licenses", []):
                lic_id = lic_entry.get("license", {}).get("id", "")
                if lic_id:
                    licenses.add(lic_id)
        info.licenses = sorted(licenses)
        return

    # In-toto attestation wrapper
    if "payload" in data or "predicate" in data:
        predicate = data.get("predicate", data.get("payload", {}))
        if isinstance(predicate, str):
            import base64
            try:
                predicate = json.loads(base64.b64decode(predicate))
            except Exception:
                return
        _parse_sbom(predicate, info)
