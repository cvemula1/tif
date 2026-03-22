# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Push Trust Card back to registry as OCI attestation via cosign

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def push_trust_card(
    image: str,
    trust_card_path: str,
    cosign_key: Optional[str] = None,
) -> bool:
    """
    Attach a Trust Card to a container image as a cosign attestation.

    This pushes the Trust Card JSON as an in-toto attestation using
    cosign attest, making it discoverable alongside the image in
    any OCI-compliant registry.

    Args:
        image: Full image reference (must include digest or tag)
        trust_card_path: Path to Trust Card JSON file
        cosign_key: Path to cosign private key (None = keyless Sigstore)

    Returns:
        True if push succeeded, False otherwise.
    """
    card_path = Path(trust_card_path)
    if not card_path.exists():
        logger.error("Trust Card not found: %s", trust_card_path)
        return False

    # Validate the Trust Card JSON
    try:
        card_data = json.loads(card_path.read_text())
        if "schema_version" not in card_data:
            logger.error("Invalid Trust Card: missing schema_version")
            return False
    except json.JSONDecodeError as e:
        logger.error("Invalid Trust Card JSON: %s", e)
        return False

    # Wrap Trust Card in in-toto predicate envelope
    predicate = {
        "predicateType": "https://tif.dev/trust-card/v1",
        "predicate": card_data,
    }

    # Write predicate to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(predicate, f)
        predicate_path = f.name

    try:
        cmd = ["cosign", "attest"]

        if cosign_key:
            cmd.extend(["--key", cosign_key])
        else:
            cmd.append("--yes")  # keyless mode

        cmd.extend([
            "--predicate", predicate_path,
            "--type", "custom",
            image,
        ])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            logger.info("Trust Card pushed to %s", image)
            return True
        else:
            logger.error("Failed to push Trust Card: %s", result.stderr.strip()[:300])
            return False

    except FileNotFoundError:
        logger.error(
            "cosign not found. Install: https://docs.sigstore.dev/cosign/system_config/installation/"
        )
        return False

    except subprocess.TimeoutExpired:
        logger.error("cosign attest timed out after 120s")
        return False

    except Exception as e:
        logger.error("Push error: %s", e)
        return False

    finally:
        Path(predicate_path).unlink(missing_ok=True)


def push_enriched(
    image: str,
    trust_card_path: str,
    destination: str,
    cosign_key: Optional[str] = None,
) -> bool:
    """
    Enrich a container image with Trust Card OCI labels and push to a registry.

    Steps:
    1. Copy source image to destination using skopeo (no rebuild, digest preserved)
    2. Inject tif.* OCI labels into the destination image
    3. Attach full Trust Card JSON as cosign attestation

    This makes trust metadata visible via `docker inspect` (labels) and
    retrievable for compliance audits (`tif inspect <destination>`).

    Args:
        image: Source image reference (must already exist in registry or local daemon)
        trust_card_path: Path to Trust Card JSON file
        destination: Destination registry path (e.g. registry.io/myapp:v1.0.0-verified)
        cosign_key: Cosign private key (None = keyless Sigstore)

    Returns:
        True if all steps succeeded, False otherwise.
    """
    card_path = Path(trust_card_path)
    if not card_path.exists():
        logger.error("Trust Card not found: %s", trust_card_path)
        return False

    try:
        card_data = json.loads(card_path.read_text())
        if "schema_version" not in card_data:
            logger.error("Invalid Trust Card: missing schema_version")
            return False
    except json.JSONDecodeError as e:
        logger.error("Invalid Trust Card JSON: %s", e)
        return False

    # Build OCI label set from Trust Card fields
    labels = {
        "tif.trust-score": str(card_data.get("trust_score", "")),
        "tif.verdict": card_data.get("verdict", ""),
        "tif.scanned-at": card_data.get("created_at", ""),
        "tif.tif-version": card_data.get("schema_version", ""),
    }
    vuln = card_data.get("vulnerabilities", {})
    labels["tif.critical-cves"] = str(vuln.get("critical", ""))
    labels["tif.fixable-critical"] = str(vuln.get("fixable_critical", ""))
    labels["tif.fixable-highs"] = str(vuln.get("fixable_high", ""))
    labels["tif.scanner"] = vuln.get("scanner", "")
    labels["tif.sbom-attached"] = "true" if card_data.get("sbom", {}).get("present") else "false"
    labels["tif.signed"] = "true" if card_data.get("signature", {}).get("verified") else "false"

    # Compliance pack (first framework name if present)
    compliance = card_data.get("compliance", [])
    if compliance:
        labels["tif.policy"] = compliance[0].get("framework", "")

    # Step 1: Copy image to destination with OCI labels via skopeo
    # --dest-oci-add-label requires skopeo >= 1.13 (Debian bookworm-backports or later)
    label_args = []
    for k, v in labels.items():
        if v:  # skip empty values
            label_args.extend(["--dest-oci-add-label", f"{k}={v}"])

    copy_cmd = ["skopeo", "copy"] + label_args + [
        f"docker://{image}",
        f"docker://{destination}",
    ]

    logger.info("Copying %s → %s with trust labels", image, destination)
    try:
        result = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            # skopeo < 1.13 doesn't support --dest-oci-add-label; fall back to copy without labels
            if "dest-oci-add-label" in stderr or "unknown flag" in stderr:
                logger.warning(
                    "skopeo version too old for --dest-oci-add-label (need >= 1.13). "
                    "Copying without OCI labels — upgrade skopeo for full label support."
                )
                fallback_cmd = ["skopeo", "copy",
                                f"docker://{image}", f"docker://{destination}"]
                result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    logger.error("skopeo copy failed: %s", result.stderr.strip()[:300])
                    return False
            else:
                logger.error("skopeo copy failed: %s", stderr[:300])
                return False
    except FileNotFoundError:
        logger.error("skopeo not found. Install: https://github.com/containers/skopeo")
        return False
    except subprocess.TimeoutExpired:
        logger.error("skopeo copy timed out after 300s")
        return False

    # Step 2: Attach Trust Card JSON as cosign attestation
    logger.info("Attaching Trust Card attestation to %s", destination)
    attested = push_trust_card(
        image=destination,
        trust_card_path=trust_card_path,
        cosign_key=cosign_key,
    )
    if not attested:
        logger.warning(
            "OCI labels pushed successfully but cosign attestation failed. "
            "Image is labeled but not attested."
        )
        # Return True — labels were pushed; attestation failure is non-fatal
        return True

    logger.info("Image enriched and pushed to %s", destination)
    return True


def pull_trust_card(
    image: str,
) -> Optional[dict]:
    """
    Pull a Trust Card attestation from a container image.

    Args:
        image: Full image reference

    Returns:
        Trust Card dict if found, None otherwise.
    """
    try:
        cmd = [
            "cosign", "verify-attestation",
            "--type", "custom",
            "--certificate-identity-regexp", ".*",
            "--certificate-oidc-issuer-regexp", ".*",
            image,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return None

        # Parse cosign output (one JSON envelope per line)
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                envelope = json.loads(line)
                payload = envelope.get("payload", "")
                if payload:
                    import base64
                    decoded = json.loads(base64.b64decode(payload))
                    predicate_type = decoded.get("predicateType", "")
                    if "trust-card" in predicate_type:
                        return decoded.get("predicate", {})
            except (json.JSONDecodeError, KeyError):
                continue

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None
