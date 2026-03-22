# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Signature verification — Cosign, Notary, Docker Content Trust

from __future__ import annotations

import json
import logging
import subprocess
from typing import Optional

from tif.core.trust_card import GateResult, SignatureInfo, Verdict

logger = logging.getLogger(__name__)


def verify_signature(image: str, key: Optional[str] = None) -> tuple[SignatureInfo, GateResult]:
    """
    Verify container image signature using cosign.

    Args:
        image: Full image reference (registry/repo:tag or @digest)
        key: Optional path to cosign public key. If None, uses keyless (Sigstore).

    Returns:
        Tuple of (SignatureInfo, GateResult)
    """
    info = SignatureInfo()
    gate = GateResult(name="Signature", verdict=Verdict.UNKNOWN)

    # Try cosign verify
    try:
        cmd = ["cosign", "verify"]
        if key:
            cmd.extend(["--key", key])
        else:
            # Keyless verification via Sigstore
            cmd.extend([
                "--certificate-identity-regexp", ".*",
                "--certificate-oidc-issuer-regexp", ".*",
            ])
        cmd.append(image)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0:
            info.verified = True
            info.signer = "cosign"
            info.transparency_log = True
            gate.verdict = Verdict.PASS
            gate.reason = "Image signature verified via Cosign"

            # Parse cosign JSON output for details
            try:
                sigs = json.loads(result.stdout)
                if isinstance(sigs, list) and sigs:
                    payload = sigs[0].get("optional", {})
                    info.key_id = payload.get("Subject", "")
            except (json.JSONDecodeError, IndexError, KeyError):
                pass
        else:
            info.verified = False
            info.error = result.stderr.strip()[:200]
            gate.verdict = Verdict.FAIL
            gate.reason = f"Signature verification failed: {info.error[:100]}"

    except FileNotFoundError:
        info.error = "cosign not found in PATH"
        gate.verdict = Verdict.WARN
        gate.reason = "cosign not installed — signature check skipped"
        logger.warning("cosign not found. Install: https://docs.sigstore.dev/cosign/system_config/installation/")

    except subprocess.TimeoutExpired:
        info.error = "cosign verify timed out after 60s"
        gate.verdict = Verdict.WARN
        gate.reason = "Signature verification timed out"

    except Exception as e:
        info.error = str(e)[:200]
        gate.verdict = Verdict.WARN
        gate.reason = f"Signature check error: {e}"

    return info, gate
