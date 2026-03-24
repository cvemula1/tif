# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# OPA/Rego policy evaluation engine

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import List, Optional

from tif.core.trust_card import ComplianceResult, GateResult, TrustCard, Verdict

logger = logging.getLogger(__name__)

# Built-in policy packs directory
PACKS_DIR = Path(__file__).parent / "packs"


def evaluate_policy(
    card: TrustCard,
    policy_path: Optional[str] = None,
    policy_pack: str = "default",
) -> tuple[List[ComplianceResult], GateResult]:
    """
    Evaluate a Trust Card against OPA/Rego policies.

    Args:
        card: Trust Card to evaluate
        policy_path: Path to custom .rego file or directory
        policy_pack: Built-in policy pack name (default, cis-l1, cis-l2, nist-800-190, dod-stig)

    Returns:
        Tuple of (list of ComplianceResult, GateResult)
    """
    gate = GateResult(name="Policy", verdict=Verdict.UNKNOWN)

    result = None

    # Try built-in Python policy evaluation first (always available)
    result = _eval_builtin(card, policy_pack)

    # If no built-in, try OPA with .rego file
    if result is None:
        rego_path = _resolve_policy(policy_path, policy_pack)
        if rego_path is not None:
            input_data = card.to_dict()
            result = _eval_opa(rego_path, input_data)

    # Custom policy file override
    if policy_path:
        rego_path = _resolve_policy(policy_path, policy_pack)
        if rego_path is not None:
            input_data = card.to_dict()
            opa_result = _eval_opa(rego_path, input_data)
            if opa_result is not None:
                result = opa_result

    if result is None:
        gate.verdict = Verdict.WARN
        gate.reason = f"No policy available for: {policy_path or policy_pack}"
        return [], gate

    # Parse results
    compliance_results = []
    all_passed = True

    for framework, checks in result.items():
        cr = ComplianceResult(framework=framework)
        if isinstance(checks, dict):
            cr.passed = checks.get("allow", False)
            cr.findings = checks.get("deny", [])
            cr.checks_total = checks.get("total", 0)
            cr.checks_passed = checks.get("passed", 0)
            cr.checks_failed = len(cr.findings)
        elif isinstance(checks, bool):
            cr.passed = checks
        else:
            cr.passed = False

        if not cr.passed:
            all_passed = False
        compliance_results.append(cr)

    if all_passed:
        gate.verdict = Verdict.PASS
        gate.reason = f"All policy checks passed ({len(compliance_results)} frameworks)"
    else:
        failed = [c.framework for c in compliance_results if not c.passed]
        gate.verdict = Verdict.FAIL
        gate.reason = f"Policy violations: {', '.join(failed)}"

    return compliance_results, gate


def _resolve_policy(policy_path: Optional[str], policy_pack: str) -> Optional[Path]:
    """Resolve policy file path."""
    if policy_path:
        p = Path(policy_path)
        if p.exists():
            return p
        return None

    # Built-in pack
    pack_file = PACKS_DIR / f"{policy_pack}.rego"
    if pack_file.exists():
        return pack_file

    return None


def _eval_opa(rego_path: Path, input_data: dict) -> Optional[dict]:
    """Evaluate policy using OPA CLI."""
    try:
        input_json = json.dumps(input_data)
        cmd = [
            "opa", "eval",
            "--data", str(rego_path),
            "--input", "/dev/stdin",
            "--format", "json",
            "data.tif",
        ]
        result = subprocess.run(
            cmd,
            input=input_json,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            output = json.loads(result.stdout)
            # OPA returns {"result": [{"expressions": [{"value": {...}}]}]}
            expressions = output.get("result", [{}])[0].get("expressions", [{}])
            if expressions:
                return expressions[0].get("value", {})
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def _eval_builtin(card: TrustCard, policy_pack: str) -> Optional[dict]:
    """Built-in Python policy evaluation (no OPA required)."""
    if policy_pack == "default":
        return _builtin_default(card)
    elif policy_pack == "cis-l1":
        return _builtin_cis_l1(card)
    elif policy_pack == "cis-l2":
        return _builtin_cis_l2(card)
    elif policy_pack == "nist-800-190":
        return _builtin_nist_800_190(card)
    return None


def _gate_available(card: TrustCard, gate_name: str) -> bool:
    """Check if a gate actually ran (tool was available), not just skipped/warned."""
    for g in card.gates:
        if g.name.lower() == gate_name.lower():
            if g.verdict == Verdict.WARN and "not installed" in g.reason.lower():
                return False
            if g.verdict == Verdict.WARN and "skipped" in g.reason.lower():
                return False
            return True
    return False


def _builtin_default(card: TrustCard) -> dict:
    """Default policy: signature + no critical CVEs (skips if tools unavailable)."""
    deny = []
    total = 0
    if _gate_available(card, "Signature"):
        total += 1
        if not card.signature.verified:
            deny.append("Image signature not verified")
    if _gate_available(card, "Vulnerabilities"):
        total += 1
        if card.vulnerabilities.scanned and card.vulnerabilities.critical > 0:
            deny.append(f"{card.vulnerabilities.critical} critical vulnerabilities found")
    if total == 0:
        return {"default": {"allow": True, "deny": [], "total": 0, "passed": 0}}
    return {
        "default": {
            "allow": len(deny) == 0,
            "deny": deny,
            "total": total,
            "passed": total - len(deny),
        }
    }


def _builtin_cis_l1(card: TrustCard) -> dict:
    """CIS Docker Benchmark Level 1."""
    deny = []
    total = 0
    if _gate_available(card, "Image Security"):
        total += 2
        if not card.security.rootless:
            deny.append("Container runs as root (CIS 4.1)")
        if not card.security.healthcheck:
            deny.append("No HEALTHCHECK instruction (CIS 4.6)")
    if _gate_available(card, "Vulnerabilities"):
        total += 1
        if card.vulnerabilities.scanned and card.vulnerabilities.critical > 0:
            deny.append(f"{card.vulnerabilities.critical} critical CVEs (CIS 4.4)")
    if total == 0:
        return {"CIS-L1": {"allow": True, "deny": [], "total": 0, "passed": 0}}
    return {
        "CIS-L1": {
            "allow": len(deny) == 0,
            "deny": deny,
            "total": total,
            "passed": total - len(deny),
        }
    }


def _builtin_cis_l2(card: TrustCard) -> dict:
    """CIS Docker Benchmark Level 2."""
    l1 = _builtin_cis_l1(card)
    deny = list(l1["CIS-L1"]["deny"])
    total = l1["CIS-L1"]["total"]

    if _gate_available(card, "Signature"):
        total += 1
        if not card.signature.verified:
            deny.append("Image not signed (CIS 4.5)")
    if _gate_available(card, "Image Security"):
        total += 2
        if not card.security.read_only_rootfs:
            deny.append("Rootfs not read-only (CIS 5.12)")
        if not card.security.no_new_privileges:
            deny.append("no-new-privileges not set (CIS 5.25)")
    if total == 0:
        return {"CIS-L2": {"allow": True, "deny": [], "total": 0, "passed": 0}}
    return {
        "CIS-L2": {
            "allow": len(deny) == 0,
            "deny": deny,
            "total": total,
            "passed": total - len(deny),
        }
    }


def _builtin_nist_800_190(card: TrustCard) -> dict:
    """NIST SP 800-190 Application Container Security Guide."""
    deny = []
    total = 0

    # 4.1.1 - Image vulnerabilities
    if _gate_available(card, "Vulnerabilities"):
        total += 1
        if card.vulnerabilities.scanned:
            if card.vulnerabilities.critical > 0:
                deny.append("Critical vulnerabilities present (NIST 4.1.1)")
            if card.vulnerabilities.high > 5:
                deny.append(f"Excessive high vulnerabilities: {card.vulnerabilities.high} (NIST 4.1.1)")

    # 4.1.3 - Image provenance
    if _gate_available(card, "Signature"):
        total += 1
        if not card.signature.verified:
            deny.append("Image provenance not verified via signature (NIST 4.1.3)")

    # 4.1.4 - Use trusted base images
    if _gate_available(card, "SBOM"):
        total += 1
        if not card.sbom.present:
            deny.append("No SBOM -- cannot verify software composition (NIST 4.1.4)")

    # 4.2.1 - Least-privilege runtime
    if _gate_available(card, "Image Security"):
        total += 1
        if not card.security.rootless:
            deny.append("Container runs as root user (NIST 4.2.1)")

    if total == 0:
        return {"NIST-800-190": {"allow": True, "deny": [], "total": 0, "passed": 0}}
    return {
        "NIST-800-190": {
            "allow": len(deny) == 0,
            "deny": deny,
            "total": total,
            "passed": total - len(deny),
        }
    }


def list_policy_packs() -> List[str]:
    """List available built-in policy packs."""
    packs = []
    if PACKS_DIR.exists():
        for f in sorted(PACKS_DIR.glob("*.rego")):
            packs.append(f.stem)
    # Always include built-in Python packs
    for name in ("default", "cis-l1", "cis-l2", "nist-800-190"):
        if name not in packs:
            packs.append(name)
    return packs
