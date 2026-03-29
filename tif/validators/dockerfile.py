# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Dockerfile analysis — security checks against a Dockerfile

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from tif.core.trust_card import GateResult, Severity, Verdict


@dataclass
class DockerfileFinding:
    """A single security finding in a Dockerfile."""
    line: int
    rule: str
    severity: str
    message: str
    fix: str


# ── Rules ────────────────────────────────────────────────────────────────

_RULES: List[Tuple[str, str, str, str]] = [
    # (regex_pattern, rule_id, severity, message)
    # -- User / root
    (
        r"^\s*USER\s+root\s*$",
        "DF-001", "high",
        "Running as root. Use a non-root user (e.g. USER 65532).",
    ),
    # -- No USER instruction at all (checked separately)
    # -- ADD instead of COPY
    (
        r"^\s*ADD\s+(?!https?://)",
        "DF-002", "medium",
        "Use COPY instead of ADD for local files. ADD auto-extracts and has unexpected behavior.",
    ),
    # -- Latest tag
    (
        r"^\s*FROM\s+\S+:latest",
        "DF-003", "medium",
        "Avoid :latest tag. Pin to a specific version for reproducible builds.",
    ),
    # -- No tag at all
    (
        r"^\s*FROM\s+(?!scratch)([a-z0-9._/-]+)\s*$",
        "DF-004", "medium",
        "No tag specified on base image. Pin to a specific version.",
    ),
    # -- curl | bash
    (
        r"curl\s.*\|\s*(ba)?sh",
        "DF-005", "high",
        "Piping curl to shell is risky. Download, verify checksum, then execute.",
    ),
    # -- EXPOSE 22
    (
        r"^\s*EXPOSE\s+22\b",
        "DF-006", "high",
        "Exposing SSH port 22. Containers should not run SSH daemons.",
    ),
    # -- apt-get without --no-install-recommends
    (
        r"apt-get\s+install\s+(?!.*--no-install-recommends)",
        "DF-007", "low",
        "Use --no-install-recommends with apt-get to minimize image size.",
    ),
    # -- Missing cleanup in same RUN layer
    (
        r"apt-get\s+install\s+(?!.*rm\s+-rf\s+/var/lib/apt)",
        "DF-008", "low",
        "Clean apt cache in the same RUN layer: rm -rf /var/lib/apt/lists/*",
    ),
    # -- chmod 777
    (
        r"chmod\s+777",
        "DF-009", "high",
        "chmod 777 grants world-writable permissions. Use least-privilege (e.g. 755 or 500).",
    ),
    # -- Secrets in ENV
    (
        r"^\s*ENV\s+\S*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIALS)\s*=",
        "DF-010", "critical",
        "Secrets in ENV are baked into the image. Use runtime secrets or mounted files.",
    ),
    # -- COPY . . (copies everything)
    (
        r"^\s*COPY\s+\.\s+\.",
        "DF-011", "medium",
        "COPY . . copies everything including .git, secrets, etc. Use .dockerignore or copy specific paths.",
    ),
    # -- Using sudo
    (
        r"\bsudo\b",
        "DF-012", "medium",
        "Avoid sudo in containers. Set USER directive instead.",
    ),
    # -- HEALTHCHECK missing (checked separately)
    # -- Multiple FROM (multi-stage is OK, just flag it)
]


def analyze_dockerfile(
    dockerfile_path: str,
) -> Tuple[List[DockerfileFinding], GateResult]:
    """
    Analyze a Dockerfile for security issues.

    Args:
        dockerfile_path: Path to Dockerfile

    Returns:
        Tuple of (list of findings, GateResult)
    """
    path = Path(dockerfile_path)
    if not path.exists():
        return [], GateResult(
            name="Dockerfile",
            verdict=Verdict.FAIL,
            reason=f"Dockerfile not found: {dockerfile_path}",
        )

    content = path.read_text()
    lines = content.splitlines()
    findings: List[DockerfileFinding] = []

    # Run regex rules
    for i, line in enumerate(lines, 1):
        for pattern, rule_id, severity, message in _RULES:
            if re.search(pattern, line, re.IGNORECASE):
                fix = _suggest_fix(rule_id, line)
                findings.append(DockerfileFinding(
                    line=i, rule=rule_id, severity=severity,
                    message=message, fix=fix,
                ))

    # Check for missing USER instruction
    has_user = any(re.match(r"^\s*USER\s+", line, re.IGNORECASE) for line in lines)
    if not has_user:
        findings.append(DockerfileFinding(
            line=0, rule="DF-100", severity="high",
            message="No USER instruction. Container will run as root.",
            fix="Add 'USER 65532' (nonroot) before the final CMD/ENTRYPOINT.",
        ))

    # Check for missing HEALTHCHECK
    has_healthcheck = any(re.match(r"^\s*HEALTHCHECK\s+", line, re.IGNORECASE) for line in lines)
    if not has_healthcheck:
        findings.append(DockerfileFinding(
            line=0, rule="DF-101", severity="low",
            message="No HEALTHCHECK instruction.",
            fix="Add HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
        ))

    # Check FROM scratch
    any(re.match(r"^\s*FROM\s+scratch\s*$", line, re.IGNORECASE) for line in lines)

    # Build gate result
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    if critical > 0:
        verdict = Verdict.FAIL
        reason = f"{critical} critical, {high} high findings in Dockerfile"
    elif high > 0:
        verdict = Verdict.WARN
        reason = f"{high} high findings in Dockerfile"
    elif findings:
        verdict = Verdict.WARN
        reason = f"{len(findings)} findings in Dockerfile (no critical/high)"
    else:
        verdict = Verdict.PASS
        reason = "Dockerfile passes all security checks"

    gate = GateResult(
        name="Dockerfile",
        verdict=verdict,
        reason=reason,
        severity=Severity.HIGH if high > 0 else Severity.MEDIUM,
    )

    return findings, gate


def _suggest_fix(rule_id: str, line: str) -> str:
    """Suggest a fix for a finding."""
    fixes = {
        "DF-001": "USER 65532",
        "DF-002": line.replace("ADD", "COPY", 1).strip(),
        "DF-003": "Pin to a specific version tag instead of :latest",
        "DF-004": "Add a version tag (e.g. :3.20, :22.04)",
        "DF-005": "Download file, verify sha256 checksum, then run",
        "DF-006": "Remove EXPOSE 22 — use kubectl exec or docker exec instead",
        "DF-007": "apt-get install --no-install-recommends <packages>",
        "DF-008": "RUN apt-get update && apt-get install -y --no-install-recommends <pkg> && rm -rf /var/lib/apt/lists/*",
        "DF-009": "Use chmod 755 or more restrictive permissions",
        "DF-010": "Use --mount=type=secret or runtime ENV injection",
        "DF-011": "COPY specific files/dirs, or add a .dockerignore",
        "DF-012": "Remove sudo and use USER directive to set permissions",
    }
    return fixes.get(rule_id, "")
