# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Trust Card — the core schema for container image trust verification

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enums ────────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    """Overall trust verdict for an image."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Tier(str, Enum):
    """Image hardening tier."""
    MINIMAL = "minimal"
    DEV = "dev"
    HARDENED = "hardened"
    COMPLIANT = "compliant"
    CUSTOM = "custom"


# ── Sub-schemas ──────────────────────────────────────────────────────────

@dataclass
class SignatureInfo:
    """Image signature verification result."""
    verified: bool = False
    signer: str = ""            # cosign, notary, docker-content-trust
    key_id: str = ""
    certificate: str = ""
    transparency_log: bool = False
    timestamp: str = ""
    error: str = ""


@dataclass
class SBOMInfo:
    """Software Bill of Materials metadata."""
    present: bool = False
    format: str = ""            # spdx-2.3, cyclonedx-1.5
    packages: int = 0
    licenses: List[str] = field(default_factory=list)
    supplier: str = ""
    completeness_score: float = 0.0   # 0.0–1.0
    error: str = ""


@dataclass
class AttestationInfo:
    """SLSA provenance and attestation metadata."""
    present: bool = False
    slsa_level: int = 0         # 0–4
    builder: str = ""           # github-actions, gitlab-ci, jenkins
    provenance_url: str = ""
    build_type: str = ""
    reproducible: bool = False
    error: str = ""


@dataclass
class CVEDetail:
    """Individual CVE record with fix availability."""
    id: str = ""                    # CVE-2024-1234
    severity: str = ""              # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float = 0.0         # 9.1, 7.5, etc.
    package: str = ""               # openssl
    installed_version: str = ""     # 3.0.1
    fixed_version: str = ""         # 3.0.2 (empty if no fix available)
    has_fix: bool = False


@dataclass
class VulnerabilityInfo:
    """Vulnerability scan summary."""
    scanned: bool = False
    scanner: str = ""           # grype, trivy, snyk
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    fixed_available: int = 0
    fixable_critical: int = 0   # critical CVEs that have a fix available
    fixable_high: int = 0       # high CVEs that have a fix available
    total_suppressed: int = 0   # CVEs filtered out when --only-fixable is used
    findings: List[CVEDetail] = field(default_factory=list)  # top CVEs (max 20)
    scan_timestamp: str = ""
    error: str = ""

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown


@dataclass
class ImageSecurity:
    """Image-level security properties."""
    from_scratch: bool = False
    rootless: bool = False
    user: str = ""              # e.g. "65532" (nonroot)
    read_only_rootfs: bool = False
    no_new_privileges: bool = False
    healthcheck: bool = False
    layers: int = 0
    size_bytes: int = 0
    base_image: str = ""


@dataclass
class EOLInfo:
    """End-of-Life status for the base image."""
    product: str = ""
    version: str = ""
    cycle: str = ""
    eol: bool = False
    eol_date: str = ""
    lts: bool = False
    latest_version: str = ""
    release_date: str = ""
    days_until_eol: int = -1    # -1 = unknown
    support_ended: bool = False
    error: str = ""


@dataclass
class BuildInfo:
    """Build provenance metadata."""
    timestamp: str = ""
    pipeline_url: str = ""
    git_repo: str = ""
    git_commit: str = ""
    git_branch: str = ""
    builder_image: str = ""
    reproducible: bool = False


@dataclass
class ComplianceResult:
    """A single compliance framework check result."""
    framework: str = ""         # CIS-L1, NIST-800-190, DISA-STIG, SOC2
    passed: bool = False
    checks_total: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    findings: List[str] = field(default_factory=list)


@dataclass
class GateResult:
    """Result of a single trust gate evaluation."""
    name: str = ""
    verdict: Verdict = Verdict.UNKNOWN
    reason: str = ""
    severity: Severity = Severity.INFO


# ── Trust Card ───────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0"

@dataclass
class TrustCard:
    """
    Trust Card — a unified trust verification report for a container image.

    Combines signature, SBOM, attestation, vulnerability, image security,
    and compliance data into a single artifact with an overall verdict.
    """
    # Identity
    schema_version: str = SCHEMA_VERSION
    image: str = ""
    digest: str = ""
    tag: str = ""
    tier: str = ""

    # Verification results
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    sbom: SBOMInfo = field(default_factory=SBOMInfo)
    attestation: AttestationInfo = field(default_factory=AttestationInfo)
    vulnerabilities: VulnerabilityInfo = field(default_factory=VulnerabilityInfo)
    security: ImageSecurity = field(default_factory=ImageSecurity)
    eol: EOLInfo = field(default_factory=EOLInfo)
    build: BuildInfo = field(default_factory=BuildInfo)

    # Policy evaluation
    compliance: List[ComplianceResult] = field(default_factory=list)
    gates: List[GateResult] = field(default_factory=list)

    # Overall
    verdict: Verdict = Verdict.UNKNOWN
    trust_score: int = 0        # 0–100
    created_at: str = ""
    errors: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat() + "Z"

    # ── Scoring ──────────────────────────────────────────────────────

    def compute_score(self) -> int:
        """
        Compute trust score (0-100) aligned to NIST SP 800-190 controls
        with CVSS-weighted vulnerability penalties.

        NIST Control Families and Weights:
          CM (Config Mgmt) - Signature + Provenance:  20 pts
          RA (Risk Assess) - Vulnerability scanning:   25 pts (CVSS-weighted)
          SA (Supply Chain) - SBOM + Attestation:      20 pts
          AC (Access Ctrl) - Rootless, no-new-privs:   15 pts
          SI (Sys Integrity) - FROM scratch, RO rootfs: 10 pts
          MA (Maintenance) - EOL / lifecycle status:    10 pts
        """
        score = 0

        # CM: Configuration Management - Signature (20 pts)
        # NIST CM-3, CM-5: signed artifacts ensure config integrity
        if self.signature.verified:
            score += 15
            if self.signature.transparency_log:
                score += 5   # Sigstore transparency adds auditability
        elif self.signature.signer:
            score += 3       # attempted but failed

        # RA: Risk Assessment - Vulnerabilities (25 pts)
        # NIST RA-5: CVSS-weighted penalty model
        if self.vulnerabilities.scanned:
            # CVSS base score weights: Critical=9.0-10.0, High=7.0-8.9
            vuln_penalty = (
                self.vulnerabilities.critical * 10.0   # ~CVSS 9.5 avg
                + self.vulnerabilities.high * 4.0      # ~CVSS 8.0 avg
                + self.vulnerabilities.medium * 1.5    # ~CVSS 5.5 avg
                + self.vulnerabilities.low * 0.3       # ~CVSS 2.5 avg
            )
            score += max(0, int(25 - vuln_penalty))

        # SA: Supply Chain - SBOM + Attestation (20 pts)
        # NIST SA-12: supply chain protection
        if self.sbom.present:
            score += 5
            score += int(self.sbom.completeness_score * 5)  # 0-5 pts
        if self.attestation.present:
            score += 3
            # SLSA level bonus: L1=2, L2=4, L3=6, L4=7
            slsa_pts = min(self.attestation.slsa_level * 2, 7)
            score += slsa_pts

        # AC: Access Control - Runtime security (15 pts)
        # NIST AC-6: least privilege
        sec = self.security
        if sec.rootless:
            score += 8      # primary AC control
        if sec.no_new_privileges:
            score += 4
        if sec.healthcheck:
            score += 3

        # SI: System Integrity - Image hardening (10 pts)
        # NIST SI-7: software integrity
        if sec.from_scratch:
            score += 5      # minimal attack surface
        if sec.read_only_rootfs:
            score += 5      # immutable runtime

        # MA: Maintenance - End-of-Life (10 pts)
        # NIST MA-6: timely maintenance, patching lifecycle
        if self.eol.product:
            if self.eol.eol:
                pass  # 0 pts - past end of life
            elif 0 <= self.eol.days_until_eol <= 180:
                # Approaching EOL - linear decay
                days = self.eol.days_until_eol
                if days > 90:
                    score += 8
                elif days > 30:
                    score += 5
                elif days > 0:
                    score += 2
                # days == 0: 0 pts, expires today
            elif self.eol.support_ended:
                score += 5   # security-only support
            else:
                score += 10  # fully supported (or EOL far away)

        self.trust_score = min(100, max(0, score))
        return self.trust_score

    def compute_verdict(self) -> Verdict:
        """Derive overall verdict from gate results."""
        if not self.gates:
            self.verdict = Verdict.UNKNOWN
            return self.verdict

        if any(g.verdict == Verdict.FAIL for g in self.gates):
            self.verdict = Verdict.FAIL
        elif any(g.verdict == Verdict.WARN for g in self.gates):
            self.verdict = Verdict.WARN
        else:
            self.verdict = Verdict.PASS
        return self.verdict

    # ── Serialization ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize Trust Card to dict."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize Trust Card to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustCard":
        """Deserialize Trust Card from dict."""
        card = cls()
        card.schema_version = data.get("schema_version", SCHEMA_VERSION)
        card.image = data.get("image", "")
        card.digest = data.get("digest", "")
        card.tag = data.get("tag", "")
        card.tier = data.get("tier", "")
        card.verdict = Verdict(data.get("verdict", "UNKNOWN"))
        card.trust_score = data.get("trust_score", 0)
        card.created_at = data.get("created_at", "")
        card.errors = data.get("errors", [])

        if "signature" in data:
            card.signature = SignatureInfo(**data["signature"])
        if "sbom" in data:
            card.sbom = SBOMInfo(**data["sbom"])
        if "attestation" in data:
            card.attestation = AttestationInfo(**data["attestation"])
        if "vulnerabilities" in data:
            vdata = dict(data["vulnerabilities"])
            raw_findings = vdata.pop("findings", [])
            card.vulnerabilities = VulnerabilityInfo(**vdata)
            card.vulnerabilities.findings = [
                CVEDetail(**f) if isinstance(f, dict) else f
                for f in raw_findings
            ]
        if "security" in data:
            card.security = ImageSecurity(**data["security"])
        if "eol" in data:
            card.eol = EOLInfo(**data["eol"])
        if "build" in data:
            card.build = BuildInfo(**data["build"])
        if "compliance" in data:
            card.compliance = [ComplianceResult(**c) for c in data["compliance"]]
        if "gates" in data:
            card.gates = [
                GateResult(
                    name=g["name"],
                    verdict=Verdict(g["verdict"]),
                    reason=g.get("reason", ""),
                    severity=Severity(g.get("severity", "info")),
                )
                for g in data["gates"]
            ]
        return card

    @classmethod
    def from_json(cls, json_str: str) -> "TrustCard":
        """Deserialize Trust Card from JSON string."""
        return cls.from_dict(json.loads(json_str))
