# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Tests for Trust Card schema

from __future__ import annotations

import json
import pytest

from tif.core.trust_card import (
    AttestationInfo,
    ComplianceResult,
    CVEDetail,
    EOLInfo,
    GateResult,
    ImageSecurity,
    SBOMInfo,
    Severity,
    SignatureInfo,
    TrustCard,
    Verdict,
    VulnerabilityInfo,
)


class TestTrustCardCreation:
    def test_default_card(self):
        card = TrustCard()
        assert card.schema_version == "1.0"
        assert card.verdict == Verdict.UNKNOWN
        assert card.trust_score == 0
        assert card.created_at.endswith("Z")

    def test_card_with_image(self):
        card = TrustCard(image="registry.io/app", tag="1.0")
        assert card.image == "registry.io/app"
        assert card.tag == "1.0"

    def test_card_with_all_fields(self):
        card = TrustCard(
            image="registry.io/app",
            tag="1.0",
            digest="sha256:abc123",
            tier="hardened",
        )
        card.signature = SignatureInfo(verified=True, signer="cosign")
        card.sbom = SBOMInfo(present=True, format="spdx-2.3", packages=42)
        assert card.signature.verified is True
        assert card.sbom.packages == 42


class TestTrustScore:
    def test_perfect_score(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True, transparency_log=True)
        card.sbom = SBOMInfo(present=True, completeness_score=1.0)
        card.attestation = AttestationInfo(present=True, slsa_level=4)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0, high=0, medium=0)
        card.security = ImageSecurity(
            rootless=True, from_scratch=True, read_only_rootfs=True,
            no_new_privileges=True, healthcheck=True,
        )
        card.eol = EOLInfo(product="python", eol=False, support_ended=False)
        score = card.compute_score()
        assert score == 100

    def test_zero_score(self):
        card = TrustCard()
        score = card.compute_score()
        assert score == 0

    def test_signature_only(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True)
        score = card.compute_score()
        # CM: 15 pts (verified, no transparency log)
        assert score == 15

    def test_vuln_penalty(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=1)
        score = card.compute_score()
        # 25 - 10 (1 critical) = 15
        assert score == 15

    def test_partial_security(self):
        card = TrustCard()
        card.security = ImageSecurity(rootless=True, healthcheck=True)
        score = card.compute_score()
        # AC: 8 (rootless) + 3 (healthcheck) = 11
        assert score == 11


class TestVerdict:
    def test_no_gates_unknown(self):
        card = TrustCard()
        assert card.compute_verdict() == Verdict.UNKNOWN

    def test_all_pass(self):
        card = TrustCard()
        card.gates = [
            GateResult(name="A", verdict=Verdict.PASS),
            GateResult(name="B", verdict=Verdict.PASS),
        ]
        assert card.compute_verdict() == Verdict.PASS

    def test_any_fail(self):
        card = TrustCard()
        card.gates = [
            GateResult(name="A", verdict=Verdict.PASS),
            GateResult(name="B", verdict=Verdict.FAIL),
        ]
        assert card.compute_verdict() == Verdict.FAIL

    def test_warn_no_fail(self):
        card = TrustCard()
        card.gates = [
            GateResult(name="A", verdict=Verdict.PASS),
            GateResult(name="B", verdict=Verdict.WARN),
        ]
        assert card.compute_verdict() == Verdict.WARN

    def test_fail_overrides_warn(self):
        card = TrustCard()
        card.gates = [
            GateResult(name="A", verdict=Verdict.WARN),
            GateResult(name="B", verdict=Verdict.FAIL),
        ]
        assert card.compute_verdict() == Verdict.FAIL


class TestSerialization:
    def test_to_json_roundtrip(self):
        card = TrustCard(image="test/image", tag="latest")
        card.signature = SignatureInfo(verified=True, signer="cosign")
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0, high=2)
        card.gates = [
            GateResult(name="Sig", verdict=Verdict.PASS, reason="OK"),
        ]
        card.compute_score()
        card.compute_verdict()

        json_str = card.to_json()
        restored = TrustCard.from_json(json_str)

        assert restored.image == "test/image"
        assert restored.tag == "latest"
        assert restored.signature.verified is True
        assert restored.signature.signer == "cosign"
        assert restored.vulnerabilities.critical == 0
        assert restored.vulnerabilities.high == 2
        assert len(restored.gates) == 1
        assert restored.gates[0].verdict == Verdict.PASS

    def test_to_dict(self):
        card = TrustCard(image="test/image")
        d = card.to_dict()
        assert isinstance(d, dict)
        assert d["image"] == "test/image"
        assert d["schema_version"] == "1.0"

    def test_from_example_file(self):
        import os
        example = os.path.join(
            os.path.dirname(__file__), "..", "examples", "trust-card-alpine.json"
        )
        if os.path.exists(example):
            with open(example) as f:
                card = TrustCard.from_json(f.read())
            assert card.image == "registry.example.com/tif-minimal/alpine"
            assert card.verdict == Verdict.PASS
            assert card.trust_score == 95


class TestCVEDetail:
    def test_defaults(self):
        cve = CVEDetail()
        assert cve.id == ""
        assert cve.has_fix is False
        assert cve.cvss_score == 0.0

    def test_with_fix(self):
        cve = CVEDetail(
            id="CVE-2024-3094",
            severity="CRITICAL",
            cvss_score=9.8,
            package="openssl",
            installed_version="3.0.1",
            fixed_version="3.0.2",
            has_fix=True,
        )
        assert cve.has_fix is True
        assert cve.fixed_version == "3.0.2"

    def test_findings_roundtrip(self):
        """CVEDetail objects survive TrustCard JSON serialization."""
        card = TrustCard(image="test/image", tag="1.0")
        card.vulnerabilities = VulnerabilityInfo(
            scanned=True,
            critical=1,
            fixable_critical=1,
            findings=[
                CVEDetail(
                    id="CVE-2024-3094",
                    severity="CRITICAL",
                    cvss_score=9.8,
                    package="openssl",
                    installed_version="3.0.1",
                    fixed_version="3.0.2",
                    has_fix=True,
                ),
                CVEDetail(
                    id="CVE-2024-9999",
                    severity="HIGH",
                    cvss_score=7.5,
                    package="libcurl",
                    installed_version="8.4.0",
                    fixed_version="",
                    has_fix=False,
                ),
            ],
        )
        restored = TrustCard.from_json(card.to_json())

        assert len(restored.vulnerabilities.findings) == 2
        f0 = restored.vulnerabilities.findings[0]
        assert f0.id == "CVE-2024-3094"
        assert f0.severity == "CRITICAL"
        assert f0.cvss_score == 9.8
        assert f0.has_fix is True
        assert f0.fixed_version == "3.0.2"

        f1 = restored.vulnerabilities.findings[1]
        assert f1.id == "CVE-2024-9999"
        assert f1.has_fix is False
        assert f1.fixed_version == ""

    def test_findings_empty_roundtrip(self):
        """Empty findings list round-trips cleanly."""
        card = TrustCard(image="test/image")
        card.vulnerabilities = VulnerabilityInfo(scanned=True, findings=[])
        restored = TrustCard.from_json(card.to_json())
        assert restored.vulnerabilities.findings == []

    def test_fixable_fields_roundtrip(self):
        """fixable_critical, fixable_high, total_suppressed survive serialization."""
        card = TrustCard(image="test/image")
        card.vulnerabilities = VulnerabilityInfo(
            scanned=True,
            critical=3,
            high=5,
            fixable_critical=1,
            fixable_high=2,
            total_suppressed=5,
        )
        restored = TrustCard.from_json(card.to_json())
        v = restored.vulnerabilities
        assert v.fixable_critical == 1
        assert v.fixable_high == 2
        assert v.total_suppressed == 5


class TestVulnerabilityInfo:
    def test_total(self):
        v = VulnerabilityInfo(critical=1, high=2, medium=3, low=4, unknown=5)
        assert v.total == 15

    def test_zero_total(self):
        v = VulnerabilityInfo()
        assert v.total == 0


class TestEnums:
    def test_verdict_values(self):
        assert Verdict.PASS.value == "PASS"
        assert Verdict.FAIL.value == "FAIL"
        assert Verdict.WARN.value == "WARN"
        assert Verdict.UNKNOWN.value == "UNKNOWN"

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.INFO.value == "info"
