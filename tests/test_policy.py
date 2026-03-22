# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Tests for policy engine

from __future__ import annotations

import pytest

from tif.core.trust_card import (
    GateResult,
    ImageSecurity,
    SBOMInfo,
    SignatureInfo,
    TrustCard,
    Verdict,
    VulnerabilityInfo,
)
from tif.policies.engine import evaluate_policy, list_policy_packs


def _add_gates(card, names):
    """Add gate results so _gate_available recognises them as ran."""
    for name in names:
        card.gates.append(GateResult(name=name, verdict=Verdict.PASS, reason="test"))


class TestBuiltinDefault:
    def test_pass_signed_no_cves(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0)
        _add_gates(card, ["Signature", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="default")
        assert gate.verdict == Verdict.PASS

    def test_fail_unsigned(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=False)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0)
        _add_gates(card, ["Signature", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="default")
        assert gate.verdict == Verdict.FAIL

    def test_fail_critical_cves(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=3)
        _add_gates(card, ["Signature", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="default")
        assert gate.verdict == Verdict.FAIL


class TestBuiltinCISL1:
    def test_pass_rootless_health_no_crit(self):
        card = TrustCard()
        card.security = ImageSecurity(rootless=True, user="65532", healthcheck=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0)
        _add_gates(card, ["Image Security", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="cis-l1")
        assert gate.verdict == Verdict.PASS

    def test_fail_root_user(self):
        card = TrustCard()
        card.security = ImageSecurity(rootless=False, user="root", healthcheck=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0)
        _add_gates(card, ["Image Security", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="cis-l1")
        assert gate.verdict == Verdict.FAIL
        findings = compliance[0].findings
        assert any("CIS 4.1" in f for f in findings)


class TestBuiltinCISL2:
    def test_pass_all_checks(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True)
        card.security = ImageSecurity(
            rootless=True, user="65532", healthcheck=True,
            read_only_rootfs=True, no_new_privileges=True,
        )
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0)
        _add_gates(card, ["Signature", "Image Security", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="cis-l2")
        assert gate.verdict == Verdict.PASS

    def test_fail_missing_signature(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=False)
        card.security = ImageSecurity(
            rootless=True, user="65532", healthcheck=True,
            read_only_rootfs=True, no_new_privileges=True,
        )
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0)
        _add_gates(card, ["Signature", "Image Security", "Vulnerabilities"])
        compliance, gate = evaluate_policy(card, policy_pack="cis-l2")
        assert gate.verdict == Verdict.FAIL


class TestBuiltinNIST:
    def test_pass_all(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0, high=2)
        card.sbom = SBOMInfo(present=True, packages=10)
        card.security = ImageSecurity(rootless=True, user="65532")
        _add_gates(card, ["Signature", "Vulnerabilities", "SBOM", "Image Security"])
        compliance, gate = evaluate_policy(card, policy_pack="nist-800-190")
        assert gate.verdict == Verdict.PASS

    def test_fail_no_sbom(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=0, high=0)
        card.sbom = SBOMInfo(present=False)
        card.security = ImageSecurity(rootless=True, user="65532")
        _add_gates(card, ["Signature", "Vulnerabilities", "SBOM", "Image Security"])
        compliance, gate = evaluate_policy(card, policy_pack="nist-800-190")
        assert gate.verdict == Verdict.FAIL


class TestPolicyPacks:
    def test_list_packs(self):
        packs = list_policy_packs()
        assert "default" in packs
        assert "cis-l1" in packs
        assert "cis-l2" in packs
        assert "nist-800-190" in packs
