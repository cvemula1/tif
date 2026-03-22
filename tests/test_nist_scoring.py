# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Tests for NIST SP 800-190 aligned trust scoring

from __future__ import annotations

import pytest

from tif.core.trust_card import (
    AttestationInfo,
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


class TestCMSignatureScoring:
    """CM (Config Management) - Signature gate: 20 pts max."""

    def test_verified_with_transparency(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True, transparency_log=True)
        assert card.compute_score() == 20

    def test_verified_without_transparency(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True, transparency_log=False)
        assert card.compute_score() == 15

    def test_attempted_but_failed(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=False, signer="cosign")
        assert card.compute_score() == 3

    def test_no_signature(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=False, signer="")
        assert card.compute_score() == 0


class TestRAVulnerabilityScoring:
    """RA (Risk Assessment) - Vulnerability gate: 25 pts max, CVSS-weighted."""

    def test_clean_scan(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(scanned=True)
        assert card.compute_score() == 25

    def test_one_critical(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=1)
        # 25 - 10 = 15
        assert card.compute_score() == 15

    def test_mixed_cvss_weighted(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(
            scanned=True, critical=0, high=2, medium=4, low=10,
        )
        # 25 - (2*4 + 4*1.5 + 10*0.3) = 25 - (8+6+3) = 8
        assert card.compute_score() == 8

    def test_many_criticals_floors_at_zero(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(scanned=True, critical=5)
        assert card.compute_score() == 0

    def test_not_scanned(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(scanned=False)
        assert card.compute_score() == 0

    def test_low_only(self):
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(scanned=True, low=20)
        # 25 - (20*0.3) = 25 - 6 = 19
        assert card.compute_score() == 19


class TestSASupplyChainScoring:
    """SA (Supply Chain) - SBOM + Attestation: 20 pts max."""

    def test_sbom_full_completeness(self):
        card = TrustCard()
        card.sbom = SBOMInfo(present=True, completeness_score=1.0)
        # 5 + int(1.0*5) = 10
        assert card.compute_score() == 10

    def test_sbom_partial_completeness(self):
        card = TrustCard()
        card.sbom = SBOMInfo(present=True, completeness_score=0.5)
        # 5 + int(0.5*5)=2 = 7
        assert card.compute_score() == 7

    def test_attestation_slsa3(self):
        card = TrustCard()
        card.attestation = AttestationInfo(present=True, slsa_level=3)
        # 3 + min(6, 7) = 9
        assert card.compute_score() == 9

    def test_attestation_slsa4(self):
        card = TrustCard()
        card.attestation = AttestationInfo(present=True, slsa_level=4)
        # 3 + min(8, 7) = 10
        assert card.compute_score() == 10

    def test_sbom_plus_slsa3(self):
        card = TrustCard()
        card.sbom = SBOMInfo(present=True, completeness_score=0.8)
        card.attestation = AttestationInfo(present=True, slsa_level=3)
        # SBOM: 5 + 4 = 9; Attestation: 3 + 6 = 9; Total: 18
        assert card.compute_score() == 18

    def test_no_sbom_no_attestation(self):
        card = TrustCard()
        assert card.compute_score() == 0


class TestACAccessControlScoring:
    """AC (Access Control) - Runtime security: 15 pts max."""

    def test_full_ac(self):
        card = TrustCard()
        card.security = ImageSecurity(
            rootless=True, no_new_privileges=True, healthcheck=True,
        )
        # 8 + 4 + 3 = 15
        assert card.compute_score() == 15

    def test_rootless_only(self):
        card = TrustCard()
        card.security = ImageSecurity(rootless=True)
        assert card.compute_score() == 8

    def test_no_new_privileges_only(self):
        card = TrustCard()
        card.security = ImageSecurity(no_new_privileges=True)
        assert card.compute_score() == 4

    def test_healthcheck_only(self):
        card = TrustCard()
        card.security = ImageSecurity(healthcheck=True)
        assert card.compute_score() == 3


class TestSISystemIntegrityScoring:
    """SI (System Integrity) - Image hardening: 10 pts max."""

    def test_from_scratch(self):
        card = TrustCard()
        card.security = ImageSecurity(from_scratch=True)
        assert card.compute_score() == 5

    def test_read_only_rootfs(self):
        card = TrustCard()
        card.security = ImageSecurity(read_only_rootfs=True)
        assert card.compute_score() == 5

    def test_full_integrity(self):
        card = TrustCard()
        card.security = ImageSecurity(from_scratch=True, read_only_rootfs=True)
        assert card.compute_score() == 10


class TestMAMaintenanceScoring:
    """MA (Maintenance) - EOL lifecycle: 10 pts max."""

    def test_fully_supported(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=False, support_ended=False)
        assert card.compute_score() == 10

    def test_security_only_support(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=False, support_ended=True)
        assert card.compute_score() == 5

    def test_eol_past(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=True, days_until_eol=-100)
        assert card.compute_score() == 0

    def test_approaching_eol_200_days(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=False, days_until_eol=200)
        # >180 days = fully supported (10 pts)
        assert card.compute_score() == 10

    def test_approaching_eol_120_days(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=False, days_until_eol=120)
        # 90 < 120 <= 180 = 8 pts
        assert card.compute_score() == 8

    def test_approaching_eol_60_days(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=False, days_until_eol=60)
        # 30 < 60 <= 90 = 5 pts
        assert card.compute_score() == 5

    def test_approaching_eol_10_days(self):
        card = TrustCard()
        card.eol = EOLInfo(product="python", eol=False, days_until_eol=10)
        # 0 < 10 <= 30 = 2 pts
        assert card.compute_score() == 2

    def test_no_eol_data(self):
        card = TrustCard()
        card.eol = EOLInfo()  # product is empty
        assert card.compute_score() == 0


class TestCombinedScoring:
    """Full scoring scenarios combining all NIST families."""

    def test_perfect_score(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True, transparency_log=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True)
        card.sbom = SBOMInfo(present=True, completeness_score=1.0)
        card.attestation = AttestationInfo(present=True, slsa_level=4)
        card.security = ImageSecurity(
            rootless=True, from_scratch=True, read_only_rootfs=True,
            no_new_privileges=True, healthcheck=True,
        )
        card.eol = EOLInfo(product="python", eol=False, support_ended=False)
        assert card.compute_score() == 100

    def test_score_capped_at_100(self):
        card = TrustCard()
        card.signature = SignatureInfo(verified=True, transparency_log=True)
        card.vulnerabilities = VulnerabilityInfo(scanned=True)
        card.sbom = SBOMInfo(present=True, completeness_score=1.0)
        card.attestation = AttestationInfo(present=True, slsa_level=4)
        card.security = ImageSecurity(
            rootless=True, from_scratch=True, read_only_rootfs=True,
            no_new_privileges=True, healthcheck=True,
        )
        card.eol = EOLInfo(product="python", eol=False, support_ended=False)
        score = card.compute_score()
        assert score <= 100

    def test_typical_production_image(self):
        """Typical well-maintained production image."""
        card = TrustCard()
        card.signature = SignatureInfo(verified=True, transparency_log=True)
        card.vulnerabilities = VulnerabilityInfo(
            scanned=True, critical=0, high=1, medium=3,
        )
        card.sbom = SBOMInfo(present=True, completeness_score=0.9)
        card.attestation = AttestationInfo(present=True, slsa_level=2)
        card.security = ImageSecurity(rootless=True, healthcheck=True)
        card.eol = EOLInfo(product="python", eol=False, support_ended=False)
        score = card.compute_score()
        # CM:20 + RA:25-(4+4.5)=16 + SA:5+4+3+4=16 + AC:8+3=11 + SI:0 + MA:10 = 73
        assert 70 <= score <= 80

    def test_neglected_image(self):
        """Legacy image with no security practices."""
        card = TrustCard()
        card.vulnerabilities = VulnerabilityInfo(
            scanned=True, critical=3, high=10,
        )
        card.eol = EOLInfo(product="python", eol=True)
        score = card.compute_score()
        # RA: 25-(30+40) -> 0; MA: 0 (eol=True)
        assert score == 0


class TestEOLInfoDataclass:
    def test_defaults(self):
        eol = EOLInfo()
        assert eol.product == ""
        assert eol.eol is False
        assert eol.days_until_eol == -1

    def test_custom(self):
        eol = EOLInfo(
            product="python", version="3.12", cycle="3.12",
            eol=False, eol_date="2028-10-01", lts=False,
        )
        assert eol.product == "python"
        assert eol.cycle == "3.12"

    def test_serialization_roundtrip(self):
        card = TrustCard(image="test/img")
        card.eol = EOLInfo(
            product="alpine", version="3.20", cycle="3.20",
            eol=False, eol_date="2026-11-01",
        )
        restored = TrustCard.from_json(card.to_json())
        assert restored.eol.product == "alpine"
        assert restored.eol.eol_date == "2026-11-01"
