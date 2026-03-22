# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Tests for Dockerfile analyzer and hardener

from __future__ import annotations

import pytest
from pathlib import Path

from tif.core.trust_card import Verdict
from tif.validators.dockerfile import analyze_dockerfile
from tif.generators.harden import harden_dockerfile


@pytest.fixture
def bad_dockerfile(tmp_path):
    """A Dockerfile with multiple security issues."""
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM ubuntu:latest\n"
        "ADD app.tar.gz /app\n"
        "ENV DB_PASSWORD=secret123\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "EXPOSE 22\n"
        "RUN chmod 777 /app\n"
        "CMD [\"python\", \"app.py\"]\n"
    )
    return str(df)


@pytest.fixture
def good_dockerfile(tmp_path):
    """A well-written Dockerfile."""
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM python:3.12-slim@sha256:abc123\n"
        "COPY requirements.txt /app/\n"
        "RUN pip install --no-cache-dir -r /app/requirements.txt\n"
        "COPY src/ /app/src/\n"
        "USER 65532\n"
        "HEALTHCHECK --interval=30s CMD [\"true\"]\n"
        "CMD [\"python\", \"/app/src/main.py\"]\n"
    )
    return str(df)


class TestDockerfileAnalyzer:
    def test_bad_dockerfile_findings(self, bad_dockerfile):
        findings, gate = analyze_dockerfile(bad_dockerfile)
        assert gate.verdict in (Verdict.FAIL, Verdict.WARN)
        rules = [f.rule for f in findings]
        assert "DF-003" in rules  # :latest
        assert "DF-002" in rules  # ADD
        assert "DF-010" in rules  # secret in ENV
        assert "DF-006" in rules  # EXPOSE 22
        assert "DF-009" in rules  # chmod 777
        assert "DF-100" in rules  # no USER

    def test_good_dockerfile_passes(self, good_dockerfile):
        findings, gate = analyze_dockerfile(good_dockerfile)
        # Should have no critical/high findings
        critical = [f for f in findings if f.severity == "critical"]
        high = [f for f in findings if f.severity == "high"]
        assert len(critical) == 0
        assert len(high) == 0

    def test_missing_dockerfile(self):
        findings, gate = analyze_dockerfile("/nonexistent/Dockerfile")
        assert gate.verdict == Verdict.FAIL

    def test_findings_have_fixes(self, bad_dockerfile):
        findings, gate = analyze_dockerfile(bad_dockerfile)
        for f in findings:
            if f.rule.startswith("DF-0"):
                assert f.fix, f"Rule {f.rule} should have a fix suggestion"


class TestDockerfileHardener:
    def test_harden_adds_user(self, bad_dockerfile):
        result = harden_dockerfile(bad_dockerfile)
        assert "USER 65532" in result

    def test_harden_adds_healthcheck(self, bad_dockerfile):
        result = harden_dockerfile(bad_dockerfile)
        assert "HEALTHCHECK" in result

    def test_harden_replaces_add(self, bad_dockerfile):
        result = harden_dockerfile(bad_dockerfile)
        assert "COPY app.tar.gz" in result

    def test_harden_removes_expose_22(self, bad_dockerfile):
        result = harden_dockerfile(bad_dockerfile)
        assert "EXPOSE 22" not in result or "removed" in result.lower()

    def test_harden_removes_secrets(self, bad_dockerfile):
        result = harden_dockerfile(bad_dockerfile)
        assert "DB_PASSWORD=secret123" not in result or "removed" in result.lower()

    def test_harden_fixes_chmod(self, bad_dockerfile):
        result = harden_dockerfile(bad_dockerfile)
        assert "chmod 755" in result

    def test_harden_output_to_file(self, bad_dockerfile, tmp_path):
        output = str(tmp_path / "Dockerfile.hardened")
        harden_dockerfile(bad_dockerfile, output_path=output)
        assert Path(output).exists()
        content = Path(output).read_text()
        assert "USER 65532" in content

    def test_harden_missing_file(self):
        with pytest.raises(FileNotFoundError):
            harden_dockerfile("/nonexistent/Dockerfile")

    def test_harden_preserves_good(self, good_dockerfile):
        result = harden_dockerfile(good_dockerfile)
        assert "USER 65532" in result
        assert "HEALTHCHECK" in result
