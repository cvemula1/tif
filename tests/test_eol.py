# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Tests for EOL validator

from __future__ import annotations

import json
from datetime import date, timedelta
from unittest.mock import patch, MagicMock

import pytest

from tif.core.trust_card import Verdict
from tif.validators.eol import (
    EOLInfo,
    _parse_image_ref,
    _extract_version,
    _parse_eol_response,
    check_eol,
)


class TestParseImageRef:
    def test_python_with_version(self):
        product, version = _parse_image_ref("python:3.11-slim")
        assert product == "python"
        assert version == "3.11"

    def test_alpine_with_version(self):
        product, version = _parse_image_ref("alpine:3.20")
        assert product == "alpine"
        assert version == "3.20"

    def test_ubuntu_with_version(self):
        product, version = _parse_image_ref("ubuntu:22.04")
        assert product == "ubuntu"
        assert version == "22.04"

    def test_node_with_major(self):
        product, version = _parse_image_ref("node:20-bullseye")
        assert product == "nodejs"
        assert version == "20"

    def test_registry_prefix(self):
        product, version = _parse_image_ref("registry.io/library/python:3.12")
        assert product == "python"
        assert version == "3.12"

    def test_nginx_with_alpine(self):
        product, version = _parse_image_ref("nginx:1.25-alpine")
        assert product == "nginx"
        assert version == "1.25"

    def test_golang(self):
        product, version = _parse_image_ref("golang:1.22")
        assert product == "go"
        assert version == "1.22"

    def test_postgres(self):
        product, version = _parse_image_ref("postgres:16")
        assert product == "postgresql"
        assert version == "16"

    def test_redis(self):
        product, version = _parse_image_ref("redis:7.2")
        assert product == "redis"
        assert version == "7.2"

    def test_unknown_image(self):
        product, version = _parse_image_ref("mycompany/custom-app:1.0")
        assert product == ""
        assert version == ""

    def test_with_digest(self):
        product, version = _parse_image_ref("python:3.11@sha256:abc123")
        assert product == "python"
        assert version == "3.11"

    def test_debian_codename(self):
        product, version = _parse_image_ref("debian:bookworm")
        assert product == "debian"
        assert version == "12"

    def test_ubuntu_codename(self):
        product, version = _parse_image_ref("ubuntu:jammy")
        assert product == "ubuntu"
        assert version == "22.04"


class TestExtractVersion:
    def test_semver(self):
        assert _extract_version("3.11.5") == "3.11.5"

    def test_major_minor(self):
        assert _extract_version("3.11") == "3.11"

    def test_major_only(self):
        assert _extract_version("20") == "20"

    def test_with_suffix(self):
        assert _extract_version("3.11-slim") == "3.11"

    def test_empty(self):
        assert _extract_version("") == "latest"

    def test_codename_bookworm(self):
        assert _extract_version("bookworm") == "12"

    def test_codename_jammy(self):
        assert _extract_version("jammy") == "22.04"


class TestParseEOLResponse:
    def test_active_product(self):
        info = EOLInfo()
        future = (date.today() + timedelta(days=500)).isoformat()
        _parse_eol_response({
            "cycle": "3.12",
            "latest": "3.12.8",
            "releaseDate": "2023-10-02",
            "eol": future,
            "lts": False,
        }, info)
        assert info.cycle == "3.12"
        assert info.eol is False
        assert info.days_until_eol > 0

    def test_eol_product(self):
        info = EOLInfo()
        past = (date.today() - timedelta(days=100)).isoformat()
        _parse_eol_response({
            "cycle": "2.7",
            "latest": "2.7.18",
            "eol": past,
        }, info)
        assert info.eol is True
        assert info.days_until_eol < 0

    def test_boolean_eol_true(self):
        info = EOLInfo()
        _parse_eol_response({"cycle": "1.0", "eol": True}, info)
        assert info.eol is True

    def test_boolean_eol_false(self):
        info = EOLInfo()
        _parse_eol_response({"cycle": "1.0", "eol": False}, info)
        assert info.eol is False

    def test_lts_flag(self):
        info = EOLInfo()
        future = (date.today() + timedelta(days=1000)).isoformat()
        _parse_eol_response({"cycle": "20", "eol": future, "lts": True}, info)
        assert info.lts is True

    def test_support_ended(self):
        info = EOLInfo()
        past_support = (date.today() - timedelta(days=30)).isoformat()
        future_eol = (date.today() + timedelta(days=200)).isoformat()
        _parse_eol_response({
            "cycle": "22.04",
            "eol": future_eol,
            "support": past_support,
        }, info)
        assert info.support_ended is True
        assert info.eol is False


class TestCheckEOL:
    @patch("tif.validators.eol._http_get")
    def test_supported_image(self, mock_get):
        future = (date.today() + timedelta(days=500)).isoformat()
        mock_get.return_value = {
            "cycle": "3.12",
            "latest": "3.12.8",
            "releaseDate": "2023-10-02",
            "eol": future,
            "lts": False,
        }
        info, gate = check_eol("python:3.12-slim")
        assert gate.verdict == Verdict.PASS
        assert info.product == "python"
        assert info.eol is False

    @patch("tif.validators.eol._http_get")
    def test_eol_image_fails(self, mock_get):
        past = (date.today() - timedelta(days=100)).isoformat()
        mock_get.return_value = {
            "cycle": "2.7",
            "latest": "2.7.18",
            "eol": past,
        }
        info, gate = check_eol("python:2.7", fail_on_eol=True)
        assert gate.verdict == Verdict.FAIL
        assert info.eol is True

    @patch("tif.validators.eol._http_get")
    def test_eol_image_warns_when_not_required(self, mock_get):
        past = (date.today() - timedelta(days=100)).isoformat()
        mock_get.return_value = {
            "cycle": "2.7",
            "latest": "2.7.18",
            "eol": past,
        }
        info, gate = check_eol("python:2.7", fail_on_eol=False)
        assert gate.verdict == Verdict.WARN

    @patch("tif.validators.eol._http_get")
    def test_approaching_eol_warns(self, mock_get):
        soon = (date.today() + timedelta(days=30)).isoformat()
        mock_get.return_value = {
            "cycle": "3.8",
            "latest": "3.8.20",
            "eol": soon,
        }
        info, gate = check_eol("python:3.8", warn_days_before_eol=90)
        assert gate.verdict == Verdict.WARN
        assert "days" in gate.reason

    def test_unknown_image(self):
        info, gate = check_eol("mycompany/custom-app:1.0")
        assert gate.verdict == Verdict.WARN
        assert "Unable to determine" in gate.reason

    @patch("tif.validators.eol._http_get")
    def test_api_returns_none(self, mock_get):
        mock_get.return_value = None
        info, gate = check_eol("python:3.12")
        assert gate.verdict == Verdict.WARN
        assert "No EOL data" in gate.reason
