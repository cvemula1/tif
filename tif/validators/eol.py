# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# End-of-Life (EOL) checking via endoflife.date API and NIST NVD

from __future__ import annotations

import json
import logging
import re
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import date
from typing import Dict, Optional, Tuple

from tif.core.trust_card import GateResult, Severity, Verdict

logger = logging.getLogger(__name__)

EOL_API_BASE = "https://endoflife.date/api"

# Map common Docker base image names to endoflife.date product slugs
_IMAGE_TO_PRODUCT: Dict[str, str] = {
    "alpine": "alpine",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "fedora": "fedora",
    "amazonlinux": "amazon-linux",
    "amazon/aws-cli": "amazon-linux",
    "oraclelinux": "oracle-linux",
    "rockylinux": "rocky-linux",
    "almalinux": "almalinux",
    "archlinux": "arch-linux",
    "opensuse": "opensuse",
    "sles": "suse",
    "photon": "photon",
    "node": "nodejs",
    "python": "python",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
    "openjdk": "java",
    "eclipse-temurin": "java",
    "amazoncorretto": "amazon-corretto",
    "rust": "rust",
    "dotnet/sdk": "dotnet",
    "dotnet/aspnet": "dotnet",
    "dotnet/runtime": "dotnet",
    "nginx": "nginx",
    "httpd": "apache-http-server",
    "postgres": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "redis": "redis",
    "mongo": "mongodb",
    "elasticsearch": "elasticsearch",
    "rabbitmq": "rabbitmq",
    "haproxy": "haproxy",
    "traefik": "traefik",
    "consul": "consul",
    "vault": "hashicorp-vault",
    "terraform": "terraform",
}


@dataclass
class EOLInfo:
    """End-of-Life status for a base image."""
    product: str = ""
    version: str = ""
    cycle: str = ""
    eol: bool = False
    eol_date: str = ""
    lts: bool = False
    latest_version: str = ""
    release_date: str = ""
    days_until_eol: int = -1
    support_ended: bool = False
    error: str = ""


def check_eol(
    image: str,
    fail_on_eol: bool = True,
    warn_days_before_eol: int = 90,
) -> Tuple[EOLInfo, GateResult]:
    """
    Check if the base image is past or near End-of-Life.

    Uses the endoflife.date API to look up EOL status.

    Args:
        image: Full image reference (e.g. python:3.9-slim, alpine:3.18)
        fail_on_eol: Fail gate if image is past EOL
        warn_days_before_eol: Warn if EOL is within this many days

    Returns:
        Tuple of (EOLInfo, GateResult)
    """
    info = EOLInfo()
    gate = GateResult(name="End-of-Life", verdict=Verdict.UNKNOWN)

    # Parse image name and version
    product, version = _parse_image_ref(image)
    if not product:
        info.error = f"Could not determine base image product from: {image}"
        gate.verdict = Verdict.WARN
        gate.reason = "Unable to determine base image for EOL check"
        return info, gate

    info.product = product
    info.version = version

    # Look up EOL data
    eol_data = _fetch_eol(product, version)
    if eol_data is None:
        info.error = f"No EOL data found for {product} {version}"
        gate.verdict = Verdict.WARN
        gate.reason = f"No EOL data available for {product} {version}"
        return info, gate

    # Parse EOL response
    _parse_eol_response(eol_data, info)

    # Evaluate gate
    if info.eol:
        if fail_on_eol:
            gate.verdict = Verdict.FAIL
            gate.severity = Severity.HIGH
            gate.reason = (
                f"{info.product} {info.cycle} reached EOL on {info.eol_date}. "
                f"Upgrade to a supported version."
            )
        else:
            gate.verdict = Verdict.WARN
            gate.reason = f"{info.product} {info.cycle} is past EOL ({info.eol_date})"
    elif info.days_until_eol >= 0 and info.days_until_eol <= warn_days_before_eol:
        gate.verdict = Verdict.WARN
        gate.reason = (
            f"{info.product} {info.cycle} reaches EOL in {info.days_until_eol} days "
            f"({info.eol_date})"
        )
    elif info.support_ended:
        gate.verdict = Verdict.WARN
        gate.reason = (
            f"{info.product} {info.cycle} active support has ended "
            f"(security fixes only until {info.eol_date})"
        )
    else:
        gate.verdict = Verdict.PASS
        if info.eol_date:
            gate.reason = f"{info.product} {info.cycle} is supported (EOL: {info.eol_date})"
        else:
            gate.reason = f"{info.product} {info.cycle} is supported"

    return info, gate


def _parse_image_ref(image: str) -> Tuple[str, str]:
    """
    Parse image reference to extract product name and version.

    Examples:
        python:3.11-slim  -> ("python", "3.11")
        alpine:3.20       -> ("alpine", "3.20")
        ubuntu:22.04      -> ("ubuntu", "22.04")
        nginx:1.25-alpine -> ("nginx", "1.25")
        registry.io/library/node:20-bullseye -> ("node", "20")
    """
    # Strip registry prefix
    name = image
    if "@" in name:
        name = name.split("@")[0]

    # Remove registry prefix (anything before the last segment with /)
    parts = name.split("/")
    name_tag = parts[-1]  # e.g. "python:3.11-slim"

    # Split name:tag
    if ":" in name_tag:
        img_name, tag = name_tag.split(":", 1)
    else:
        img_name = name_tag
        tag = ""

    # Handle multi-segment names (e.g. dotnet/sdk)
    if len(parts) >= 2:
        parent = parts[-2]
        if parent in ("dotnet",):
            img_name = f"{parent}/{img_name}"

    # Map to product slug
    product = _IMAGE_TO_PRODUCT.get(img_name, "")
    if not product:
        # Try without common suffixes
        base = img_name.split("-")[0]
        product = _IMAGE_TO_PRODUCT.get(base, "")

    if not product:
        return "", ""

    # Extract version from tag
    version = _extract_version(tag)
    return product, version


def _extract_version(tag: str) -> str:
    """Extract version number from a Docker tag."""
    if not tag:
        return "latest"

    # Match version patterns: 3.11, 22.04, 20, 1.25.3, etc.
    match = re.match(r"^(\d+(?:\.\d+)*)", tag)
    if match:
        return match.group(1)

    # Tags like "bullseye", "bookworm", "jammy" - these are codenames
    codename_map = {
        "bookworm": "12", "bullseye": "11", "buster": "10", "stretch": "9",
        "jammy": "22.04", "noble": "24.04", "focal": "20.04", "bionic": "18.04",
    }
    tag_lower = tag.lower().split("-")[0]
    if tag_lower in codename_map:
        return codename_map[tag_lower]

    return tag


def _fetch_eol(product: str, version: str) -> Optional[dict]:
    """Fetch EOL data from endoflife.date API."""
    # Try specific version first
    if version and version != "latest":
        cycle = _version_to_cycle(version)
        url = f"{EOL_API_BASE}/{product}/{cycle}.json"
        data = _http_get(url)
        if data:
            return data

    # Try listing all cycles and finding best match
    url = f"{EOL_API_BASE}/{product}.json"
    all_cycles = _http_get(url)
    if all_cycles and isinstance(all_cycles, list):
        if version and version != "latest":
            return _find_best_cycle(all_cycles, version)
        elif all_cycles:
            return all_cycles[0]  # latest cycle

    return None


def _version_to_cycle(version: str) -> str:
    """Convert version to API cycle (e.g. 3.11.5 -> 3.11, 22.04 -> 22.04)."""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def _find_best_cycle(cycles: list, version: str) -> Optional[dict]:
    """Find the best matching cycle for a version."""
    target = _version_to_cycle(version)
    for cycle in cycles:
        cycle_id = str(cycle.get("cycle", ""))
        if cycle_id == target or cycle_id == version:
            return cycle
        # Partial match (e.g. version "3" matches cycle "3.20")
        if cycle_id.startswith(version + ".") or version.startswith(cycle_id + "."):
            return cycle
    return None


def _http_get(url: str) -> Optional[any]:
    """Simple HTTP GET with JSON parsing."""
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "tif-cli/0.1"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as e:
        logger.debug("EOL API request failed for %s: %s", url, e)
    return None


def _parse_eol_response(data: dict, info: EOLInfo) -> None:
    """Parse endoflife.date API response into EOLInfo."""
    info.cycle = str(data.get("cycle", info.version))
    info.latest_version = str(data.get("latest", ""))
    info.release_date = str(data.get("releaseDate", ""))
    info.lts = bool(data.get("lts", False))

    # EOL field can be bool or date string
    eol_val = data.get("eol", False)
    if isinstance(eol_val, bool):
        info.eol = eol_val
        info.eol_date = ""
    elif isinstance(eol_val, str):
        info.eol_date = eol_val
        try:
            eol_date = date.fromisoformat(eol_val)
            today = date.today()
            info.eol = eol_date <= today
            info.days_until_eol = (eol_date - today).days
        except ValueError:
            info.eol = False

    # Support field (active support vs security-only)
    support_val = data.get("support", None)
    if isinstance(support_val, str):
        try:
            support_date = date.fromisoformat(support_val)
            info.support_ended = support_date <= date.today()
        except ValueError:
            pass
    elif isinstance(support_val, bool):
        info.support_ended = not support_val
