# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Image security analysis — rootless, FROM scratch, layers, metadata

from __future__ import annotations

import json
import logging
import re
import subprocess
import urllib.request
import urllib.error
from typing import Optional

from tif.core.trust_card import GateResult, ImageSecurity, Verdict

logger = logging.getLogger(__name__)


def inspect_image(image: str) -> tuple[ImageSecurity, GateResult]:
    """
    Inspect container image for security properties.

    Checks: rootless user, FROM scratch, read-only rootfs,
    healthcheck, layer count, image size.

    Args:
        image: Full image reference

    Returns:
        Tuple of (ImageSecurity, GateResult)
    """
    sec = ImageSecurity()
    gate = GateResult(name="Image Security", verdict=Verdict.UNKNOWN)

    config = _get_image_config(image)
    if config is None:
        gate.verdict = Verdict.WARN
        gate.reason = "Could not inspect image config"
        return sec, gate

    # Parse config
    _parse_config(config, sec)

    # Evaluate security posture
    issues = []

    if not sec.rootless:
        issues.append("runs as root")
    if not sec.healthcheck:
        issues.append("no HEALTHCHECK")

    if not issues:
        gate.verdict = Verdict.PASS
        flags = []
        if sec.rootless:
            flags.append("rootless")
        if sec.from_scratch:
            flags.append("FROM scratch")
        if sec.read_only_rootfs:
            flags.append("read-only rootfs")
        gate.reason = f"Image security OK: {', '.join(flags)}" if flags else "Image security OK"
    elif sec.rootless:
        gate.verdict = Verdict.WARN
        gate.reason = f"Minor issues: {', '.join(issues)}"
    else:
        gate.verdict = Verdict.FAIL
        gate.reason = f"Security issues: {', '.join(issues)}"

    return sec, gate


def _get_image_config(image: str) -> Optional[dict]:
    """Get image config via docker/skopeo inspect, or OCI registry API."""
    # Try docker inspect first
    config = _docker_inspect(image)
    if config:
        return config

    # Try skopeo inspect
    config = _skopeo_inspect(image)
    if config:
        return config

    # Fallback: pure Python OCI registry API (no tools needed)
    config = _oci_registry_inspect(image)
    if config:
        return config

    return None


def _docker_inspect(image: str) -> Optional[dict]:
    """Inspect image using docker."""
    try:
        cmd = ["docker", "inspect", image]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if isinstance(data, list) and data:
                return data[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    # Try pulling first, then inspect
    try:
        subprocess.run(
            ["docker", "pull", image],
            capture_output=True, text=True, timeout=300,
        )
        cmd = ["docker", "inspect", image]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if isinstance(data, list) and data:
                return data[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    return None


def _skopeo_inspect(image: str) -> Optional[dict]:
    """Inspect image using skopeo (no pull required)."""
    try:
        ref = image if image.startswith("docker://") else f"docker://{image}"
        cmd = ["skopeo", "inspect", "--config", ref]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


# ── Pure Python OCI registry client ──────────────────────────────────────

def _parse_image_reference(image: str) -> tuple[str, str, str]:
    """Parse image reference into (registry, repository, reference)."""
    # Remove digest if present
    ref = image
    tag = "latest"

    if "@" in ref:
        ref, _ = ref.split("@", 1)
    if ":" in ref:
        parts = ref.rsplit(":", 1)
        # Avoid splitting on port numbers (e.g. localhost:5000/repo)
        if "/" not in parts[1]:
            ref, tag = parts

    # Determine registry and repository
    parts = ref.split("/")
    if len(parts) == 1:
        # e.g. "alpine" -> docker.io/library/alpine
        return "registry-1.docker.io", f"library/{parts[0]}", tag
    elif len(parts) == 2 and "." not in parts[0] and ":" not in parts[0]:
        # e.g. "myuser/myapp" -> docker.io/myuser/myapp
        return "registry-1.docker.io", f"{parts[0]}/{parts[1]}", tag
    else:
        # e.g. "ghcr.io/org/repo" or "docker.io/library/alpine"
        registry = parts[0]
        repo = "/".join(parts[1:])
        # Docker Hub special case
        if registry in ("docker.io", "index.docker.io"):
            registry = "registry-1.docker.io"
            if "/" not in repo:
                repo = f"library/{repo}"
        return registry, repo, tag


def _get_auth_token(registry: str, repository: str) -> Optional[str]:
    """Get bearer token for registry authentication."""
    if registry == "registry-1.docker.io":
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
    else:
        # Try token endpoint via WWW-Authenticate challenge
        try:
            req = urllib.request.Request(
                f"https://{registry}/v2/",
                method="GET",
            )
            urllib.request.urlopen(req, timeout=10)
            return None  # No auth needed
        except urllib.error.HTTPError as e:
            if e.code == 401:
                auth_header = e.headers.get("WWW-Authenticate", "")
                match = re.search(r'realm="([^"]+)"', auth_header)
                service_match = re.search(r'service="([^"]+)"', auth_header)
                if match:
                    realm = match.group(1)
                    service = service_match.group(1) if service_match else ""
                    url = f"{realm}?service={service}&scope=repository:{repository}:pull"
                else:
                    return None
            else:
                return None
        except Exception:
            return None

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("token") or data.get("access_token")
    except Exception:
        return None


def _registry_get(url: str, token: Optional[str], accept: str = "application/json") -> Optional[dict]:
    """Make an authenticated GET request to a registry."""
    headers = {"Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _oci_registry_inspect(image: str) -> Optional[dict]:
    """Fetch image config directly from OCI registry API (pure Python)."""
    try:
        registry, repository, tag = _parse_image_reference(image)
        token = _get_auth_token(registry, repository)

        base = f"https://{registry}/v2/{repository}"

        # Get manifest
        manifest_accept = ", ".join([
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
        ])
        manifest = _registry_get(f"{base}/manifests/{tag}", token, manifest_accept)
        if not manifest:
            return None

        # Handle manifest list / index (multi-arch)
        media_type = manifest.get("mediaType", "")
        if "manifest.list" in media_type or "image.index" in media_type:
            # Pick linux/amd64
            for m in manifest.get("manifests", []):
                platform = m.get("platform", {})
                if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
                    digest = m["digest"]
                    manifest = _registry_get(f"{base}/manifests/{digest}", token, manifest_accept)
                    break
            else:
                # Fallback to first manifest
                manifests = manifest.get("manifests", [])
                if manifests:
                    digest = manifests[0]["digest"]
                    manifest = _registry_get(f"{base}/manifests/{digest}", token, manifest_accept)

        if not manifest:
            return None

        # Get config blob
        config_desc = manifest.get("config", {})
        config_digest = config_desc.get("digest")
        if not config_digest:
            return None

        config = _registry_get(f"{base}/blobs/{config_digest}", token)
        return config

    except Exception as e:
        logger.debug(f"OCI registry inspect failed: {e}")
        return None


def _parse_config(config: dict, sec: ImageSecurity) -> None:
    """Parse image config into ImageSecurity fields."""
    # Docker inspect format
    container_config = config.get("Config", config.get("config", {}))

    # User
    user = container_config.get("User", "")
    sec.user = user
    sec.rootless = bool(user) and user not in ("0", "root")

    # Healthcheck
    healthcheck = container_config.get("Healthcheck", container_config.get("healthcheck"))
    sec.healthcheck = healthcheck is not None and bool(healthcheck)

    # Layers
    rootfs = config.get("RootFS", config.get("rootfs", {}))
    layers = rootfs.get("Layers", rootfs.get("diff_ids", []))
    sec.layers = len(layers)

    # FROM scratch detection: images built FROM scratch typically have very few layers
    # and no base image history entries
    history = config.get("History", config.get("history", []))
    if history:
        first_entry = history[0] if history else {}
        created_by = first_entry.get("created_by", "")
        if "scratch" in created_by.lower() or sec.layers <= 2:
            sec.from_scratch = True

    # Size
    sec.size_bytes = config.get("Size", config.get("size", 0))

    # Labels for base image info
    labels = container_config.get("Labels", {}) or {}
    sec.base_image = labels.get("org.opencontainers.image.base.name", "")

    # Read-only rootfs (from container runtime config if present)
    host_config = config.get("HostConfig", {})
    if host_config.get("ReadonlyRootfs"):
        sec.read_only_rootfs = True

    # SecurityOpt for no-new-privileges
    security_opt = host_config.get("SecurityOpt", []) or []
    if "no-new-privileges" in security_opt or "no-new-privileges:true" in security_opt:
        sec.no_new_privileges = True
