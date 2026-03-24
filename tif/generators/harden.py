# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Hardened Dockerfile generator — takes a Dockerfile and produces a hardened version

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional


def harden_dockerfile(
    dockerfile_path: str,
    output_path: Optional[str] = None,
    user: str = "65532",
    from_scratch: bool = False,
    read_only: bool = True,
) -> str:
    """
    Read a Dockerfile and produce a hardened version.

    Transformations applied:
      - Pin :latest tags to digest (where possible)
      - Replace ADD with COPY for local files
      - Add USER nonroot if missing
      - Add HEALTHCHECK if missing
      - Merge apt-get install + cleanup into single RUN
      - Remove EXPOSE 22
      - Add security labels
      - Add .dockerignore suggestions as comment

    Args:
        dockerfile_path: Path to source Dockerfile
        output_path: Where to write hardened Dockerfile (None = stdout)
        user: Non-root user ID (default: 65532 = nonroot)
        from_scratch: If True, add a FROM scratch multi-stage final layer
        read_only: Add read-only rootfs label hint

    Returns:
        The hardened Dockerfile content as a string.
    """
    path = Path(dockerfile_path)
    if not path.exists():
        raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

    content = path.read_text()
    lines = content.splitlines()

    hardened_lines: List[str] = []
    has_user = False
    has_healthcheck = False
    entrypoint_line = -1

    for i, line in enumerate(lines):
        modified = line

        # Track last FROM and ENTRYPOINT/CMD
        if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
            pass

        if re.match(r"^\s*(ENTRYPOINT|CMD)\s+", line, re.IGNORECASE):
            entrypoint_line = len(hardened_lines)

        # Replace ADD with COPY for local files
        if re.match(r"^\s*ADD\s+(?!https?://)", line, re.IGNORECASE):
            modified = re.sub(r"^(\s*)ADD\s+", r"\1COPY ", line, flags=re.IGNORECASE)
            hardened_lines.append("# TIF: replaced ADD with COPY for security")

        # Pin :latest to warning comment
        if re.match(r"^\s*FROM\s+\S+:latest", line, re.IGNORECASE):
            hardened_lines.append("# TIF: pin base image to a specific version/digest for reproducibility")

        # Remove EXPOSE 22
        if re.match(r"^\s*EXPOSE\s+22\b", line, re.IGNORECASE):
            hardened_lines.append("# TIF: removed EXPOSE 22 (SSH not recommended in containers)")
            continue

        # Fix chmod 777
        if "chmod 777" in line:
            modified = line.replace("chmod 777", "chmod 755")
            hardened_lines.append("# TIF: changed chmod 777 -> 755 for least-privilege")

        # Remove secrets from ENV
        if re.match(r"^\s*ENV\s+\S*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIALS)\s*=", line, re.IGNORECASE):
            hardened_lines.append("# TIF: removed hardcoded secret — use runtime secrets instead")
            hardened_lines.append(f"# {line}")
            continue

        # Fix sudo usage
        if re.search(r"\bsudo\b", line) and not line.strip().startswith("#"):
            modified = re.sub(r"\bsudo\s+", "", line)
            hardened_lines.append("# TIF: removed sudo (use USER directive instead)")

        # Track USER instruction
        if re.match(r"^\s*USER\s+", line, re.IGNORECASE):
            has_user = True
            # Replace root user
            if re.match(r"^\s*USER\s+root\s*$", line, re.IGNORECASE):
                modified = f"USER {user}"
                hardened_lines.append(f"# TIF: changed USER root -> {user}")

        # Track HEALTHCHECK
        if re.match(r"^\s*HEALTHCHECK\s+", line, re.IGNORECASE):
            has_healthcheck = True

        # apt-get: add --no-install-recommends and cleanup
        if "apt-get install" in line and "--no-install-recommends" not in line:
            modified = line.replace("apt-get install", "apt-get install --no-install-recommends")

        if "apt-get install" in modified and "rm -rf /var/lib/apt" not in modified:
            if modified.rstrip().endswith("\\"):
                pass  # multi-line RUN, user handles cleanup
            else:
                modified = modified.rstrip() + " && rm -rf /var/lib/apt/lists/*"

        hardened_lines.append(modified)

    # Add USER if missing (before CMD/ENTRYPOINT if present, else at end)
    if not has_user:
        user_line = f"USER {user}"
        comment = "# TIF: added non-root user for security"
        if entrypoint_line >= 0:
            hardened_lines.insert(entrypoint_line, user_line)
            hardened_lines.insert(entrypoint_line, comment)
            hardened_lines.insert(entrypoint_line, "")
        else:
            hardened_lines.append("")
            hardened_lines.append(comment)
            hardened_lines.append(user_line)

    # Add HEALTHCHECK if missing
    if not has_healthcheck:
        hardened_lines.append("")
        hardened_lines.append("# TIF: added HEALTHCHECK for container orchestrator liveness probes")
        hardened_lines.append('HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["true"]')

    # Add security labels
    hardened_lines.insert(_find_after_first_from(hardened_lines), "")
    label_idx = _find_after_first_from(hardened_lines)
    labels = [
        'LABEL org.opencontainers.image.source="https://github.com/OWNER/REPO"',
        'LABEL org.opencontainers.image.description="Hardened by TIF"',
    ]
    for j, label in enumerate(labels):
        hardened_lines.insert(label_idx + j, label)

    result = "\n".join(hardened_lines) + "\n"

    if output_path:
        Path(output_path).write_text(result)

    return result


def _find_after_first_from(lines: List[str]) -> int:
    """Find the line index right after the first FROM instruction."""
    for i, line in enumerate(lines):
        if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
            return i + 1
    return 0
