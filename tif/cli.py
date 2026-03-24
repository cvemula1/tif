# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# TIF CLI — The Trust Gate for Container Images

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    """TIF CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="tif",
        description="TIF — The Trust Gate for Container Images. "
        "Verify signatures, SBOMs, attestations, vulnerabilities, and compliance in one command.",
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version and exit"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── verify ───────────────────────────────────────────────────────
    verify_parser = subparsers.add_parser(
        "verify",
        help="Run all trust gates on a container image",
        description="Verify a container image against all trust gates and produce a Trust Card.",
    )
    verify_parser.add_argument("image", help="Container image reference (e.g. registry.io/app:1.0)")
    verify_parser.add_argument("--key", help="Path to cosign public key (default: keyless)")
    verify_parser.add_argument(
        "--scanner", choices=["trivy", "grype"], default="trivy",
        help="Vulnerability scanner (default: trivy)",
    )
    verify_parser.add_argument(
        "--policy", help="Path to custom .rego policy file",
    )
    verify_parser.add_argument(
        "--policy-pack", default="default",
        help="Built-in policy pack: default, cis-l1, cis-l2, nist-800-190, dod-stig",
    )
    verify_parser.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low"],
        default="critical",
        help="Fail if any vulnerability at this severity or higher (default: critical)",
    )
    verify_parser.add_argument("--max-high", type=int, default=10, help="Max high CVEs (default: 10)")
    verify_parser.add_argument(
        "--only-fixable", action="store_true",
        help="Only count CVEs that have a fix available (reduces alert fatigue)",
    )
    verify_parser.add_argument("--require-sbom", action="store_true", help="Fail if no SBOM found")
    verify_parser.add_argument("--require-provenance", action="store_true", help="Fail if no SLSA provenance")
    verify_parser.add_argument("--min-slsa-level", type=int, default=0, help="Minimum SLSA level (0-4)")
    verify_parser.add_argument(
        "--skip", nargs="+",
        choices=["signature", "vulnerabilities", "sbom", "attestation", "image", "eol", "policy"],
        default=[],
        help="Skip specific gates",
    )
    verify_parser.add_argument(
        "-f", "--format", choices=["table", "json", "card"], default="table",
        help="Output format (default: table)",
    )
    verify_parser.add_argument("-o", "--output", help="Write Trust Card JSON to file")
    verify_parser.add_argument("--ascii", action="store_true", help="ASCII-safe output (no emoji)")
    verify_parser.add_argument("--ci", action="store_true", help="CI mode: exit code 1 on FAIL verdict")

    # ── inspect ──────────────────────────────────────────────────────
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Show Trust Card for a container image (read-only, no gating)",
    )
    inspect_parser.add_argument("image", help="Container image reference")
    inspect_parser.add_argument("--key", help="Cosign public key path")
    inspect_parser.add_argument("--scanner", choices=["trivy", "grype"], default="trivy")
    inspect_parser.add_argument("-f", "--format", choices=["table", "json", "card"], default="table")
    inspect_parser.add_argument("--ascii", action="store_true")

    # ── policy ───────────────────────────────────────────────────────
    policy_parser = subparsers.add_parser(
        "policy",
        help="Manage and evaluate trust policies",
    )
    policy_sub = policy_parser.add_subparsers(dest="policy_command")

    policy_sub.add_parser("list", help="List available policy packs")

    policy_check_parser = policy_sub.add_parser(
        "check", help="Evaluate a Trust Card JSON against a policy",
    )
    policy_check_parser.add_argument("card_file", help="Path to Trust Card JSON file")
    policy_check_parser.add_argument("--policy", help="Custom .rego policy file")
    policy_check_parser.add_argument("--policy-pack", default="default", help="Built-in policy pack")
    policy_check_parser.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # ── demo ─────────────────────────────────────────────────────────
    demo_parser = subparsers.add_parser(
        "demo",
        help="Show a sample Trust Card (no external tools required)",
    )
    demo_parser.add_argument("-f", "--format", choices=["table", "json", "card"], default="table")
    demo_parser.add_argument("--ascii", action="store_true")

    # ── scan-dockerfile ──────────────────────────────────────────────
    df_parser = subparsers.add_parser(
        "scan-dockerfile",
        help="Analyze a Dockerfile for security issues",
    )
    df_parser.add_argument("dockerfile", help="Path to Dockerfile")
    df_parser.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # ── harden ───────────────────────────────────────────────────────
    harden_parser = subparsers.add_parser(
        "harden",
        help="Generate a hardened version of a Dockerfile",
    )
    harden_parser.add_argument("dockerfile", help="Path to source Dockerfile")
    harden_parser.add_argument("-o", "--output", help="Write hardened Dockerfile to file (default: stdout)")
    harden_parser.add_argument("--user", default="65532", help="Non-root user ID (default: 65532)")

    # ── push ─────────────────────────────────────────────────────────
    push_parser = subparsers.add_parser(
        "push",
        help="Enrich image with Trust Card labels and push to registry",
    )
    push_parser.add_argument("image", help="Source image reference (already verified)")
    push_parser.add_argument("card_file", help="Path to Trust Card JSON file")
    push_parser.add_argument(
        "--to", metavar="DESTINATION",
        help="Push enriched image to this registry path (default: same as source)",
    )
    push_parser.add_argument("--key", help="Cosign private key for signing (default: keyless)")
    push_parser.add_argument(
        "--no-labels", action="store_true",
        help="Skip OCI label injection, attach attestation only",
    )

    # ── version ──────────────────────────────────────────────────────
    subparsers.add_parser("version", help="Show version")

    # ── Parse ────────────────────────────────────────────────────────
    args = parser.parse_args(argv)

    if args.version or args.command == "version":
        from tif import __version__
        print(f"tif {__version__}")
        return 0

    # Logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    if args.command is None:
        parser.print_help()
        return 0

    # ── Dispatch ─────────────────────────────────────────────────────
    if args.command == "verify":
        return _cmd_verify(args)
    elif args.command == "inspect":
        return _cmd_inspect(args)
    elif args.command == "policy":
        return _cmd_policy(args)
    elif args.command == "demo":
        return _cmd_demo(args)
    elif args.command == "scan-dockerfile":
        return _cmd_scan_dockerfile(args)
    elif args.command == "harden":
        return _cmd_harden(args)
    elif args.command == "push":
        return _cmd_push(args)
    else:
        parser.print_help()
        return 0


# ── Command implementations ─────────────────────────────────────────────

def _cmd_verify(args: argparse.Namespace) -> int:
    """Run all trust gates and produce a Trust Card."""
    from tif.core.verifier import verify_image
    from tif.core.output import print_trust_card, print_trust_card_json

    fail_on_critical = args.fail_on in ("critical",)
    max_high = args.max_high

    # Adjust thresholds based on --fail-on
    if args.fail_on == "high":
        max_high = 0
    elif args.fail_on == "medium":
        max_high = 0
        fail_on_critical = True

    card = verify_image(
        image=args.image,
        check_signature="signature" not in args.skip,
        check_vulnerabilities="vulnerabilities" not in args.skip,
        check_sbom="sbom" not in args.skip,
        check_attestation="attestation" not in args.skip,
        check_image="image" not in args.skip,
        check_eol="eol" not in args.skip,
        check_policy="policy" not in args.skip,
        cosign_key=args.key,
        scanner=args.scanner,
        fail_on_critical=fail_on_critical,
        max_high=max_high,
        only_fixable=args.only_fixable,
        require_sbom=args.require_sbom,
        require_provenance=args.require_provenance,
        min_slsa_level=args.min_slsa_level,
        policy_path=args.policy,
        policy_pack=args.policy_pack,
    )

    # Output
    if args.format == "json" or args.format == "card":
        print_trust_card_json(card)
    else:
        print_trust_card(card, ascii_mode=args.ascii)

    # Write to file
    if args.output:
        with open(args.output, "w") as f:
            f.write(card.to_json())
        logging.info("Trust Card written to %s", args.output)

    # CI exit code
    if args.ci and card.verdict.value == "FAIL":
        return 1
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    """Retrieve stored Trust Card attestation pushed by `tif push`.
    Falls back to live verification if no stored Trust Card is found."""
    from tif.core.output import print_trust_card, print_trust_card_json
    from tif.core.trust_card import TrustCard
    from tif.publishers.registry import pull_trust_card

    # Try to retrieve the stored Trust Card attestation first
    card_data = pull_trust_card(args.image)
    if card_data:
        try:
            card = TrustCard.from_dict(card_data)
            if args.format == "json" or args.format == "card":
                print_trust_card_json(card)
            else:
                print_trust_card(card, ascii_mode=args.ascii)
            return 0
        except Exception:
            pass  # fall through to live verification

    # Fallback: live verification (no stored Trust Card found)
    import logging
    logging.getLogger(__name__).info(
        "No stored Trust Card found for %s — running live verification", args.image
    )
    from tif.core.verifier import verify_image
    card = verify_image(
        image=args.image,
        cosign_key=args.key,
        scanner=args.scanner,
    )

    if args.format == "json" or args.format == "card":
        print_trust_card_json(card)
    else:
        print_trust_card(card, ascii_mode=args.ascii)

    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    """Policy subcommands."""
    if args.policy_command == "list":
        from tif.policies.engine import list_policy_packs
        packs = list_policy_packs()
        print("Available policy packs:")
        for p in packs:
            print(f"  - {p}")
        return 0

    elif args.policy_command == "check":
        from tif.core.trust_card import TrustCard
        from tif.policies.engine import evaluate_policy

        with open(args.card_file) as f:
            card = TrustCard.from_json(f.read())

        compliance, gate = evaluate_policy(
            card,
            policy_path=args.policy,
            policy_pack=args.policy_pack,
        )

        if args.format == "json":
            result = {
                "gate": {"name": gate.name, "verdict": gate.verdict.value, "reason": gate.reason},
                "compliance": [
                    {
                        "framework": c.framework,
                        "passed": c.passed,
                        "checks_total": c.checks_total,
                        "checks_passed": c.checks_passed,
                        "findings": c.findings,
                    }
                    for c in compliance
                ],
            }
            print(json.dumps(result, indent=2))
        else:
            icon = "[PASS]" if gate.verdict.value == "PASS" else "[FAIL]"
            print(f"\n{icon}  {gate.verdict.value}: {gate.reason}\n")
            for c in compliance:
                status = "[PASS]" if c.passed else "[FAIL]"
                print(f"  {status} {c.framework}: {c.checks_passed}/{c.checks_total} passed")
                for finding in c.findings:
                    print(f"       ↳ {finding}")
            print()

        return 1 if gate.verdict.value == "FAIL" else 0

    else:
        print("Usage: tif policy {list,check}")
        return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    """Show a demo Trust Card with sample data."""
    from tif.core.verifier import build_demo_card
    from tif.core.output import print_trust_card, print_trust_card_json

    card = build_demo_card()

    if args.format == "json" or args.format == "card":
        print_trust_card_json(card)
    else:
        print_trust_card(card, ascii_mode=args.ascii)

    return 0


def _cmd_scan_dockerfile(args: argparse.Namespace) -> int:
    """Analyze a Dockerfile for security issues."""
    from tif.validators.dockerfile import analyze_dockerfile

    findings, gate = analyze_dockerfile(args.dockerfile)

    if args.format == "json":
        result = {
            "gate": {"name": gate.name, "verdict": gate.verdict.value, "reason": gate.reason},
            "findings": [
                {
                    "line": f.line,
                    "rule": f.rule,
                    "severity": f.severity,
                    "message": f.message,
                    "fix": f.fix,
                }
                for f in findings
            ],
        }
        print(json.dumps(result, indent=2))
    else:
        icon = "[PASS]" if gate.verdict.value == "PASS" else "[FAIL]"
        if gate.verdict.value == "WARN":
            icon = "[WARN]"
        print(f"\n{icon}  {gate.verdict.value}: {gate.reason}\n")
        for f in findings:
            sev = f.severity.upper()
            loc = f"line {f.line}" if f.line > 0 else "global"
            print(f"  [{sev:>8}] {f.rule} ({loc}): {f.message}")
            if f.fix:
                print(f"             Fix: {f.fix}")
        if not findings:
            print("  No issues found.")
        print()

    return 1 if gate.verdict.value == "FAIL" else 0


def _cmd_harden(args: argparse.Namespace) -> int:
    """Generate a hardened Dockerfile."""
    from tif.generators.harden import harden_dockerfile

    try:
        result = harden_dockerfile(
            dockerfile_path=args.dockerfile,
            output_path=args.output,
            user=args.user,
        )
        if not args.output:
            print(result)
        else:
            print(f"Hardened Dockerfile written to {args.output}")
        return 0
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _cmd_push(args: argparse.Namespace) -> int:
    """Enrich image with Trust Card labels and push to registry."""
    from tif.publishers.registry import push_enriched, push_trust_card

    destination = args.to or args.image

    if getattr(args, "no_labels", False):
        # Attestation-only mode (original behaviour)
        success = push_trust_card(
            image=destination,
            trust_card_path=args.card_file,
            cosign_key=args.key,
        )
        if success:
            print(f"Trust Card attestation pushed to {destination}")
            return 0
        print("Failed to push Trust Card. Run with -v for details.", file=sys.stderr)
        return 1

    success = push_enriched(
        image=args.image,
        trust_card_path=args.card_file,
        destination=destination,
        cosign_key=args.key,
    )
    if success:
        print(f"Image enriched with Trust Card labels and pushed to {destination}")
        print("Verify with: docker inspect " + destination + " --format '{{json .Config.Labels}}'")
        return 0
    print("Failed to push enriched image. Run with -v for details.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
