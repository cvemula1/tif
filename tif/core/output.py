# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Output formatters for Trust Card display

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tif.core.trust_card import TrustCard

# ── Verdict colors/icons ─────────────────────────────────────────────────

_VERDICT_STYLE = {
    "PASS": ("[PASS]", "green"),
    "FAIL": ("[FAIL]", "red"),
    "WARN": ("[WARN]", "yellow"),
    "UNKNOWN": ("[????]", "dim"),
}

_SEVERITY_ICON = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _is_ci() -> bool:
    """Detect CI environment."""
    import os
    return any(os.environ.get(v) for v in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"))


# ── Rich table output ────────────────────────────────────────────────────

def print_trust_card(card: "TrustCard", ascii_mode: bool = False) -> None:
    """Pretty-print a Trust Card to the terminal using Rich."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

    except ImportError:
        # Fallback to plain text
        print_trust_card_plain(card)
        return

    console = Console(force_terminal=not _is_ci())
    icon, color = _VERDICT_STYLE.get(card.verdict.value, ("[????]", "dim"))

    if ascii_mode:
        icon = card.verdict.value

    # Header
    header = f"{icon}  Trust Score: {card.trust_score}/100  —  {card.verdict.value}"
    console.print()
    console.print(Panel(
        f"[bold {color}]{header}[/]",
        title="[bold]TIF Trust Card[/]",
        subtitle=f"[dim]{card.image}[/]" if card.tag and card.image.endswith(f":{card.tag}") else (f"[dim]{card.image}:{card.tag}[/]" if card.tag else f"[dim]{card.image}[/]"),
        border_style=color,
    ))

    # Gates table
    if card.gates:
        table = Table(title="Trust Gates", show_header=True, header_style="bold")
        table.add_column("Gate", style="bold")
        table.add_column("Verdict", justify="center")
        table.add_column("Reason")

        for gate in card.gates:
            g_icon, g_color = _VERDICT_STYLE.get(gate.verdict.value, ("[????]", "dim"))
            if ascii_mode:
                g_icon = gate.verdict.value
            table.add_row(
                gate.name,
                f"[{g_color}]{g_icon} {gate.verdict.value}[/]",
                gate.reason,
            )
        console.print(table)

    # Summary sections
    _print_signature_summary(console, card, ascii_mode)
    _print_vuln_summary(console, card, ascii_mode)
    _print_sbom_summary(console, card, ascii_mode)
    _print_security_summary(console, card, ascii_mode)
    _print_eol_summary(console, card, ascii_mode)
    _print_failure_summary(console, card)

    console.print()


def _print_signature_summary(console, card: "TrustCard", ascii_mode: bool) -> None:
    sig = card.signature
    icon = "[PASS]" if sig.verified else "[FAIL]"
    if ascii_mode:
        icon = "PASS" if sig.verified else "FAIL"
    status = f"{icon} Verified" if sig.verified else f"{icon} Not verified"
    detail = f"  Signer: {sig.signer}" if sig.signer else ""
    console.print(f"  [bold]Signature:[/] {status}{detail}")


def _print_vuln_summary(console, card: "TrustCard", ascii_mode: bool) -> None:
    v = card.vulnerabilities
    if not v.scanned:
        console.print("  [bold]Vulnerabilities:[/] [dim]Not scanned[/]")
        return
    parts = []
    if v.critical:
        parts.append(f"[red]{v.critical} critical[/]")
    if v.high:
        parts.append(f"[bright_red]{v.high} high[/]")
    if v.medium:
        parts.append(f"[yellow]{v.medium} medium[/]")
    if v.low:
        parts.append(f"[blue]{v.low} low[/]")
    summary = ", ".join(parts) if parts else "[green]0 vulnerabilities[/]"
    console.print(f"  [bold]Vulnerabilities:[/] {summary} ({v.scanner})")

    # Show noise reduction info when --only-fixable was used
    if v.total_suppressed > 0:
        console.print(
            f"    [dim]↳ {v.total_suppressed} additional CVE(s) suppressed "
            f"(no fix available — use without --only-fixable to see all)[/]"
        )

    # Show top 5 actionable (fixable) CVEs
    if v.findings:
        actionable = [c for c in v.findings if c.has_fix][:5]
        if actionable:
            console.print("  [bold]Top fixable CVEs:[/]")
            for cve in actionable:
                sev_color = "red" if cve.severity == "CRITICAL" else "bright_red"
                console.print(
                    f"    [{sev_color}]{cve.id}[/] "
                    f"[dim]{cve.package}@{cve.installed_version}[/] "
                    f"→ [green]{cve.fixed_version}[/] "
                    f"[dim](CVSS {cve.cvss_score:.1f})[/]"
                )


def _print_sbom_summary(console, card: "TrustCard", ascii_mode: bool) -> None:
    s = card.sbom
    if not s.present:
        console.print("  [bold]SBOM:[/] [dim]Not found[/]")
        return
    console.print(
        f"  [bold]SBOM:[/] {s.format} — {s.packages} packages, "
        f"completeness {s.completeness_score:.0%}"
    )


def _print_security_summary(console, card: "TrustCard", ascii_mode: bool) -> None:
    sec = card.security
    flags = []
    if sec.rootless:
        flags.append("[green]rootless[/]")
    if sec.from_scratch:
        flags.append("[green]FROM scratch[/]")
    if sec.read_only_rootfs:
        flags.append("[green]read-only rootfs[/]")
    if sec.no_new_privileges:
        flags.append("[green]no-new-privileges[/]")
    if not flags:
        flags.append("[dim]none detected[/]")
    console.print(f"  [bold]Security:[/] {', '.join(flags)}")


def _print_failure_summary(console, card: "TrustCard") -> None:
    """Print a clear summary of why the verdict failed or warned."""
    from tif.core.trust_card import Verdict

    failed = [g for g in card.gates if g.verdict == Verdict.FAIL]
    warned = [g for g in card.gates if g.verdict == Verdict.WARN]

    if failed:
        console.print()
        console.print("  [bold red]FAILED gates:[/]")
        for g in failed:
            console.print(f"    [red]x[/] [bold]{g.name}:[/] {g.reason}")

    if warned:
        console.print()
        console.print("  [bold yellow]WARNINGS:[/]")
        for g in warned:
            console.print(f"    [yellow]![/] [bold]{g.name}:[/] {g.reason}")

    # Compliance findings
    if card.compliance:
        for c in card.compliance:
            if not c.passed and c.findings:
                console.print()
                console.print(f"  [bold red]Policy violations ({c.framework}):[/]")
                for f in c.findings:
                    console.print(f"    [red]x[/] {f}")

    # Actionable next steps
    if failed or warned:
        console.print()
        console.print("  [bold]Next steps:[/]")
        for g in failed:
            name = g.name.lower()
            if "signature" in name:
                console.print("    - Sign the image: cosign sign <image>")
            elif "vulnerabilit" in name:
                console.print("    - Fix CVEs: grype <image> --only-fixed")
                console.print("    - Reduce noise: tif verify <image> --only-fixable")
            elif "sbom" in name:
                console.print("    - Attach SBOM: syft <image> -o spdx-json | cosign attach sbom --sbom /dev/stdin <image>")
            elif "attestation" in name:
                console.print("    - Add provenance: use slsa-github-generator in CI")
            elif "end-of-life" in name or "eol" in name:
                console.print("    - Upgrade base image to a supported version")
            elif "image security" in name:
                console.print("    - Add USER, HEALTHCHECK, and --read-only to your Dockerfile")
            elif "policy" in name:
                console.print("    - Review policy findings above and remediate")
        for g in warned:
            name = g.name.lower()
            if "not installed" in g.reason.lower():
                if "cosign" in g.reason.lower():
                    console.print("    - Install cosign: brew install cosign")
                elif "grype" in g.reason.lower():
                    console.print("    - Install grype: brew install grype")
            elif "eol" in name or "end-of-life" in name:
                if "days" in g.reason.lower():
                    console.print("    - Plan base image upgrade before EOL")


def _print_eol_summary(console, card: "TrustCard", ascii_mode: bool) -> None:
    eol = card.eol
    if not eol.product:
        console.print("  [bold]EOL:[/] [dim]Not checked[/]")
        return
    if eol.eol:
        console.print(
            f"  [bold]EOL:[/] [red]{eol.product} {eol.cycle} "
            f"reached EOL on {eol.eol_date}[/]"
        )
    elif eol.support_ended:
        console.print(
            f"  [bold]EOL:[/] [yellow]{eol.product} {eol.cycle} "
            f"active support ended (security-only until {eol.eol_date})[/]"
        )
    elif eol.days_until_eol >= 0 and eol.days_until_eol <= 90:
        console.print(
            f"  [bold]EOL:[/] [yellow]{eol.product} {eol.cycle} "
            f"EOL in {eol.days_until_eol} days ({eol.eol_date})[/]"
        )
    else:
        detail = f" (EOL: {eol.eol_date})" if eol.eol_date else ""
        lts = " [green]LTS[/]" if eol.lts else ""
        console.print(
            f"  [bold]EOL:[/] [green]{eol.product} {eol.cycle} supported[/]"
            f"{detail}{lts}"
        )


# ── Plain text fallback ──────────────────────────────────────────────────

def print_trust_card_plain(card: "TrustCard") -> None:
    """Plain text output when Rich is not available."""
    print()
    print("═══ TIF Trust Card ═══")
    print(f"Image:       {card.image}:{card.tag}" if card.tag else f"Image: {card.image}")
    print(f"Verdict:     {card.verdict.value}")
    print(f"Trust Score: {card.trust_score}/100")
    print()
    if card.gates:
        print("Trust Gates:")
        for g in card.gates:
            print(f"  [{g.verdict.value:>7}] {g.name}: {g.reason}")
    print()


# ── JSON output ──────────────────────────────────────────────────────────

def print_trust_card_json(card: "TrustCard") -> None:
    """Output Trust Card as JSON."""
    print(card.to_json())
