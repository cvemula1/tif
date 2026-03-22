# TIF Policy Pack: DISA STIG / FedRAMP
# DoD Container Image Hardening Requirements

package tif

default allow = false

allow {
    signature_verified
    no_critical_or_high_cves
    sbom_present
    provenance_verified
    rootless_enforced
    from_scratch_required
    read_only_rootfs
}

# V-222399 — Image must be signed by trusted authority
signature_verified {
    input.signature.verified == true
}

# V-222400 — No critical or high vulnerabilities
no_critical_or_high_cves {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical == 0
    input.vulnerabilities.high == 0
}

# V-222401 — SBOM must be present
sbom_present {
    input.sbom.present == true
    input.sbom.packages > 0
}

# V-222402 — Build provenance must be verifiable
provenance_verified {
    input.attestation.present == true
    input.attestation.slsa_level >= 2
}

# V-222403 — Must run as non-root (UID 65532 recommended)
rootless_enforced {
    input.security.rootless == true
}

# V-222404 — Must use FROM scratch or approved base
from_scratch_required {
    input.security.from_scratch == true
}

# V-222405 — Read-only root filesystem
read_only_rootfs {
    input.security.read_only_rootfs == true
}

# Denial reasons
deny[msg] {
    not signature_verified
    msg := "STIG V-222399: Image signature not verified by trusted authority"
}

deny[msg] {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical > 0
    msg := sprintf("STIG V-222400: %d critical vulnerabilities (must be 0)", [input.vulnerabilities.critical])
}

deny[msg] {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.high > 0
    msg := sprintf("STIG V-222400: %d high vulnerabilities (must be 0)", [input.vulnerabilities.high])
}

deny[msg] {
    not sbom_present
    msg := "STIG V-222401: No SBOM attached to image"
}

deny[msg] {
    not provenance_verified
    msg := "STIG V-222402: Build provenance not verified (requires SLSA Level 2+)"
}

deny[msg] {
    not rootless_enforced
    msg := sprintf("STIG V-222403: Container runs as user '%s' (must be non-root)", [input.security.user])
}

deny[msg] {
    not from_scratch_required
    msg := "STIG V-222404: Image not built FROM scratch"
}

deny[msg] {
    not read_only_rootfs
    msg := "STIG V-222405: Root filesystem is not read-only"
}
