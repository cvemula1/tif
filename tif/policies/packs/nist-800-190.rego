# TIF Policy Pack: NIST SP 800-190
# Application Container Security Guide

package tif

default allow = false

allow {
    image_vulnerabilities_acceptable
    image_provenance_verified
    software_composition_known
    least_privilege_runtime
}

# NIST 4.1.1 — Image vulnerabilities
image_vulnerabilities_acceptable {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical == 0
    input.vulnerabilities.high <= 5
}

image_vulnerabilities_acceptable {
    input.vulnerabilities.scanned == false
}

# NIST 4.1.3 — Image provenance
image_provenance_verified {
    input.signature.verified == true
}

# NIST 4.1.4 — Trusted base images / known composition
software_composition_known {
    input.sbom.present == true
    input.sbom.packages > 0
}

# NIST 4.2.1 — Least-privilege container runtime
least_privilege_runtime {
    input.security.rootless == true
}

# Denial reasons
deny[msg] {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical > 0
    msg := sprintf("NIST 4.1.1: %d critical vulnerabilities present", [input.vulnerabilities.critical])
}

deny[msg] {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.high > 5
    msg := sprintf("NIST 4.1.1: %d high vulnerabilities exceed threshold (max 5)", [input.vulnerabilities.high])
}

deny[msg] {
    not image_provenance_verified
    msg := "NIST 4.1.3: Image provenance not verified via signature"
}

deny[msg] {
    not software_composition_known
    msg := "NIST 4.1.4: No SBOM — cannot verify software composition"
}

deny[msg] {
    not least_privilege_runtime
    msg := "NIST 4.2.1: Container does not run as non-root user"
}
