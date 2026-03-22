# TIF Policy Pack: CIS Docker Benchmark Level 2
# Includes all Level 1 controls plus additional hardening

package tif

default allow = false

allow {
    rootless_user
    healthcheck_present
    no_critical_cves
    signature_verified
    read_only_rootfs
    no_new_privileges
}

# CIS 4.1 — Non-root user
rootless_user {
    input.security.user != ""
    input.security.user != "0"
    input.security.user != "root"
}

# CIS 4.6 — HEALTHCHECK present
healthcheck_present {
    input.security.healthcheck == true
}

# CIS 4.4 — No critical CVEs
no_critical_cves {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical == 0
}

no_critical_cves {
    input.vulnerabilities.scanned == false
}

# CIS 4.5 — Image signed and verified
signature_verified {
    input.signature.verified == true
}

# CIS 5.12 — Read-only root filesystem
read_only_rootfs {
    input.security.read_only_rootfs == true
}

# CIS 5.25 — No new privileges
no_new_privileges {
    input.security.no_new_privileges == true
}

# Denial reasons
deny[msg] {
    not rootless_user
    msg := sprintf("CIS 4.1: Container runs as user '%s' (must be non-root)", [input.security.user])
}

deny[msg] {
    not healthcheck_present
    msg := "CIS 4.6: No HEALTHCHECK instruction found"
}

deny[msg] {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical > 0
    msg := sprintf("CIS 4.4: %d critical vulnerabilities found", [input.vulnerabilities.critical])
}

deny[msg] {
    not signature_verified
    msg := "CIS 4.5: Image signature not verified"
}

deny[msg] {
    not read_only_rootfs
    msg := "CIS 5.12: Root filesystem is not read-only"
}

deny[msg] {
    not no_new_privileges
    msg := "CIS 5.25: no-new-privileges flag not set"
}
