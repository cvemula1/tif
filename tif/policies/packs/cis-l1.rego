# TIF Policy Pack: CIS Docker Benchmark Level 1
# Based on CIS Docker Benchmark v1.6.0

package tif

default allow = false

allow {
    rootless_user
    healthcheck_present
    no_critical_cves
}

# CIS 4.1 — Ensure a user for the container has been created
rootless_user {
    input.security.user != ""
    input.security.user != "0"
    input.security.user != "root"
}

# CIS 4.6 — Ensure HEALTHCHECK instructions have been added
healthcheck_present {
    input.security.healthcheck == true
}

# CIS 4.4 — Ensure images are scanned for vulnerabilities
no_critical_cves {
    input.vulnerabilities.scanned == true
    input.vulnerabilities.critical == 0
}

no_critical_cves {
    input.vulnerabilities.scanned == false
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
