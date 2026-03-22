# TIF Default Trust Policy
# Minimum trust gates: signature verified + no critical CVEs

package tif

default allow = false

allow {
    signature_verified
    vulnerability_acceptable
}

signature_verified {
    input.signature.verified == true
}

vulnerability_acceptable {
    input.vulnerabilities.critical == 0
}

deny[msg] {
    not signature_verified
    msg := "Image signature not verified"
}

deny[msg] {
    not vulnerability_acceptable
    critical := input.vulnerabilities.critical
    msg := sprintf("Critical vulnerabilities found: %d", [critical])
}
