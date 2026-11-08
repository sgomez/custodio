#!/usr/bin/env bash
# The payload check of scripts/test-e2e-vm-host.sh (sourced by it, which defines tmp and R): the files of a VM run travel as one tar on the VM's payload drive.
# shellcheck disable=SC2154,SC2015 # tmp and R come from the sourcing script; A && B || C is the check
ck_payload() { # ck_payload NAME: prints the problem and fails
    local n=$1 pl=$tmp/$1/log.payload t m
    ! grep -q '^vm put' "$tmp/$n/log" || { echo "a vm put call: $(grep '^vm put' "$tmp/$n/log" | head -n 1)"; return 1; }
    [ -s "$pl" ] || { echo "vm start got no VM_PAYLOAD"; return 1; }
    [ $(( $(stat -c %s "$pl") % 512 )) = 0 ] || { echo "the payload is not a whole number of sectors"; return 1; }
    t=$(tar -tf "$pl") || { echo "the payload is not a tar"; return 1; }
    for m in pkg/custodio_1.2.3_amd64.deb pkg-next/custodio_1.2.4_amd64.deb e2e/guest.sh e2e/vm/cases.list e2e-target/install.sh e2e-target/cases.list \
        e2e-docs/audit.md e2e-noplain/scripts/check-no-plaintext.sh e2e-noplain/scripts/check_no_plaintext.py e2e-src/app_id_source.rs; do
        grep -qx -- "$m" <<< "$t" || { echo "the payload lacks $m"; return 1; }
    done
    ! grep -q __pycache__ <<< "$t" || { echo "the payload holds __pycache__"; return 1; }
    ! grep -q '^/' <<< "$t" || { echo "the payload holds an absolute path"; return 1; }
    mkdir "$tmp/$n/x" && tar -C "$tmp/$n/x" -xf "$pl" || return 1
    cmp -s "$tmp/pk/custodio_1.2.3_amd64.deb" "$tmp/$n/x/pkg/custodio_1.2.3_amd64.deb" && cmp -s "$tmp/pkn/custodio_1.2.4_amd64.deb" "$tmp/$n/x/pkg-next/custodio_1.2.4_amd64.deb" \
        || { echo "a package in the payload differs from the file"; return 1; }
    cmp -s "$R/e2e/vm/cases.list" "$tmp/$n/x/e2e-target/cases.list" || { echo "e2e-target/cases.list is not the VM list"; return 1; }
}
