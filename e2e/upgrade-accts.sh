#!/usr/bin/env bash
# Root side of the two-account part of the upgrade case (F96, acceptance 10 of SPEC.md), run by upgrade.sh. Needs WORK and MODULE.
#   upgrade-accts.sh seed      before the install: bob (a fixed uid when the account is new; the old-path run has none) imports rsa1 (the id alice
#                              holds too) and bobonly with the old package, replaces the certificate of rsa1, and alice and bob list their keys
#   upgrade-accts.sh collect   after the upgrade: the same lists and certificates, each as its own user in a session of his or her own
#   upgrade-accts.sh sign      each account signs with each of its keys and with a denial, one agent request each
#   upgrade-accts.sh cleanup   bob deletes his keys (the lifecycle cases that follow start from the state alice's keys alone make)
#   upgrade-accts.sh uids      prints "ALICE_UID BOB_UID CUSTODIO_UID"
# The judgements are upgrade-accts-lib.sh's, called by upgrade.sh at the case each belongs to.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
# shellcheck source=e2e/upgrade-accts-lib.sh
source "$here/upgrade-accts-lib.sh"
ACC=$WORK/upgrade-acct
BOB_UID=4711 # used only when the account is created here (the main run has bob from the owner step; the old-path run does not)

run_user() { # USER ARGS...
    local u=$1
    shift
    timeout 300 su -l "$u" -c "WORK=$WORK MODULE=$MODULE bash /e2e/upgrade-accts-user.sh $*"
}

case ${1:-} in
seed)
    bash "$here/upgrade-accts-selftest.sh" || fail "the upgrade accounts self-test failed"
    id alice > /dev/null 2>&1 || fail "alice does not exist"
    id bob > /dev/null 2>&1 || useradd -m -u "$BOB_UID" -s /bin/bash bob
    bu=$(id -u bob)
    [ "$bu" != "$(id -u alice)" ] && [ "$bu" != "$(id -u custodio)" ] || fail "bob's uid is not his own ($bu)"
    root=$(readlink -f "$STATE_LINK")
    if [ -d "$root/$bu" ] && [ -n "$(ls -A "$root/$bu")" ]; then fail "bob (uid $bu) has keys from an earlier step: $(find "$root/$bu" -mindepth 1 -printf '%f ')"; fi
    rm -rf "$ACC"
    mkdir -p "$ACC/before" "$ACC/after" "$ACC/sign"
    chmod 1777 "$ACC" "$ACC/before" "$ACC/after" "$ACC/sign"
    head -c 2000 /dev/urandom > "$ACC/sign/data.bin" # more than 1024 bytes: pkcs11-tool does not retry a denied signature as a second one
    for id in rsa1 bobonly; do
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ACC/bob-$id.key" 2> /dev/null
        openssl req -new -x509 -key "$ACC/bob-$id.key" -subj "/CN=custodio e2e upgrade bob $id" -days 30 -out "$ACC/bob-$id.crt"
        openssl pkcs12 -export -inkey "$ACC/bob-$id.key" -in "$ACC/bob-$id.crt" -name "$id" -passout pass:e2e-password -out "$ACC/bob-$id.p12"
    done
    openssl x509 -in "$ACC/bob-rsa1.crt" -outform DER -out "$ACC/bob-old.der"
    # the replacement: a new certificate for the same key
    openssl req -new -x509 -key "$ACC/bob-rsa1.key" -subj "/CN=custodio e2e upgrade bob rsa1 replaced" -days 60 -outform DER -out "$ACC/bob-new.der"
    rm -f "$ACC"/*.key
    chmod 644 "$ACC"/*.p12 "$ACC"/*.crt "$ACC"/*.der "$ACC/sign/data.bin"
    run_user bob seed > "$ACC/bob-seed.out" 2>&1 || { cat "$ACC/bob-seed.out" >&2; fail "bob's seed session failed"; }
    for u in alice bob; do run_user "$u" collect before > "$ACC/$u-collect.out" 2>&1 || { cat "$ACC/$u-collect.out" >&2; fail "$u: listing before the upgrade failed"; }; done
    echo "e2e: upgrade: seeded: alice holds $ACCT_ALICE_IDS, bob (uid $bu) holds $ACCT_BOB_IDS, bob's rsa1 certificate replaced"
    ;;
collect)
    for u in alice bob; do run_user "$u" collect after > "$ACC/$u-collect.out" 2>&1 || { cat "$ACC/$u-collect.out" >&2; fail "$u: listing after the upgrade failed"; }; done
    ;;
sign)
    for u in alice bob; do run_user "$u" sign > "$ACC/$u-sign.out" 2>&1 || { cat "$ACC/$u-sign.out" >&2; fail "$u: signing after the upgrade failed"; }; done
    ;;
cleanup)
    run_user bob cleanup > "$ACC/bob-cleanup.out" 2>&1 || { cat "$ACC/bob-cleanup.out" >&2; fail "bob's cleanup failed"; }
    ;;
uids) echo "$(id -u alice) $(id -u bob) $(id -u custodio)" ;;
*) fail "usage: upgrade-accts.sh seed|collect|sign|cleanup|uids" ;;
esac
