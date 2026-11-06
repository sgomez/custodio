#!/usr/bin/env bash
# The upgrade from an M3 build (F142, acceptance 9 of SPEC.md), run as root by guest.sh in the m3 run, on a fresh container with the M3 package installed and its service
# running. Four keys are imported with the M3 build's own CLI (alice: rsa1, ec1; bob: rsa1, bobonly), the state directory is recorded, package N (this tree's) is installed over it with
# the target's own install.sh and nothing else, and the result is judged by e2e/upgradem3.py: the old files are gone, nothing is listed, the journal has one purge entry per key and
# the same ids import again. Usage: upgrade-m3.sh PKG_M3 PKG_N (needs WORK; E2E_INSTALL overrides the install step, the tests of this script use it).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/upgrade-lib.sh
source "$here/upgrade-lib.sh"
: "${WORK:?}"
[ $# -eq 2 ] || fail "usage: upgrade-m3.sh PKG_M3 PKG_N"
old=$1
new=$2
install=${E2E_INSTALL:-/e2e-target/install.sh}
[ -f "$old" ] && [ -f "$new" ] && [ "$old" != "$new" ] || fail "the M3 and the new package must be two package files"
fmt=$(pkg_format "$new")
[ "$(pkg_format "$old")" = "$fmt" ] || fail "the M3 and the new package are not in the same format"
um3() { python3 -I "$here/upgradem3.py" "$@"; }
# judged CASE ARGS...: the judgement of upgradem3.py prints one problem per line and nothing when the evidence is right; a judgement that crashes stops the run, and a case is
# reported only after the evidence is right
judged() {
    local c=$1 p
    shift
    p=$(um3 "$@") || fail "$c: the judgement did not run"
    [ -z "$p" ] || { printf '%s\n' "$p" >&2; fail "$c: the evidence is wrong (see above)"; }
    case_run "$c"
}
manual_step_problems "$here/upgrade-m3.sh" || fail "the M3 upgrade runs a manual step (see above)"

ACC=$WORK/upgrade-m3
user_run() { # USER ARGS...
    local u=$1
    shift
    timeout 300 su -l "$u" -c "WORK=$WORK bash /e2e/upgrade-m3-user.sh $*"
}
files_snapshot() { # "PATH<TAB>SHA256" per regular file of the state directory
    snapshot_state "$STATE_LINK" | awk '$1 == "f" { p = $6; sub(/^\.\//, "", p); print p "\t" $5 }'
}
collect() { # DIR: both accounts list their keys
    mkdir -p "$ACC/$1"
    chmod 1777 "$ACC/$1"
    for u in alice bob; do user_run "$u" collect "$ACC/$1" > "$ACC/$1/$u.out" 2>&1 || { cat "$ACC/$1/$u.out" >&2; fail "$u: the listing ($1) failed"; }; done
}

# The accounts and the four keys (a p12 each; the seed's keys are the ones imported again afterwards).
id alice > /dev/null 2>&1 || fail "alice does not exist"
id bob > /dev/null 2>&1 || useradd -m -u 4711 -s /bin/bash bob
ua=$(id -u alice)
ub=$(id -u bob)
[ "$ua" != "$ub" ] && [ "$ub" != "$(id -u custodio)" ] || fail "bob's uid is not his own ($ub)"
rm -rf "$ACC"
mkdir -p "$ACC"
chmod 1777 "$ACC"
for k in alice-rsa1 alice-ec1 bob-rsa1 bob-bobonly; do
    case $k in
    *ec1) genopt=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256) ;;
    *) genopt=(-algorithm RSA -pkeyopt rsa_keygen_bits:2048) ;;
    esac
    openssl genpkey "${genopt[@]}" -out "$ACC/$k.key" 2> /dev/null
    openssl req -new -x509 -key "$ACC/$k.key" -subj "/CN=custodio e2e upgrade-m3 $k" -days 30 -out "$ACC/$k.crt"
    openssl pkcs12 -export -inkey "$ACC/$k.key" -in "$ACC/$k.crt" -name "${k#*-}" -passout pass:e2e-password -out "$ACC/$k.p12"
done
rm -f "$ACC"/*.key
chmod 644 "$ACC"/*

# BEGIN upgrade-case
vm=$(pkg_file_version "$fmt" "$old")
vn=$(pkg_file_version "$fmt" "$new")
# The new package must be strictly greater than the M3 one by the target's own tool, before anything is installed.
upgrade_gate "$fmt" "$old" "$new" || fail "the upgrade gate refused the pair (see above); nothing was installed"
systemctl is-active --quiet custodio || fail "custodio.service was not running before the upgrade"
[ "$(installed_version "$fmt")" = "$vm" ] || fail "before the upgrade the database holds $(installed_version "$fmt"), not the M3 build $vm"
pid1=$(systemctl show -p MainPID --value custodio)
[ "$pid1" -gt 0 ] || fail "custodio.service has no main pid before the upgrade"
user_run alice seed > "$ACC/alice-seed.out" 2>&1 || { cat "$ACC/alice-seed.out" >&2; fail "alice's seed with the M3 build failed"; }
user_run bob seed > "$ACC/bob-seed.out" 2>&1 || { cat "$ACC/bob-seed.out" >&2; fail "bob's seed with the M3 build failed"; }
files_snapshot > "$ACC/state.before"
seed_problems=$(um3 seeded "$ua" "$ub" "$ACC/state.before") || fail "the seed judgement did not run"
[ -z "$seed_problems" ] || { printf '%s\n' "$seed_problems" >&2; fail "the M3 build did not leave the old files of the four keys (see above)"; }
echo "e2e: upgrade-m3: seeded with $vm: $(grep -c . "$ACC/state.before") old files for four keys (alice uid $ua, bob uid $ub)"
journalctl --sync
journalctl -n1 --show-cursor --no-pager | sed -n 's/^-- cursor: //p' > "$ACC/cursor"
[ -s "$ACC/cursor" ] || fail "no journal cursor before the install"

bash "$install" "$new" || fail "$(basename "$new") could not be installed with install.sh"
echo "e2e: upgrade-m3: installed $(basename "$new") with $install, nothing else was run"

# Wait (reading state only) for the service to be up with a new main pid.
pid2=$pid1
for _ in $(seq 60); do
    pid2=$(systemctl show -p MainPID --value custodio)
    if [ "$pid2" -gt 0 ] && [ "$pid2" != "$pid1" ] && systemctl is-active --quiet custodio; then break; fi
    sleep 1
done
[ "$pid2" != "$pid1" ] || fail "the service did not restart after the install (still pid $pid1)"
systemctl is-active --quiet custodio || fail "custodio.service is not active after the upgrade"
[ "$(installed_version "$fmt")" = "$vn" ] || fail "after the upgrade the database holds $(installed_version "$fmt"), not $vn"
files_snapshot > "$ACC/state.after"
journalctl --sync
journalctl --after-cursor="$(cat "$ACC/cursor")" _SYSTEMD_UNIT=custodio.service -o json --no-pager > "$ACC/journal.json"
collect after
# END upgrade-case

judged upgrade-m3-state-purged purged "$ua" "$ub" "$ACC/state.before" "$ACC/state.after"
judged upgrade-m3-list-empty empty "$ACC/after"
judged upgrade-m3-journal-purge journal "$ua" "$ub" "$ACC/journal.json"

# The same ids import again, with this tree's CLI and a real polkit approval; they are listed under their owners afterwards.
mkdir -p "$ACC/reimported/import"
chmod 1777 "$ACC/reimported" "$ACC/reimported/import"
for u in alice bob; do user_run "$u" import > "$ACC/$u-import.out" 2>&1 || { cat "$ACC/$u-import.out" >&2; fail "$u: the import session failed"; }; done
collect reimported
judged upgrade-m3-reimport reimport "$ua" "$ub" "$ACC/reimported"
