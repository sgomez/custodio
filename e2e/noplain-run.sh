#!/usr/bin/env bash
# Root side of the noplain-* cases (F135, acceptance 3 of SPEC.md). Needs WORK and E2E_TPM. In every mode (swtpm, none, lacking) alice imports an RSA 2048 and then a P-256 key
# (noplain-user.sh); after each import scripts/check-no-plaintext.sh, mounted unchanged at /e2e-noplain, searches the service's real state directory with that key's own .p12 and password
# (noplain-rsa, noplain-ec; each case also checks the kind the mode gives, so that the run is not vacuous). After both imports noplain.py judges that no file there is an unencrypted
# private key (noplain-no-key-file). A guest control plants the key's PKCS#8 DER in a COPY of the directory and the script must find it. Then alice deletes both keys.
# Placement: guest.sh runs this after the sign step; the keys are deleted, so the state and the counts the other steps read are as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
CHECK=/e2e-noplain/scripts/check-no-plaintext.sh
[ -r "$CHECK" ] || fail "scripts/check-no-plaintext.sh is not mounted at $CHECK"
for tool in openssl python3; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done

mode=${E2E_TPM:-swtpm}
NP=$WORK/noplain
rm -rf "$NP"
mkdir "$NP"
tk_make "$NP" noplain
chmod -R a+rX "$NP"
chmod 1777 "$NP"
fx="$(fixture_problems "$NP/rsa.p12" rsa)
$(fixture_problems "$NP/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"

state=$(readlink -f /var/lib/custodio)
[ -d "$state" ] || fail "the state directory $state does not exist"
echo "noplain: state directory $state (as the service sees it: /var/lib/custodio)"
np() { python3 -I "$here/noplain.py" "$@"; }
alice() { timeout 300 su -l alice -c "WORK=$WORK bash /e2e/noplain-user.sh $*" > "$NP/alice.out" 2>&1 || { cat "$NP/alice.out" >&2; fail "alice's session ($*) failed"; }; }
# scan P12: the script on the real state directory with the .p12's password on stdin
scan() { printf '%s\n' "$TK_PASSWORD" | timeout 120 bash "$CHECK" "$state" "$1"; }
problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
scan_job() { # NAME P12: the script on P12 into $NP/job-NAME.out, its exit code into $NP/job-NAME.rc (run as a background job)
    local rc=0
    scan "$2" > "$NP/job-$1.out" 2>&1 || rc=$?
    echo "$rc" > "$NP/job-$1.rc"
}
scan_problem() { # NAME P12: the problem of a finished scan job, if any
    local rc
    rc=$(cat "$NP/job-$1.rc")
    echo "noplain: check-no-plaintext on $(basename "$2") ($1) exit $rc" >&2
    [ "$rc" = 0 ] || echo "check-no-plaintext.sh on $(basename "$2") exited $rc: $(cat "$NP/job-$1.out")"
}
kind_problem() { # CASE TYPE: the kind of np-TYPE in the mode
    np kind "$NP/list-$2.out" "$mode" "np-$2:$([ "$2" = rsa ] && echo rsa2048 || echo ecdsa-p256)"
    echo "noplain: $1 kind $(awk -v k="np-$2" '$1 == k { print $3 }' "$NP/list-$2.out")" >&2
}
control_job() { # the script finds a planted key in a copy of the directory; the live one is untouched. Problems into $NP/job-control.out
    local before copy rc=0 out
    before=$(find "$state" -printf '%p %s %T@\n' | sort)
    copy=$(mktemp -d)
    cp -a "$state/." "$copy/"
    openssl pkcs12 -in "$NP/rsa.p12" -passin "pass:$TK_PASSWORD" -nocerts -noenc 2> /dev/null | openssl pkey -outform DER -out "$copy/planted.der"
    out=$(printf '%s\n' "$TK_PASSWORD" | timeout 120 bash "$CHECK" "$copy" "$NP/rsa.p12" 2>&1) || rc=$?
    echo "noplain: control: planted key in a copy: exit $rc" >&2
    rm -rf "$copy"
    [ "$rc" = 1 ] && grep -q 'planted.der' <<< "$out" || echo "the script did not find the planted key in the copy (exit $rc): $out"
    [ "$before" = "$(find "$state" -printf '%p %s %T@\n' | sort)" ] || echo "the live state directory changed during the control"
}

alice import rsa
scan_job rsa "$NP/rsa.p12" # right after its own import, before anything else touches the state
judge noplain-rsa "$(kind_problem noplain-rsa rsa)
$(scan_problem rsa "$NP/rsa.p12")"

alice import ec
# the independent checks run at once: both scans (the first key must not be exposed by the later write), the files judgement, the control
scan_job ec "$NP/ec.p12" &
scan_job rsa2 "$NP/rsa.p12" &
np list "$state" | sed 's/^/noplain: file /'
(np files "$state" > "$NP/job-files.out" 2>&1 || echo "np files failed" >> "$NP/job-files.out") &
control_job > "$NP/job-control.out" &
wait
judge noplain-ec "$(kind_problem noplain-ec ec)
$(scan_problem ec "$NP/ec.p12")
$(scan_problem rsa2 "$NP/rsa.p12")"
judge noplain-no-key-file "$(cat "$NP/job-files.out")"
if [ -s "$NP/job-control.out" ]; then problems="$problems
control:
$(cat "$NP/job-control.out")"; fi

alice delete
if grep -qE '^np-(rsa|ec)	' "$NP/list-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
[ -z "$problems" ] || fail "noplain cases:$problems"
echo "noplain-run: passed"
