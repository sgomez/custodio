#!/usr/bin/env bash
# F161: container-free checks of the vm-silent-* cases (e2e/vm/silent.sh, silent-lib.sh, silent.py): the judgements over fixtures of the guest's evidence with a negative control for each
# fact, hiding and restoring the library with stubbed dpkg-divert/systemctl (the restore after a failed judge, a signal and a failing restore; a run without the trap is the control), and the
# report of the cases in the modes that do not run them. NOT checked here: a real guest (F168).
# shellcheck disable=SC2015,SC2016 # A && B || bad is the check; single quotes hold text for the stubs
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-vm-silent: $*" >&2; fail=1; }
E=$ROOT/e2e
LIB=$E/vm/silent-lib.sh
ID=vs-key
CASES="vm-silent-import-fails vm-silent-journal-cause vm-silent-nothing-stored vm-silent-no-key vm-silent-restored-imports"
# shellcheck source=e2e/vm/silent-lib.sh
source "$LIB"

# ---- the judgements
ETPM_TEXT="Storage: encrypted-tpm. This key is weaker than a TPM key: the TPM of this machine lacks a capability the key type needs, so the key is a file encrypted with a key bound to this TPM."
jline() { # CAUSE: one import entry of the key
    printf '{"_SYSTEMD_UNIT":"custodio.service","CUSTODIO_OPERATION":"import","CUSTODIO_KEY_ID":"%s","CUSTODIO_OUTCOME":"storage_failure","CUSTODIO_CAUSE":"%s"}\n' "$ID" "$1"
}
mkgood() { # DIR
    local d=$1 h=$1/hidden r=$1/restored
    mkdir -p "$h" "$r"
    echo partial > "$h/has2.out"; echo 1 > "$h/has2.rc"
    printf "Error: the credential could not be sealed (com.rfirma.Custodio1.Error.CredentialsUnavailable)\n" > "$h/import.out"; echo 1 > "$h/import.rc"
    printf 'd /var/lib/custodio 700 4096\nf /var/lib/custodio/other.rec 600 120\nabc123  /var/lib/custodio/other.rec\n' > "$h/state-before"
    cp "$h/state-before" "$h/state-after"
    printf 'other\trsa2048\tencrypted-tpm\n' > "$h/list.out"
    printf 'id: other\n  type: rsa2048\n  kind: encrypted-tpm\n' > "$h/cli-list.out"
    jline binding_mismatch > "$h/journal.json"
    echo yes > "$r/has2.out"; echo 0 > "$r/has2.rc"
    printf "Imported key '%s' (rsa2048).\n%s\n" "$ID" "$ETPM_TEXT" > "$r/import.out"
    printf 'other\trsa2048\tencrypted-tpm\n%s\trsa2048\tencrypted-tpm\n' "$ID" > "$r/list.out"
    echo "reader: key $ID: ok" > "$r/reader.out"; echo 0 > "$r/reader.rc"
    : > "$r/restore.problems"
}
judge_all() { local c; for c in $CASES; do vs_problems "$c" "$1" "$ID"; done; }
mkgood "$tmp/good"
[ -z "$(judge_all "$tmp/good")" ] || bad "good evidence rejected: $(judge_all "$tmp/good")"
# ctl NAME CASE SHELL-TEXT: a copy of the good evidence changed by SHELL-TEXT (run in the copy), which the judgement of CASE must reject
ctl() {
    local n=$1 c=$2 d=$tmp/c-$1 out
    cp -r "$tmp/good" "$d"
    (cd "$d" && bash -c "$3")
    out=$(vs_problems "$c" "$d" "$ID")
    [ -n "$out" ] || bad "control $n: the case $c accepts bad evidence"
}
ctl succeeds vm-silent-import-fails "printf \"Imported key '$ID' (rsa2048).\n$ETPM_TEXT\n\" > hidden/import.out; echo 0 > hidden/import.rc"
ctl exit0 vm-silent-import-fails 'echo 0 > hidden/import.rc'
ctl othererr vm-silent-import-fails 'echo "Error (com.rfirma.Custodio1.Error.TpmFailed)" > hidden/import.out'
ctl hidden-yes vm-silent-import-fails 'echo yes > hidden/has2.out; echo 0 > hidden/has2.rc'
ctl newfile vm-silent-nothing-stored 'echo "f /var/lib/custodio/vs-key.rec 600 900" >> hidden/state-after'
ctl newsum vm-silent-nothing-stored 'echo "def456  /var/lib/custodio/vs-key.rec" >> hidden/state-after'
ctl changedsum vm-silent-nothing-stored 'sed -i s/abc123/zzz999/ hidden/state-after'
ctl changedmode vm-silent-nothing-stored 'sed -i "s/ 600 120/ 644 120/" hidden/state-after'
ctl emptystate vm-silent-nothing-stored ': > hidden/state-before; : > hidden/state-after'
ctl nocause vm-silent-journal-cause 'sed -i "s/,\"CUSTODIO_CAUSE\":\"binding_mismatch\"//" hidden/journal.json'
for cause in tpm_error credentials_unavailable tpm_device; do
    ctl "cause-$cause" vm-silent-journal-cause "sed -i s/binding_mismatch/$cause/ hidden/journal.json"
done
ctl noentry vm-silent-journal-cause ': > hidden/journal.json'
ctl twoentries vm-silent-journal-cause 'cat hidden/journal.json hidden/journal.json > hidden/j; mv hidden/j hidden/journal.json'
ctl stored vm-silent-journal-cause 'sed -i "s/storage_failure/stored/" hidden/journal.json'
ctl kind-in-entry vm-silent-journal-cause 'sed -i "s/}\$/,\"CUSTODIO_STORAGE_KIND\":\"encrypted-tpm\"}/" hidden/journal.json'
for k in tpm encrypted-host encrypted-tpm; do
    ctl "left-api-$k" vm-silent-no-key "printf '$ID\trsa2048\t$k\n' >> hidden/list.out"
    ctl "left-cli-$k" vm-silent-no-key "printf 'id: $ID\n  type: rsa2048\n  kind: $k\n' >> hidden/cli-list.out"
done
ctl weaker-in-text vm-silent-no-key 'echo "Storage: encrypted-host." >> hidden/import.out'
ctl lists-empty vm-silent-no-key ': > hidden/list.out; : > hidden/cli-list.out'
ctl restored-fails vm-silent-restored-imports 'echo "Error (com.rfirma.Custodio1.Error.CredentialsUnavailable)" > restored/import.out'
for k in tpm encrypted-host; do
    ctl "restored-$k" vm-silent-restored-imports "sed -i s/encrypted-tpm/$k/g restored/import.out restored/list.out"
done
ctl restored-nolist vm-silent-restored-imports "printf 'other\trsa2048\tencrypted-tpm\n' > restored/list.out"
ctl reader-fails vm-silent-restored-imports 'echo 3 > restored/reader.rc'
ctl reader-missing vm-silent-restored-imports 'rm restored/reader.rc'
ctl has2-partial-after vm-silent-restored-imports 'echo partial > restored/has2.out'
ctl has2-rc-after vm-silent-restored-imports 'echo 1 > restored/has2.rc'
ctl restore-problem vm-silent-restored-imports 'echo "a diversion is left" > restored/restore.problems'
ctl restore-unchecked vm-silent-restored-imports 'rm restored/restore.problems'
# an import that succeeds while hidden is not also blamed on the state listing (each case judges its own fact)
[ -z "$(vs_problems vm-silent-nothing-stored "$tmp/c-succeeds" "$ID")" ] || bad "an import that succeeds while hidden is also blamed on the state listing"

# ---- hiding and restoring, with stubs
S=$tmp/stub
mkdir -p "$S/bin" "$S/lib"
: > "$S/log"; : > "$S/div"; echo 100 > "$S/pid"
touch "$S/lib/libtss2-rc.so.0.0.0"; ln -s libtss2-rc.so.0.0.0 "$S/lib/libtss2-rc.so.0"
stub() { printf '#!/bin/bash\necho "%s $*" >> "%s"\n%s\n' "$1" "$S/log" "$2" > "$S/bin/$1"; chmod +x "$S/bin/$1"; }
stub dpkg-divert 'mode=; p=; d=; while [ $# -gt 0 ]; do case $1 in --add) mode=add; p=$2; shift ;; --remove) mode=rm; p=$2; shift ;; --list) mode=list; p=$2; shift ;; --divert) d=$2; shift ;; esac; shift; done
case $mode in
add) mv "$p" "$d"; echo "$p $d" >> '"$S/div"' ;;
rm) [ -z "${FAIL_REMOVE:-}" ] || exit 2; line=$(grep "^$p " '"$S/div"') || exit 2; mv "${line#* }" "$p"; grep -v "^$p " '"$S/div"' > '"$S/div.new"' || true; mv '"$S/div.new"' '"$S/div"' ;;
list) while read -r a b; do echo "local diversion of $a to $b"; done < '"$S/div"' ;;
esac'
stub ldconfig 'exit 0'
stub busctl 'exit 0'
stub systemctl 'case "$*" in "show -p MainPID --value custodio") cat '"$S/pid"' ;; "show -p ActiveState --value custodio") echo active ;; "restart custodio") echo $(( $(cat '"$S/pid"') + 1 )) > '"$S/pid"' ;; esac; exit 0'
stub systemd-analyze '[ ! -s '"$S/div"' ] && echo yes || { echo partial; exit 1; }'
VSENV=(env PATH="$S/bin:$PATH" VS_LIBS="$S/lib/libtss2-rc.so.0.0.0 $S/lib/libtss2-rc.so.0")
harness() { printf '#!/bin/bash\nsource %s\n%s\n' "$LIB" "$2" > "$S/$1.sh"; } # NAME BODY
back_ok() { [ -e "$S/lib/libtss2-rc.so.0.0.0" ] && [ -L "$S/lib/libtss2-rc.so.0" ] && [ ! -s "$S/div" ]; }
reset_stub() { : > "$S/div"; rm -f "$S"/lib/*.hidden-by-e2e; touch "$S/lib/libtss2-rc.so.0.0.0"; ln -sf libtss2-rc.so.0.0.0 "$S/lib/libtss2-rc.so.0"; }
run_h() { # NAME [VAR=VALUE...]: runs the harness; its status in $S/NAME.rc
    local n=$1 rc=0
    shift
    : > "$S/log"
    "${VSENV[@]}" "$@" bash "$S/$n.sh" > "$S/$n.out" 2> "$S/$n.err" || rc=$?
    echo "$rc" > "$S/$n.rc"
}
# vs_hide moves the library aside and restarts the users
harness hide 'vs_hide; echo hidden-ok'
run_h hide
[ -s "$S/div" ] || bad "vs_hide left no diversion"
[ ! -e "$S/lib/libtss2-rc.so.0.0.0" ] || bad "vs_hide left the library file in place"
grep -q 'daemon-reexec' "$S/log" && grep -q 'restart custodio' "$S/log" || bad "vs_hide did not restart what needs the library"
[ "$(cat "$S/hide.rc")" = 0 ] || bad "vs_hide failed: $(cat "$S/hide.err")"
out=$("${VSENV[@]}" bash -c "source $LIB; vs_restore_ok") || true
[ -n "$out" ] || bad "vs_restore_ok finds nothing wrong while the library is hidden"
harness restore 'vs_restore; vs_restore_ok'
run_h restore
back_ok || bad "vs_restore did not put the library back"
[ -z "$(cat "$S/restore.out")" ] || bad "vs_restore_ok reports problems after a restore: $(cat "$S/restore.out")"
# a hiding with no library to hide fails
harness nolib 'vs_hide'
run_h nolib VS_LIBS=
[ "$(cat "$S/nolib.rc")" != 0 ] || bad "vs_hide succeeds with no library"
# whatever the outcome the trap restores: a failing judge (exit 3), success, a signal
reset_stub
harness failjudge 'vs_install_trap; vs_hide; exit 3'
run_h failjudge
[ "$(cat "$S/failjudge.rc")" = 3 ] || bad "failjudge: the status of the failure was lost ($(cat "$S/failjudge.rc"))"
back_ok || bad "failjudge: the library is not back after a failed judge"
grep -q -- '--remove' "$S/log" && grep -q 'restart custodio' "$S/log" || bad "failjudge: the log shows no undivert and restart"
harness okrun 'vs_install_trap; vs_hide; true'
run_h okrun
{ [ "$(cat "$S/okrun.rc")" = 0 ] && back_ok; } || bad "okrun: not restored on success, or the status changed"
for sig in TERM HUP; do
    harness "sig$sig" "vs_install_trap; vs_hide; touch $S/ready$sig; while :; do sleep 0.1; done"
    rm -f "$S/ready$sig"
    : > "$S/log"
    "${VSENV[@]}" bash "$S/sig$sig.sh" > /dev/null 2>&1 &
    pid=$!
    timeout 10 bash -c "until [ -e $S/ready$sig ]; do sleep 0.05; done" || bad "sig$sig: the harness never hid the library"
    kill -"$sig" "$pid"
    if wait "$pid" 2> /dev/null; then bad "sig$sig: the harness exited 0 after the signal"; fi
    back_ok || bad "sig$sig: the library is not back after the signal"
    grep -q -- '--remove' "$S/log" && grep -q 'restart custodio' "$S/log" || bad "sig$sig: the log shows no undivert and restart"
done
# a restore that fails is reported and the run fails, even if it would have passed
reset_stub
harness failrestore 'vs_install_trap; vs_hide; true'
run_h failrestore FAIL_REMOVE=1
[ "$(cat "$S/failrestore.rc")" != 0 ] || bad "failrestore: a restore that fails exits 0"
grep -q 'could not be put back' "$S/failrestore.err" || bad "failrestore: the failure of the restore is not reported"
# control: the same run without the trap leaves the diversion, and the "restored" check catches it
reset_stub
harness notrap 'vs_hide; exit 3'
run_h notrap
if back_ok; then bad "notrap: the control restored the library too (the trap is not what restores it)"; fi
out=$("${VSENV[@]}" bash -c "source $LIB; vs_restore_ok") || true
grep -q 'diversion is left' <<< "$out" || bad "notrap: vs_restore_ok does not report the diversion left ($out)"
reset_stub
# silent.sh installs the trap before it hides, reads the credential after the restore; a copy without the trap is a different file
tl=$(grep -n '^vs_install_trap$' "$E/vm/silent.sh" | head -n 1 | cut -d: -f1 || true)
hl=$(grep -n '^vs_hide ||' "$E/vm/silent.sh" | head -n 1 | cut -d: -f1 || true)
{ [ -n "$hl" ] && [ -n "$tl" ] && [ "$tl" -lt "$hl" ]; } || bad "silent.sh does not install the trap before it hides the library"
grep -q 'vm_read_credential "\$ID"' "$E/vm/silent.sh" || bad "silent.sh does not read the stored credential after the restore"
sed '/^vs_install_trap$/d' "$E/vm/silent.sh" > "$tmp/silent-notrap.sh"
if cmp -s "$E/vm/silent.sh" "$tmp/silent-notrap.sh"; then bad "the control copy of silent.sh without the trap is the same file"; fi
tl2=$(grep -c '^vs_install_trap$' "$tmp/silent-notrap.sh" || true)
[ "$tl2" = 0 ] || bad "the control copy still installs the trap"

# ---- the report in the modes that do not run the cases
for m in swtpm lacking; do
    for vmv in '' 1; do
        if [ -n "$vmv" ] && [ "$m" = lacking ]; then continue; fi
        out=$(WORK=$tmp E2E_SELECT_FILE=/nonexistent E2E_VM=$vmv E2E_TPM=$m bash "$E/vm/silent.sh" 2>&1) || bad "silent.sh in mode $m (vm='$vmv') failed: $out"
        for c in $CASES; do grep -qx "E2E-CASE skipped $c" <<< "$out" || bad "silent.sh in mode $m (vm='$vmv') does not report $c skipped"; done
    done
done

# ---- wiring
for c in $CASES; do
    grep -qx "$c" "$E/vm/cases.list" || bad "$c is not in e2e/vm/cases.list"
    grep -q "^$c: " "$E/vm/skip.list" || bad "$c has no skip list entry (full mode)"
done
# shellcheck source=e2e/select.sh
( source "$E/select.sh"; [ "$(case_group vm-silent-no-key)" = vm-silent ] && [ "$(case_group vm-tpmrm0-exists)" = vm ] ) || bad "case_group does not put vm-silent-* before vm-*"
printf 'vm-silent-no-key\n' > "$tmp/sel"
mkdir -p "$tmp/tg"
# shellcheck source=e2e/select.sh disable=SC2030,SC2031
# shellcheck disable=SC2030,SC2031
# shellcheck source=e2e/select.sh disable=SC2030,SC2031
# shellcheck disable=SC2030,SC2031
( source "$E/select.sh"; export E2E_SELECT_FILE=$tmp/sel E2E_TARGET_DIR=/nonexistent; ! phase_runs vm-silent ) || bad "phase_runs runs vm-silent on a target that does not list its cases"
grep -q 'phase_runs vm-silent' "$E/guest.sh" || bad "guest.sh has no vm-silent step"

[ "$fail" = 0 ] || exit 1
echo "test-e2e-vm-silent: ok"
