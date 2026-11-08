#!/usr/bin/env bash
# shellcheck disable=SC2013 # ids are single words
# shellcheck disable=SC2016,SC2086 # sed programs in single quotes; $TB is a list of words
# F160: the case list of the VM target (e2e/vm/cases.list) and the accounting of a VM run (e2e/check-cases.sh with CHECK_VM=1), with no VM.
#   list        the list lints, holds each group and each VM-only case, and every container id of the six groups is in it or in omitted.list
#   scripts     every id of the list is reported by a case script (comments do not count), and every id a VM-only script reports is in the list
#   accounting  a synthetic guest output for the real list, in both modes
#   tpmbound    run is accepted in a VM run and refused in a container run; skipped is refused in a VM run
# A negative control is a copy of the thing under test with one behaviour removed (shown to differ with cmp); the same check on the copy must fail.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHK=$ROOT/e2e/check-cases.sh
LIST=$ROOT/e2e/vm/cases.list OMIT=$ROOT/e2e/vm/omitted.list VSKIP=$ROOT/e2e/vm/skip.list
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-vm-cases: $*" >&2; fail=1; }
ids() { grep -v '^[[:space:]]*\(#\|$\)' "$1" | sed 's/:.*//'; }
differs() { cmp -s "$1" "$2" && { bad "$3: the control is identical to the original"; return 1; }; return 0; }

# ---- list
check_list() { # check_list LIST OMITTED: prints the problems
    local l=$1 o=$2 g id n
    [ -z "$(ids "$l" | sort | uniq -d)" ] || echo "duplicate ids in the list"
    ids "$l" | grep -qvE '^[A-Za-z0-9._-]+$' && echo "an id is not one word"
    for g in sign- noplain- pcr- fallback- tpm-clear- upgrade-kinds-; do ids "$l" | grep -q "^$g" || echo "no case of the group $g"; done
    for id in vm-tpmrm0-exists vm-has-tpm2-full vm-install-no-recommends vm-unit-shipped vm-tpm-via-device; do ids "$l" | grep -qx "$id" || echo "VM-only case $id is not in the list"; done
    for id in $(cat "$ROOT/e2e/cases.list" "$ROOT/e2e/targets/debian13/cases.list" | grep -E '^(sign-|noplain-|pcr-|fallback-|tpm-clear-|upgrade-kinds-)' ); do
        n=0; ids "$l" | grep -qx "$id" && n=$((n + 1)); ids "$o" | grep -qx "$id" && n=$((n + 1))
        [ "$n" = 1 ] || echo "$id is $([ "$n" = 0 ] && echo neither in the list nor omitted || echo both in the list and omitted)"
    done
    for id in $(ids "$o"); do grep -qxF "$id" "$ROOT/e2e/cases.list" "$ROOT/e2e/targets/debian13/cases.list" || echo "omitted id $id is in no container list"; done
    grep -qvE '^[A-Za-z0-9._-]+: .*[^[:space:]]$|^#|^$' "$o" && echo "an omitted line has no reason"
    return 0
}
p=$(check_list "$LIST" "$OMIT"); [ -z "$p" ] || bad "list: $p"
grep -v '^pcr-extended-signs$' "$LIST" > "$tmp/l1"; differs "$LIST" "$tmp/l1" list-missing || true
[ -n "$(check_list "$tmp/l1" "$OMIT")" ] || bad "list: a list without a group id passed"
{ cat "$LIST"; echo sign-nonexistent; } > "$tmp/l2"
bash "$CHK" lint "$VSKIP" || bad "skip.list does not lint"

# ---- scripts
SCRIPTS="sign-run.sh sign.py noplain-run.sh pcr-cases.sh pcr-run.sh pcr.py fallback-cases.sh tpmclear-cases.sh tpmclear-run.sh tpmclear.py upgrade-kinds.sh upgradekinds.py vm/judge.sh tpmkind-cases.sh"
stage() { # stage DIR: copies the case scripts
    local s; mkdir -p "$1/vm"; for s in $SCRIPTS; do cp "$ROOT/e2e/$s" "$1/$s"; done
}
check_scripts() { # check_scripts DIR LIST: prints the problems
    local d=$1 l=$2 id s gen
    # ids a script generates are read from its listing mode (sign.py groups, upgradekinds.py cases); the rest from the non-comment lines of the scripts
    gen=$( { python3 -I "$d/sign.py" groups; python3 -I "$d/upgradekinds.py" cases; } 2>&1 )
    for id in $(ids "$l"); do
        grep -qxF -- "$id" <<< "$gen" && continue
        for s in $SCRIPTS; do grep -v '^[[:space:]]*#' "$d/$s" | grep -qw -- "$id" && continue 2; done
        echo "no case script reports $id"
    done
    for id in $(grep -v '^[[:space:]]*#' "$d/vm/judge.sh" | grep -oE '\bvm-[a-z0-9]+(-[a-z0-9]+)*\b' | sort -u); do
        ids "$l" | grep -qx "$id" || echo "judge.sh reports $id, which is not in the list"
    done
}
stage "$tmp/s"; p=$(check_scripts "$tmp/s" "$LIST"); [ -z "$p" ] || bad "scripts: $p"
[ -n "$(check_scripts "$tmp/s" "$tmp/l2")" ] || bad "scripts: a list with an id no script reports passed"
stage "$tmp/c1"; sed -i 's/\bnoplain-no-key-file\b/noplain-gone/g' "$tmp/c1/noplain-run.sh"; differs "$tmp/s/noplain-run.sh" "$tmp/c1/noplain-run.sh" scripts-stops || true
[ -n "$(check_scripts "$tmp/c1" "$LIST")" ] || bad "scripts: a script that stops reporting an id passed"
stage "$tmp/c2"; sed -i 's/\bvm-unit-shipped\b/vm-unit-shipped vm-extra-case/' "$tmp/c2/vm/judge.sh"; differs "$tmp/s/vm/judge.sh" "$tmp/c2/vm/judge.sh" scripts-extra || true
[ -n "$(check_scripts "$tmp/c2" "$LIST")" ] || bad "scripts: a script that reports an extra id passed"
stage "$tmp/c3"; sed -i 's/sign-ec-ecdsa/sign-ec-gone/' "$tmp/c3/sign.py"; differs "$tmp/s/sign.py" "$tmp/c3/sign.py" scripts-generated || true
[ -n "$(check_scripts "$tmp/c3" "$LIST")" ] || bad "scripts: a generating script that stops reporting an id passed"

# ---- accounting
out_for() { # out_for FILE [-ID...] [+KIND ID...]: a complete guest output for the VM list (all run), minus/with changes
    local f=$1; shift
    local drop=" " extra=() id
    while [ $# -gt 0 ]; do case $1 in -*) drop="$drop${1#-} " ;; *) extra+=("$1") ;; esac; shift; done
    { echo "noise"; for id in $(ids "$LIST"); do case $drop in *" $id "*) ;; *) echo "E2E-CASE run $id" ;; esac; done
      for id in "${extra[@]}"; do echo "E2E-CASE $id"; done; echo "e2e: all checks passed"; } > "$f"
}
acct() { # acct MODE-OR-EMPTY OUT [VM]: stdout+stderr of the check; the status is the function's
    local mode=$1 out=$2 vm=${3-1}
    CHECK_VM=${vm:+1} CHECK_TPM_MODE=$mode bash "${CHK_UNDER:-$CHK}" check "$LIST" "$VSKIP" "$out" 2>&1
}
expect_fail() { # expect_fail NAME MESSAGE MODE OUT [VM]
    local name=$1 msg=$2 res
    if res=$(acct "$3" "$4" "${5-1}"); then bad "$name ($3): passed"; return; fi
    grep -qF -- "$msg" <<< "$res" || bad "$name ($3): the message lacks '$msg': $res"
}
for mode in swtpm lacking; do
    out_for "$tmp/ok"; acct "$mode" "$tmp/ok" > /dev/null || bad "complete run ($mode) failed"
    out_for "$tmp/o1" -pcr-restarted-signs; expect_fail missing "case 'pcr-restarted-signs' was not reported" "$mode" "$tmp/o1"
    out_for "$tmp/o2" "run bogus-case"; expect_fail unknown "unknown case 'bogus-case'" "$mode" "$tmp/o2"
    out_for "$tmp/o3" "run sign-rsa-pkcs"; expect_fail twice "case 'sign-rsa-pkcs' reported twice" "$mode" "$tmp/o3"
    unl="vm-unit-shipped"; out_for "$tmp/o4" "-$unl" "skipped $unl"; expect_fail skipped-unlisted "case '$unl' was skipped and is not on the skip list" "$mode" "$tmp/o4"
    for id in sign-rsa-pkcs noplain-rsa pcr-extended-signs tpm-clear-delete upgrade-kinds-kept; do
        out_for "$tmp/o5" "-$id" "skipped $id"; expect_fail "skipped-$id" "case '$id'" "$mode" "$tmp/o5"
    done
    out_for "$tmp/o6"; printf 'E2E-CASE run tpm-kind-import-rsa\n' >> "$tmp/o6"
    CHECK_VM=1 CHECK_TPM_MODE=$mode bash "$CHK" check "$LIST" "$VSKIP" "$tmp/o6" "$tmp/sel" 2> /dev/null && bad "selection with a missing file passed"
done
# a selection: exactly the selected cases; one that is not selected fails
printf 'sign-rsa-pkcs\nnoplain-rsa\n' > "$tmp/sel"
printf 'E2E-CASE run sign-rsa-pkcs\nE2E-CASE run noplain-rsa\n' > "$tmp/s1"
CHECK_VM=1 CHECK_TPM_MODE=swtpm bash "$CHK" check "$LIST" "$VSKIP" "$tmp/s1" "$tmp/sel" > /dev/null 2>&1 || bad "a complete selection failed"
printf 'E2E-CASE run sign-rsa-pkcs\nE2E-CASE run noplain-rsa\nE2E-CASE run noplain-ec\n' > "$tmp/s2"
CHECK_VM=1 CHECK_TPM_MODE=swtpm bash "$CHK" check "$LIST" "$VSKIP" "$tmp/s2" "$tmp/sel" > "$tmp/r" 2>&1 && bad "a case that is not selected passed"
grep -q "case 'noplain-ec' was reported and is not selected" "$tmp/r" || bad "selection message: $(cat "$tmp/r")"
# the same input in a container run gives the same message (the list is the VM's; the container check reads it as a list)
for mode in "" swtpm none lacking; do
    out_for "$tmp/o1" -pcr-restarted-signs
    a=$(CHECK_TPM_MODE=$mode bash "$CHK" check "$LIST" "$VSKIP" "$tmp/o1" 2>&1 >/dev/null | grep "pcr-restarted-signs") || true
    b=$(CHECK_VM=1 CHECK_TPM_MODE=$mode bash "$CHK" check "$LIST" "$VSKIP" "$tmp/o1" 2>&1 >/dev/null | grep "pcr-restarted-signs") || true
    [ -n "$a" ] && [ "$a" = "$b" ] || bad "missing-case message differs between a container and a VM run (mode '$mode'): '$a' / '$b'"
done
# the flag absent: byte-identical to a run with the flag set to nothing
out_for "$tmp/o1" -pcr-restarted-signs
for mode in "" swtpm none lacking; do
    a=$(CHECK_TPM_MODE=$mode bash "$CHK" check "$LIST" "$VSKIP" "$tmp/o1" 2>&1 || true); b=$(CHECK_VM="" CHECK_TPM_MODE=$mode bash "$CHK" check "$LIST" "$VSKIP" "$tmp/o1" 2>&1 || true)
    [ "$a" = "$b" ] || bad "an empty CHECK_VM changes the output (mode '$mode')"
done

# ---- tpmbound
TB="fallback-tpmbound-import fallback-tpmbound-cli-list upgrade-kinds-tpmbound"
printf "%s: fixture reason\n" ${TB}  > "$tmp/skip-tb"
sed -i 's/^\(.*\):.*/\1: fixture reason/' "$tmp/skip-tb"
for id in $TB; do
    out_for "$tmp/t1" # all run, including the tpmbound cases
    for mode in swtpm lacking; do acct "$mode" "$tmp/t1" > /dev/null || bad "tpmbound run in a VM run ($mode) failed"; done
    for mode in swtpm none lacking ""; do expect_fail "container-run-$id" "case '$id' cannot be run (deviation F134) and was reported run" "$mode" "$tmp/t1" ""; done
    out_for "$tmp/t2" "-$id" "skipped $id"
    for mode in swtpm lacking; do
        res=$(CHECK_VM=1 CHECK_TPM_MODE=$mode bash "$CHK" check "$LIST" "$tmp/skip-tb" "$tmp/t2" 2>&1) && bad "tpmbound skipped in a VM run ($mode, listed) passed"
        grep -qF "case '$id'" <<< "$res" || bad "tpmbound skipped message lacks the case: $res"
    done
done
# controls: a check-cases.sh that accepts them run in a container run, and one that accepts them skipped in a VM run, each fails the check below
refuses_run_in_container() { # CHK: the container accounting refuses every tpmbound case reported run, in every mode
    local m
    out_for "$tmp/t1"
    for m in swtpm none lacking ""; do CHECK_TPM_MODE=$m bash "$1" check "$LIST" "$VSKIP" "$tmp/t1" > /dev/null 2>&1 && return 1; done
    return 0
}
refuses_skipped_in_vm() { # CHK
    local m id
    for id in $TB; do
        out_for "$tmp/t2" "-$id" "skipped $id"
        for m in swtpm lacking; do CHECK_VM=1 CHECK_TPM_MODE=$m bash "$1" check "$LIST" "$tmp/skip-tb" "$tmp/t2" > /dev/null 2>&1 && return 1; done
    done
    return 0
}
refuses_run_in_container "$CHK" || bad "the real check-cases.sh accepts a tpmbound case run in a container run"
refuses_skipped_in_vm "$CHK" || bad "the real check-cases.sh accepts a tpmbound case skipped in a VM run"
cp "$CHK" "$tmp/chk-run.sh"; sed -i 's/if \[ -z "\${CHECK_VM:-}" \]; then/if true; then :; else/' "$tmp/chk-run.sh"; differs "$CHK" "$tmp/chk-run.sh" control-run || true
refuses_run_in_container "$tmp/chk-run.sh" && bad "control: a check that accepts tpmbound run in a container run was not caught"
cp "$CHK" "$tmp/chk-skip.sh"; sed -i 's/if \[ "\$kind" = skipped \] && \[ -n "\${CHECK_VM:-}" \]; then/if false; then/' "$tmp/chk-skip.sh"; differs "$CHK" "$tmp/chk-skip.sh" control-skip || true
refuses_skipped_in_vm "$tmp/chk-skip.sh" && bad "control: a check that accepts tpmbound skipped in a VM run was not caught"

[ "$fail" -eq 0 ] || exit 1
echo "test-e2e-vm-cases: ok"
