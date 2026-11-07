#!/usr/bin/env bash
# Root side of the tpm-dup-* cases (F136, acceptance 4 of SPEC.md). Needs WORK and E2E_TPM. In mode none no key is of kind tpm and the cases are reported skipped. Otherwise (swtpm, lacking)
# alice imports an RSA 2048 and a P-256 key (tpmdup-user.sh) and root reads the service's real state directory: tpmdup.py scan takes the public and private areas out of every record of
# kind tpm there (not only the two imported; the two ids must be among them), a parent is made on the service's swtpm with the template of the service (SRK_ATTRS, docs/findings/F113.md)
# and its name must be the one stored in each record. Each key is then loaded with tpm2_load and
#   tpm-dup-authpolicy-empty   tpm2_readpublic on the loaded key shows no authorization policy
#   tpm-dup-duplicate-fails    tpm2_duplicate under a policy session on TPM2_CC_Duplicate fails with TPM_RC_POLICY_FAIL
#   tpm-dup-other-tpm          tpm2_load of the same areas under the parent of a second, independent swtpm (same template) fails with an integrity error
# Guest controls (they decide the cases): the blob loads under its own parent on the first swtpm; the same tpm2_duplicate succeeds on a key made duplicable there; the two parents are one
# template (equal public areas but for the name and the unique field). The second swtpm is stopped before this script ends, and both keys are deleted.
# Placement: guest.sh runs this after the noplain step; the state and the counts the other steps read are as before.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/tpmdup-cases.sh
source "$here/tpmdup-cases.sh"
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpm-lib.sh
source "$here/tpm-lib.sh"

mode=${E2E_TPM:-swtpm}
if [ "$mode" = none ]; then
    tpmdup_skip_all "$mode"
    exit 0
fi
for tool in tpm2_createprimary tpm2_load tpm2_readpublic tpm2_duplicate tpm2_create tpm2_startauthsession tpm2_policycommandcode tpm2_flushcontext swtpm swtpm_setup swtpm_ioctl openssl python3; do
    command -v "$tool" > /dev/null || fail "$tool is not installed"
done
TD=$WORK/tpmdup
rm -rf "${TD:?}"
mkdir "$TD"
tk_make "$TD" tpmdup
rm -f "${TD:?}"/*.crt
chmod -R a+rX "$TD"
chmod 1777 "$TD"
fx="$(fixture_problems "$TD/rsa.p12" rsa)
$(fixture_problems "$TD/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"

state=$(readlink -f /var/lib/custodio)
[ -d "$state" ] || fail "the state directory $state does not exist"
echo "tpmdup: state directory $state (as the service sees it: /var/lib/custodio)"
td() { python3 -I "$here/tpmdup.py" "$@"; }
hexof() { od -An -tx1 -v "$1" | tr -d ' \n'; }
SRK_ATTRS='fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt' # the template of the service's parent (docs/findings/F113.md)
TCTI1=swtpm:path=$TPM_SOCK
TD_DIR2=/tmp/custodio-e2e-tpmdup
TD_STATE2=/var/tmp/custodio-e2e-tpmdup-state
TD_SOCK2=$TD_DIR2/swtpm.sock
TCTI2=swtpm:path=$TD_SOCK2
second_stop() { # the second swtpm over its control socket, and wait until its process is gone
    if [ -S "$TD_SOCK2.ctrl" ]; then swtpm_ioctl --unix "$TD_SOCK2.ctrl" -s > /dev/null 2>&1 || true; fi
    for _ in $(seq 50); do pgrep -f "dir=$TD_STATE2" > /dev/null || break; sleep 0.1; done
    rm -rf "${TD_DIR2:?}" "${TD_STATE2:?}"
}
trap second_stop EXIT

# tt TCTI DIR TOOL ARGS...: a tpm2-tools command on that TPM, in DIR; the transient objects it leaves are flushed (no resource manager). Output into DIR/last.out, status into DIR/last.rc.
tt() {
    local tcti=$1 dir=$2 rc=0
    shift 2
    ( cd "$dir" && TPM2TOOLS_TCTI=$tcti timeout 60 "$@" > last.out 2>&1 < /dev/null ) || rc=$?
    echo "$rc" > "$dir/last.rc"
    TPM2TOOLS_TCTI=$tcti timeout 60 tpm2_flushcontext -t > /dev/null 2>&1 < /dev/null || true
    return 0
}
mk_parent() { # TCTI DIR: the parent of the service's template as DIR/p.ctx, its name as DIR/p.name, its public area as DIR/p.show (one helper for both TPMs)
    tt "$1" "$2" tpm2_createprimary -C o -G ecc256:aes128cfb -a "$SRK_ATTRS" -c p.ctx
    [ "$(cat "$2/last.rc")" = 0 ] || { cat "$2/last.out" >&2; return 1; }
    tt "$1" "$2" tpm2_readpublic -c p.ctx -n p.name
    [ "$(cat "$2/last.rc")" = 0 ] || { cat "$2/last.out" >&2; return 1; }
    tt "$1" "$2" tpm2_readpublic -c p.ctx
    cp "$2/last.out" "$2/p.show"
}

# the second swtpm and its parent, while alice imports
mkdir -p "$TD/t2" "$TD_DIR2"
(
    tpm_swtpm_start "$TD_SOCK2" "$TD_STATE2" && mk_parent "$TCTI2" "$TD/t2"
) > "$TD/second.out" 2>&1 &
second_pid=$!
timeout 300 su -l alice -c "WORK=$WORK bash /e2e/tpmdup-user.sh import" > "$TD/alice.out" 2>&1 || { cat "$TD/alice.out" >&2; fail "alice's import session failed"; }
wait "$second_pid" || { cat "$TD/second.out" >&2; fail "the second swtpm or its parent did not come up"; }
[ -s "$TD/t2/p.name" ] || fail "the second parent has no name"

problems=''
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local case=$1 p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$case"; else problems="$problems
$case:
$p"; fi
}
# the keys to judge: every record of kind tpm in the state directory
mkdir -p "$TD/rec"
td scan "$state" "$TD/rec" > "$TD/scan.tsv" || fail "the records could not be read: $(td scan "$state" "$TD/rec" 2>&1 | tail -n 3)"
sed 's/^/tpmdup: record /' "$TD/scan.tsv"
inv=$(td inventory "$TD/scan.tsv" "$mode" td-rsa td-ec)
[ -z "$inv" ] || fail "the records are not those of the cases: $inv"
keys=$(awk -F'\t' '$3 == "tpm" { print $1 "-" $2 }' "$TD/scan.tsv")
echo "tpmdup: keys judged: $(tr '\n' ' ' <<< "$keys")"

# the first TPM: parent, loads, readpublic, duplicate, and the controls (one job); the second TPM: the load under its parent (another job)
mkdir -p "$TD/t1"
mk_parent "$TCTI1" "$TD/t1" || fail "the parent could not be made on the service's swtpm"
policy_dup() { # TCTI DIR KEYCTX: tpm2_duplicate of KEYCTX under a policy session on Duplicate, as DIR/dup.* (the one invocation of the stored keys and the control)
    local tcti=$1 dir=$2
    rm -f "$dir/dup.priv" "$dir/dup.seed"
    tt "$tcti" "$dir" tpm2_createprimary -C e -c np.ctx
    tt "$tcti" "$dir" tpm2_startauthsession --policy-session -S s.ctx
    tt "$tcti" "$dir" tpm2_policycommandcode -S s.ctx TPM2_CC_Duplicate
    tt "$tcti" "$dir" tpm2_duplicate -C np.ctx -c "$3" -G null -p "session:s.ctx" -r dup.priv -s dup.seed
    cp "$dir/last.out" "$dir/dup.out"
    cp "$dir/last.rc" "$dir/dup.rc"
    tt "$tcti" "$dir" tpm2_flushcontext s.ctx
}
load_key() { # TCTI DIR: the record's areas under DIR/../p.ctx as DIR/k.ctx, result in DIR/load.*
    tt "$1" "$2" tpm2_load -C ../p.ctx -u k.pub -r k.priv -c k.ctx
    cp "$2/last.out" "$2/load.out"
    cp "$2/last.rc" "$2/load.rc"
}
job1() {
    local k d=$TD/t1 kd
    for k in $keys; do
        kd=$d/$k
        mkdir -p "$kd"
        cp "$TD/rec/$k/k.pub" "$TD/rec/$k/k.priv" "$kd/"
        load_key "$TCTI1" "$kd"
        tt "$TCTI1" "$kd" tpm2_readpublic -c k.ctx
        cp "$kd/last.out" "$kd/show.out"
        policy_dup "$TCTI1" "$kd" k.ctx
    done
    # control: a key made on this TPM that may be duplicated (no fixedTPM, no fixedParent), and the same invocation
    kd=$d/control
    mkdir -p "$kd"
    tt "$TCTI1" "$kd" tpm2_createprimary -C o -c cp.ctx
    tt "$TCTI1" "$kd" tpm2_startauthsession -S trial.ctx
    tt "$TCTI1" "$kd" tpm2_policycommandcode -S trial.ctx -L pol.dat TPM2_CC_Duplicate
    tt "$TCTI1" "$kd" tpm2_flushcontext trial.ctx
    tt "$TCTI1" "$kd" tpm2_create -C cp.ctx -g sha256 -G ecc256 -L pol.dat -a 'sensitivedataorigin|userwithauth|sign' -u c.pub -r c.priv
    tt "$TCTI1" "$kd" tpm2_load -C cp.ctx -u c.pub -r c.priv -c c.ctx
    cp "$kd/last.rc" "$kd/load.rc"
    cp "$kd/last.out" "$kd/load.out"
    tt "$TCTI1" "$kd" tpm2_readpublic -c c.ctx
    cp "$kd/last.out" "$kd/show.out"
    policy_dup "$TCTI1" "$kd" c.ctx
}
job2() {
    local k kd
    for k in $keys; do
        kd=$TD/t2/$k
        mkdir -p "$kd"
        cp "$TD/rec/$k/k.pub" "$TD/rec/$k/k.priv" "$kd/"
        load_key "$TCTI2" "$kd"
    done
}
job1 &
j1=$!
job2 &
j2=$!
wait "$j1" || fail "the checks on the service's swtpm did not finish"
wait "$j2" || fail "the checks on the second swtpm did not finish"
second_stop
if pgrep -f "dir=$TD_STATE2" > /dev/null; then fail "the second swtpm is still running"; fi

# judgements
echo "tpmdup: parent names: service's TPM $(hexof "$TD/t1/p.name"), second TPM $(hexof "$TD/t2/p.name")"
common=''
for k in $keys; do
    stored=$(awk -F'\t' -v k="$k" '$1 "-" $2 == k { print $4 }' "$TD/scan.tsv")
    common="$common
$(td parent "$stored" "$TD/t1/p.name" | sed "s/^/$k: /")"
done
common="$common
$(td samepub "$TD/t1/p.show" "$TD/t2/p.show")
$(td succeeded 'the control key made duplicable, loaded' "$(cat "$TD/t1/control/load.rc")" "$TD/t1/control/load.out")
$(td succeeded 'tpm2_duplicate of the control key' "$(cat "$TD/t1/control/dup.rc")" "$TD/t1/control/dup.out")"
# the control key has a policy: the same judgement must see it (so an empty result for the stored keys is not the judgement's blindness)
if [ -z "$(td authpolicy "$TD/t1/control/show.out")" ]; then common="$common
the judgement of the authorization policy did not see the policy of the control key: $(tr '\n' ' ' < "$TD/t1/control/show.out" | cut -c1-300)"; fi
echo "tpmdup: tpm2-tools $(tpm2_readpublic --version 2>&1 | tr '\n' ' '); control key: $(grep 'authorization policy' "$TD/t1/control/show.out" || true)"
[ -s "$TD/t1/control/dup.priv" ] || common="$common
the control key's duplicate was not written"
a='' b='' c=''
for k in $keys; do
    a="$a
$(td succeeded "the load on its own TPM" "$(cat "$TD/t1/$k/load.rc")" "$TD/t1/$k/load.out" | sed "s/^/$k: /")
$(td authpolicy "$TD/t1/$k/show.out" | sed "s/^/$k: /")"
    b="$b
$(td duplicate "$(cat "$TD/t1/$k/dup.rc")" "$TD/t1/$k/dup.out" | sed "s/^/$k: /")"
    if [ -e "$TD/t1/$k/dup.priv" ]; then b="$b
$k: a duplicate was written"; fi
    c="$c
$(td other-tpm "$(cat "$TD/t2/$k/load.rc")" "$TD/t2/$k/load.out" | sed "s/^/$k: /")"
    echo "tpmdup: $k: public area: $(tr '\n' ' ' < "$TD/t1/$k/show.out" | cut -c1-400)"
    echo "tpmdup: $k: authorization policy lines: $(grep -c 'authorization policy' "$TD/t1/$k/show.out" || true)"
    echo "tpmdup: $k: tpm2_duplicate exit $(cat "$TD/t1/$k/dup.rc"): $(grep -m1 'tpm:' "$TD/t1/$k/dup.out" || true)"
    echo "tpmdup: $k: second TPM tpm2_load exit $(cat "$TD/t2/$k/load.rc"): $(grep -m1 'tpm:' "$TD/t2/$k/load.out" || true)"
done
judge tpm-dup-authpolicy-empty "$common
$a"
judge tpm-dup-duplicate-fails "$common
$b"
judge tpm-dup-other-tpm "$common
$c"

timeout 300 su -l alice -c "WORK=$WORK bash /e2e/tpmdup-user.sh delete" > "$TD/alice-delete.out" 2>&1 || { cat "$TD/alice-delete.out" >&2; fail "alice's delete session failed"; }
if grep -qE '^td-(rsa|ec)	' "$TD/list-after.out"; then problems="$problems
end:
a key of the cases is still listed after the deletes"; fi
[ -z "$(printf '%s' "$problems" | tr -d '[:space:]')" ] || fail "tpm-dup cases:$problems"
echo "tpmdup-run: passed"
