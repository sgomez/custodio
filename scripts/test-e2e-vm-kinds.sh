#!/usr/bin/env bash
# F161: container-free checks of the kind cases of a VM run: the judgements per mode (full: tpm for RSA 2048 and P-256; lacking: encrypted-tpm for both, with the weaker-and-why text),
# the case accounting of a VM run, tpmkind_judge on files with the right and the wrong mode, and the reader of the stored credential (e2e/vm/cred-lib.sh) on synthetic records.
# NOT checked here: a real guest (F168).
# shellcheck disable=SC2086,SC2013,SC2015,SC2016 # the ids are words; the greps read the scripts for their calls (single quotes keep the $)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-vm-kinds: $*" >&2; fail=1; }
E=$ROOT/e2e
ids="tpm-kind-import-rsa tpm-kind-import-ec tpm-kind-api-list tpm-kind-cli-list tpm-kind-journal"

# ---- evidence per mode
TPM_TEXT="Storage: tpm. The key is in the TPM and cannot be copied out of it."
ETPM_TEXT="Storage: encrypted-tpm. This key is weaker than a TPM key: the TPM of this machine lacks a capability the key type needs, so the key is a file encrypted with a key bound to this TPM. Root can use it while the machine runs."
REMIND="Now delete the original file: it still holds your private key."
imp() { printf "Imported key '%s' (%s).\n%s\n%s\n" "$1" "$2" "$3" "$REMIND"; }
# mkset DIR KIND TEXT: a complete set of the step's files, every key of KIND
mkset() {
    local d=$1 k=$2 t=$3
    mkdir -p "$d"
    imp tk-rsa rsa2048 "$t" > "$d/import-rsa.out"
    imp tk-ec ecdsa-p256 "$t" > "$d/import-ec.out"
    printf 'tk-rsa\trsa2048\t%s\ntk-ec\tecdsa-p256\t%s\n' "$k" "$k" > "$d/api.out"
    printf 'id: tk-rsa\n  type: rsa2048\n  kind: %s\n\nid: tk-ec\n  type: ecdsa-p256\n  kind: %s\n' "$k" "$k" > "$d/cli.out"
    : > "$d/api-after.out"
    {
        for i in tk-rsa tk-ec; do
            printf '{"_SYSTEMD_UNIT":"custodio.service","CUSTODIO_OPERATION":"import","CUSTODIO_KEY_ID":"%s","CUSTODIO_OUTCOME":"stored","CUSTODIO_STORAGE_KIND":"%s"}\n' "$i" "$k"
        done
    } > "$d/journal.json"
}
J() { python3 -I "$E/tpmkind.py" "$@"; }
ok() { local n=$1 out; shift; out=$(J "$@") || { bad "$n: judgement failed"; return; }; [ -z "$out" ] || bad "$n: good evidence rejected: $out"; }
no() { local n=$1 out; shift; out=$(J "$@") || true; [ -n "$out" ] || bad "$n: bad evidence accepted"; }
judge_all() { # MODE DIR: every judgement of the step; prints the problems
    local m=$1 d=$2
    J --mode "$m" import "$d/import-rsa.out" tk-rsa rsa2048
    J --mode "$m" import "$d/import-ec.out" tk-ec ecdsa-p256
    J --mode "$m" api "$d/api.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256
    J --mode "$m" cli "$d/cli.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256
    J --mode "$m" journal "$d/journal.json" tk-rsa tk-ec
}
mkset "$tmp/full" tpm "$TPM_TEXT"
mkset "$tmp/lack" encrypted-tpm "$ETPM_TEXT"
[ -z "$(judge_all full "$tmp/full")" ] || bad "full: good evidence rejected: $(judge_all full "$tmp/full")"
[ -z "$(judge_all lacking "$tmp/lack")" ] || bad "lacking: good evidence rejected: $(judge_all lacking "$tmp/lack")"
[ -n "$(judge_all lacking "$tmp/full")" ] || bad "lacking accepts the full evidence"
[ -n "$(judge_all full "$tmp/lack")" ] || bad "full accepts the lacking evidence"
[ -z "$(judge_all swtpm "$tmp/full")" ] || bad "the container mode (swtpm) rejects the tpm evidence"
J --mode bogus api x 2> /dev/null && bad "an unknown mode is accepted"

# controls: one place and one key at a time. $1 mode, $2 the set that is good for the mode, $3 the kind that is wrong
control_kinds() {
    local m=$1 good=$2 wrong=$3 key sub
    for key in rsa ec; do
        sub=$tmp/c-$m-$key-$wrong
        cp -r "$good" "$sub"
        local id=tk-$key
        # the import text of one key with the wrong kind line
        local wtext=$TPM_TEXT
        [ "$wrong" != tpm ] && wtext="Storage: $wrong. This key is weaker than a TPM key: x."
        case $key in rsa) imp tk-rsa rsa2048 "$wtext" > "$sub/import-rsa.out" ;; ec) imp tk-ec ecdsa-p256 "$wtext" > "$sub/import-ec.out" ;; esac
        [ -n "$(J --mode "$m" import "$sub/import-$key.out" "$id" "$([ $key = rsa ] && echo rsa2048 || echo ecdsa-p256)")" ] || bad "$m: import text of $id with kind $wrong accepted"
        cp -r "$good" "$sub-api"
        sed -i "s/^$id\(.*\)\t[a-z-]*\$/$id\1\t$wrong/" "$sub-api/api.out"
        [ -n "$(J --mode "$m" api "$sub-api/api.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256)" ] || bad "$m: API kind of $id $wrong accepted"
        cp -r "$good" "$sub-cli"
        awk -v id="$id" -v k="$wrong" '$0=="id: " id {f=1} f && /^  kind:/ {print "  kind: " k; f=0; next} {print}' "$good/cli.out" > "$sub-cli/cli.out"
        [ -n "$(J --mode "$m" cli "$sub-cli/cli.out" tk-rsa:rsa2048 tk-ec:ecdsa-p256)" ] || bad "$m: CLI kind of $id $wrong accepted"
        cp -r "$good" "$sub-j"
        sed -i "/\"$id\"/ s/\"CUSTODIO_STORAGE_KIND\":\"[a-z-]*\"/\"CUSTODIO_STORAGE_KIND\":\"$wrong\"/" "$sub-j/journal.json"
        [ -n "$(J --mode "$m" journal "$sub-j/journal.json" tk-rsa tk-ec)" ] || bad "$m: journal kind of $id $wrong accepted"
    done
}
for w in encrypted-tpm encrypted-host ''; do control_kinds full "$tmp/full" "$w"; done
for w in tpm encrypted-host ''; do control_kinds lacking "$tmp/lack" "$w"; done
# the weaker-and-why text (lacking): none, no reason, a text of another kind, weaker spoken in full mode
for k in rsa ec; do
    t=$([ $k = rsa ] && echo rsa2048 || echo ecdsa-p256)
    imp tk-$k $t "Storage: encrypted-tpm. The key is in a file." > "$tmp/w1"
    imp tk-$k $t "Storage: encrypted-tpm. This key is weaker than a TPM key: it is a file." > "$tmp/w2"
    imp tk-$k $t "Storage: encrypted-tpm." > "$tmp/w3"
    for w in w1 w2 w3; do
        [ -n "$(J --mode lacking import "$tmp/$w" tk-$k $t)" ] || bad "lacking: $k text $w (no weaker, or no reason) accepted"
    done
    printf "Imported key 'tk-%s' (%s).\nStorage: tpm. The key is in the TPM and cannot be copied out of it.\nThis key is weaker\n" $k $t > "$tmp/w4"
    [ -n "$(J --mode full import "$tmp/w4" tk-$k $t)" ] || bad "full: $k with a weaker line accepted"
done
# journal of another id or outcome (lacking)
cp -r "$tmp/lack" "$tmp/jo"; sed -i 's/"tk-rsa"/"other"/' "$tmp/jo/journal.json"
[ -n "$(J --mode lacking journal "$tmp/jo/journal.json" tk-rsa tk-ec)" ] || bad "lacking: a journal entry of another id accepted"
cp -r "$tmp/lack" "$tmp/jo2"; sed -i 's/"stored"/"failed"/' "$tmp/jo2/journal.json"
[ -n "$(J --mode lacking journal "$tmp/jo2/journal.json" tk-rsa tk-ec)" ] || bad "lacking: a journal entry of another outcome accepted"
# the old calls (no --mode) are the container run: kind tpm, unchanged
ok container-default import "$tmp/full/import-rsa.out" tk-rsa rsa2048
no container-default-etpm import "$tmp/lack/import-rsa.out" tk-rsa rsa2048

# ---- tpmkind_judge on files, with the right and the wrong mode: the cases reported and the problems named
# shellcheck source=e2e/tpmkind-lib.sh
source "$E/tpmkind-lib.sh"
# shellcheck source=e2e/tpmkind-cases.sh
source "$E/tpmkind-cases.sh"
count_run() { # MODE DIR: how many cases the judgement reports as run
    E2E_SELECT_FILE=/nonexistent tpmkind_judge "$1" "$2" "$(J --mode "$1" journal "$2/journal.json" tk-rsa tk-ec)" | grep -c '^E2E-CASE run' || true
}
[ "$(count_run full "$tmp/full")" = 5 ] || bad "judge full: not five cases run on the full evidence"
[ "$(count_run lacking "$tmp/lack")" = 5 ] || bad "judge lacking: not five cases run on the lacking evidence"
# tpmkind_judge sets TK_PROBLEMS in the current shell, so the checks that read it do not go through a pipe
E2E_SELECT_FILE=/nonexistent tpmkind_judge lacking "$tmp/full" "$(J --mode lacking journal "$tmp/full/journal.json" tk-rsa tk-ec)" > "$tmp/out-wrong1"
[ -n "$TK_PROBLEMS" ] || bad "judge: mode lacking with the full evidence (kind tpm) has no problem"
grep -q '^E2E-CASE run' "$tmp/out-wrong1" && bad "judge: mode lacking with kind tpm reported a case run"
E2E_SELECT_FILE=/nonexistent tpmkind_judge full "$tmp/lack" "$(J --mode full journal "$tmp/lack/journal.json" tk-rsa tk-ec)" > "$tmp/out-wrong2"
[ -n "$TK_PROBLEMS" ] || bad "judge: mode full with the lacking evidence (kind encrypted-tpm) has no problem"
grep -q '^E2E-CASE run' "$tmp/out-wrong2" && bad "judge: mode full with kind encrypted-tpm reported a case run"
printf 'tk-rsa\trsa2048\tencrypted-tpm\n' > "$tmp/lack/api-after.out"
E2E_SELECT_FILE=/nonexistent tpmkind_judge lacking "$tmp/lack" "" > /dev/null
grep -q 'still listed' <<< "$TK_PROBLEMS" || bad "judge: a key left after the deletes is not reported"
: > "$tmp/lack/api-after.out"
# the container run does not read --mode full/lacking: the old rule
grep -q 'tpmkind_judge "\$judge_mode"' "$E/tpmkind-run.sh" || bad "tpmkind-run.sh does not judge through tpmkind_judge with the mode it computed"
grep -q 'judge_mode=full' "$E/tpmkind-run.sh" && grep -q 'judge_mode=lacking' "$E/tpmkind-run.sh" || bad "tpmkind-run.sh does not map the VM modes"
grep -q 'tpmkind_skip_all "\$mode"' "$E/tpmkind-run.sh" || bad "tpmkind-run.sh lost the container skip"

# ---- the accounting of a VM run
CHK=$E/check-cases.sh
cases=$tmp/cases; cp "$E/vm/cases.list" "$cases"
for id in $ids; do grep -qx "$id" "$cases" || bad "$id is not in e2e/vm/cases.list"; done
ids_run() { local id; for id in $(grep -v '^[[:space:]]*\(#\|$\)' "$cases"); do echo "E2E-CASE run $id"; done; }
ids_run > "$tmp/all-run"
printf 'tpm-kind-import-rsa: x\n' > "$tmp/skip-tk"      # a skip list that names the case does not help
for m in full lacking; do
    tm=$([ $m = full ] && echo swtpm || echo lacking)
    CHECK_VM=1 CHECK_TPM_MODE=$tm bash "$CHK" check "$cases" "$E/vm/skip.list" "$tmp/all-run" > /dev/null 2>&1 || bad "$m: all cases run is refused"
    for id in tpm-kind-import-rsa tpm-kind-journal fallback-tpmbound-import fallback-tpmbound-cli-list; do
        sed "s/^E2E-CASE run $id\$/E2E-CASE skipped $id/" "$tmp/all-run" > "$tmp/sk"
        CHECK_VM=1 CHECK_TPM_MODE=$tm bash "$CHK" check "$cases" "$tmp/skip-tk" "$tmp/sk" > /dev/null 2>&1 && bad "$m: $id skipped is accepted"
        printf '%s: x\n' "$id" > "$tmp/skip-one"
        CHECK_VM=1 CHECK_TPM_MODE=$tm bash "$CHK" check "$cases" "$tmp/skip-one" "$tmp/sk" > /dev/null 2>&1 && bad "$m: $id skipped is accepted with a skip list entry"
    done
done
# vm-silent-*: skipped is refused in lacking, accepted in full (with the skip list entry)
printf 'vm-silent-import-fails\n' > "$tmp/c-silent"; { cat "$cases"; echo vm-silent-import-fails; } > "$tmp/cases2"
{ cat "$tmp/all-run"; echo 'E2E-CASE skipped vm-silent-import-fails'; } > "$tmp/out-silent"
printf 'vm-silent-import-fails: needs an encrypted-tpm import\n' > "$tmp/skip-silent"
CHECK_VM=1 CHECK_TPM_MODE=lacking bash "$CHK" check "$tmp/cases2" "$tmp/skip-silent" "$tmp/out-silent" > /dev/null 2>&1 && bad "lacking: vm-silent-* skipped is accepted"
CHECK_VM=1 CHECK_TPM_MODE=swtpm bash "$CHK" check "$tmp/cases2" "$tmp/skip-silent" "$tmp/out-silent" > /dev/null 2>&1 || bad "full: vm-silent-* skipped with a skip list entry is refused"
CHECK_VM=1 CHECK_TPM_MODE=swtpm bash "$CHK" check "$tmp/cases2" "$E/vm/skip.list" "$tmp/out-silent" > /dev/null 2>&1 && bad "full: vm-silent-* skipped without a skip list entry is accepted"
# the container accounting: tpm-kind-* skipped in none/lacking with the skip list is as before (no CHECK_VM)
sed 's/^E2E-CASE run \(tpm-kind-.*\)$/E2E-CASE skipped \1/' "$tmp/all-run" > "$tmp/ctr"
grep -h '^tpm-kind' "$E/targets/debian13/skip.list" > /dev/null || bad "debian13 skip list lost the tpm-kind entries"
# control: a check-cases.sh copy without the VM rule accepts the skipped case
mkdir "$tmp/nr"; sed '/F161: in a VM run the tpm-kind-/,+3d' "$CHK" > "$tmp/nr/check-cases.sh"
cmp -s "$CHK" "$tmp/nr/check-cases.sh" && bad "the control copy without the VM rule changes nothing"
sed "s/^E2E-CASE run tpm-kind-import-rsa\$/E2E-CASE skipped tpm-kind-import-rsa/" "$tmp/all-run" > "$tmp/sk"
printf 'tpm-kind-import-rsa: x\n' > "$tmp/skip-one"
CHECK_VM=1 CHECK_TPM_MODE=lacking bash "$tmp/nr/check-cases.sh" check "$cases" "$tmp/skip-one" "$tmp/sk" > /dev/null 2>&1 \
    && bad "the control copy without the VM rule still refuses a skipped tpm-kind case in lacking"

# ---- the reader on the stored credential
rec() { # DIR ID KINDTAG CREDFILE: a record file as record.rs writes it, in DIR/1000/
    mkdir -p "$1/1000"
    python3 -I - "$1/1000/$2.key" "$2" "$3" "$4" << 'PY'
import sys
path, key_id, tag, cred = sys.argv[1], sys.argv[2], int(sys.argv[3]), open(sys.argv[4], "rb").read()
out = b"CUSTODIO" + bytes([1, tag]) + (1000).to_bytes(4, "big") + bytes([len(key_id)]) + key_id.encode()
out += (3).to_bytes(4, "big") + b"crt" + len(cred).to_bytes(4, "big") + cred
open(path, "wb").write(out)
PY
}
cred() { # OUT IDHEX MASK: a synthetic credential with the header of F153 (host+tpm2 scoped when the id says so)
    python3 -I - "$1" "$2" "$3" << 'PY'
import struct, sys
out, idhex, mask = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
b = bytes.fromhex(idhex) + struct.pack("<IIII", 32, 1, 12, 16) + bytes(12) + bytes(4)
b += struct.pack("<QHHII", mask, 0x000b, 0x0023, 240, 32) + bytes(240 + 32)
b = b[:344] if len(b) >= 344 else b + bytes(344 - len(b))
b += struct.pack("<Q", 7) + bytes(64)
open(out, "wb").write(b)
PY
}
S=$tmp/state
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0
cred "$tmp/pcr.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
cred "$tmp/host.cred" 5a1c6a86df9d4096b1d5a65e0862f19a 0
cred "$tmp/null.cred" 058469daf6f54324800549da0f8ea2fb 0
rec "$S" good 2 "$tmp/ok.cred"; rec "$S" pcr 2 "$tmp/pcr.cred"; rec "$S" host 2 "$tmp/host.cred"; rec "$S" nul 2 "$tmp/null.cred"; rec "$S" plain 1 "$tmp/ok.cred"
# shellcheck source=e2e/vm/cred-lib.sh
source "$E/vm/cred-lib.sh"
rd() { VM_STATE_DIR=$S VM_CRED_DIR=${RD_DIR:-$E/vm} VM_SYSTEMD_VERSION=${RD_VER:-259} vm_read_credential "$1" 2> "$tmp/rderr" > "$tmp/rdout"; }
rd good || bad "reader: a TPM-bound credential fails: $(cat "$tmp/rderr")"
rd pcr && bad "reader: a nonzero PCR mask passes"; grep -q 'mask' "$tmp/rderr" || bad "reader: the nonzero mask reason is not in the message: $(cat "$tmp/rderr")"
rd host && bad "reader: a host-only credential passes"; grep -q 'host' "$tmp/rderr" || bad "reader: the host-only reason is not in the message"
rd nul && bad "reader: a null-key credential passes"; grep -q 'null' "$tmp/rderr" || bad "reader: the null reason is not in the message"
rd plain && bad "reader: a record of kind tpm passes"; grep -q 'not encrypted-tpm' "$tmp/rderr" || bad "reader: the kind reason is not in the message"
rd absent && bad "reader: a key without a record passes"
RD_VER=258 rd good && bad "reader: an unsupported systemd version passes"
mkdir "$tmp/nr-dir"; cp "$E/vm/credrec.py" "$tmp/nr-dir/"
RD_DIR=$tmp/nr-dir rd good && bad "reader: a reader that is missing passes"
printf 'import sys\nsys.exit(2)\n' > "$tmp/nr-dir/credread.py"
RD_DIR=$tmp/nr-dir rd good && bad "reader: a reader that exits 2 passes"
printf 'import sys\nsys.exit(0)\n' > "$tmp/nr-dir/credread.py"
RD_DIR=$tmp/nr-dir rd good || bad "reader: a stub reader that exits 0 fails"
# the calls: the case script runs the helper on each key; a copy whose lacking path skips it fails the call check
reader_called() { grep -v '^[[:space:]]*#' "$1" | grep -q 'vm_read_credential "\$id"'; }
reader_called "$E/tpmkind-run.sh" || bad "tpmkind-run.sh does not call vm_read_credential on its keys"
sed 's/vm_read_credential "\$id"/true/' "$E/tpmkind-run.sh" > "$tmp/nr-run.sh"
reader_called "$tmp/nr-run.sh" && bad "the control copy without the reader call passes the call check"
grep -q 'read_creds=1' "$E/tpmkind-run.sh" && grep -q 'lacking) judge_mode=lacking read_creds=1' "$E/tpmkind-run.sh" || bad "tpmkind-run.sh does not read the credentials in the lacking mode"
grep -q 'TK_READ' "$E/tpmkind-user.sh" || bad "tpmkind-user.sh does not wait for the reader before the deletes"

exit "$fail"
