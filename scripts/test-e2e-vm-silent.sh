#!/usr/bin/env bash
# F161: container-free checks of the vm-silent-* cases (e2e/vm/silent.sh, silent-lib.sh, silent.py): the judgements over fixtures of the guest's evidence with a negative control for each
# fact. NOT checked here: a real guest (F168).
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
    printf "custodio: the credential service is unavailable; nothing was stored\n" > "$h/import.out"; echo 1 > "$h/import.rc"
    printf 'd /var/lib/custodio 700 4096\nf /var/lib/custodio/other.rec 600 120\nabc123  /var/lib/custodio/other.rec\n' > "$h/state-before"
    cp "$h/state-before" "$h/state-after"
    printf 'other\trsa2048\tencrypted-tpm\n' > "$h/list.out"
    printf 'other  rsa2048  encrypted-tpm  CN=o  2030-01-01\n' > "$h/cli-list.out"
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
ctl othererr vm-silent-import-fails 'echo "custodio: the TPM failed or cannot be used; nothing was stored" > hidden/import.out'
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
    ctl "left-cli-$k" vm-silent-no-key "printf '$ID  rsa2048  $k  CN=o  2030-01-01\n' >> hidden/cli-list.out"
done
ctl weaker-in-text vm-silent-no-key 'echo "Storage: encrypted-host." >> hidden/import.out'
ctl lists-empty vm-silent-no-key ': > hidden/list.out; : > hidden/cli-list.out'
ctl restored-fails vm-silent-restored-imports 'echo "custodio: the credential service is unavailable; nothing was stored" > restored/import.out'
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

[ "$fail" = 0 ] || exit 1
echo "test-e2e-vm-silent: ok"
