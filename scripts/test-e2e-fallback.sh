#!/usr/bin/env bash
# F138: container-free checks of the fallback-* cases: the judgements (e2e/fallback.py) accept the output of `custodio import` and `custodio list` for kind encrypted-host and
# reject each bad one. NOT checked here: a real run
# (`E2E_TPM=none just e2e-cases debian13 'fallback-*'`).
# shellcheck disable=SC2086,SC2015 # the ids are words; `A && B || bad` is a check, not an if-then-else
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-fallback: $*" >&2; fail=1; }
J="python3 -I $ROOT/e2e/fallback.py"

HOST_TEXT="Storage: encrypted-host. This key is weaker than a TPM key: this machine has no TPM, so the key is a file encrypted with the host key. Root, and anyone with a copy of /var/lib, can use it."
REMIND=$'Now delete the original file: it still holds your private key.\n  shred -u /tmp/k.p12   (or remove it with your file manager and empty the trash)'
imp() { printf "Imported key '%s' (%s).\n%s\n%s\n" "$1" "$2" "$3" "$REMIND"; }
imp fb-rsa rsa2048 "$HOST_TEXT" > "$tmp/good-import"
printf 'fb-rsa\trsa2048\tencrypted-host\nfb-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/good-api"
printf 'id: fb-rsa\n  type: rsa2048\n  kind: encrypted-host\n\nid: fb-ec\n  type: ecdsa-p256\n  kind: encrypted-host\n' > "$tmp/good-cli"

accepts() { local out; out=$($J "$@") || { bad "judgement failed: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
rejects() { # NAME ARGS...: the judgement prints a problem
    local n=$1 out; shift
    out=$($J "$@") || true
    [ -n "$out" ] || bad "bad evidence accepted: $n"
}
accepts import "$tmp/good-import" fb-rsa rsa2048
accepts why "$tmp/good-import"
accepts api "$tmp/good-api" fb-rsa:rsa2048 fb-ec:ecdsa-p256
accepts cli "$tmp/good-cli" fb-rsa:rsa2048 fb-ec:ecdsa-p256

TPM_TEXT="Storage: tpm. The key is in the TPM and cannot be copied out of it."
ETPM_TEXT="Storage: encrypted-tpm. This key is weaker than a TPM key: the TPM of this machine lacks a capability the key type needs, so the key is a file encrypted with a key bound to this TPM."
imp fb-rsa rsa2048 "$TPM_TEXT" > "$tmp/b-tpm"
imp fb-rsa rsa2048 "$ETPM_TEXT" > "$tmp/b-etpm"
printf "Imported key 'fb-rsa' (rsa2048).\n%s\n" "$REMIND" > "$tmp/b-nostorage"
imp fb-rsa rsa2048 "$HOST_TEXT"$'\n'"$HOST_TEXT" > "$tmp/b-two"
imp fb-rsa rsa2048 "Storage: encrypted-host. This machine has no TPM, so the key is a file encrypted with the host key." > "$tmp/b-noweaker"
imp fb-rsa rsa2048 "Storage: encrypted-host. This key is weaker than a TPM key: it is a file encrypted with the host key." > "$tmp/b-noreason"
imp fb-rsa rsa2048 "Storage: encrypted-host-x. This key is weaker than a TPM key: this machine has no TPM." > "$tmp/b-prefix"
imp fb-other rsa2048 "$HOST_TEXT" > "$tmp/b-wrongid"
imp fb-rsa rsa2048 "$HOST_TEXT" | sed 's/^Imported.*/Imported key '"'fb-rsa'"' (ecdsa-p256)./' > "$tmp/b-wrongtype"
rejects kind-tpm import "$tmp/b-tpm" fb-rsa rsa2048
rejects kind-encrypted-tpm import "$tmp/b-etpm" fb-rsa rsa2048
rejects no-storage-line import "$tmp/b-nostorage" fb-rsa rsa2048
rejects two-storage-lines import "$tmp/b-two" fb-rsa rsa2048
rejects kind-prefix import "$tmp/b-prefix" fb-rsa rsa2048
rejects wrong-id import "$tmp/b-wrongid" fb-rsa rsa2048
rejects wrong-type import "$tmp/b-wrongtype" fb-rsa rsa2048
rejects why-kind-tpm why "$tmp/b-tpm"
rejects why-no-storage why "$tmp/b-nostorage"
rejects why-two-lines why "$tmp/b-two"
rejects why-no-weaker why "$tmp/b-noweaker"
rejects why-no-reason why "$tmp/b-noreason"
rejects why-one-bad-of-two why "$tmp/good-import" "$tmp/b-noweaker"
# the explanation is judged apart from the kind line: text lacking the explanation passes `import` and fails `why`
[ -z "$($J import "$tmp/b-noweaker" fb-rsa rsa2048)" ] || bad "the import judgement also judges the explanation"

for k in tpm encrypted-tpm unknown ''; do
    printf 'fb-rsa\trsa2048\t%s\nfb-ec\tecdsa-p256\tencrypted-host\n' "$k" > "$tmp/b-api"
    rejects "api-kind-$k" api "$tmp/b-api" fb-rsa:rsa2048 fb-ec:ecdsa-p256
    printf 'id: fb-rsa\n  type: rsa2048\n  kind: %s\n\nid: fb-ec\n  type: ecdsa-p256\n  kind: encrypted-host\n' "$k" > "$tmp/b-cli"
    rejects "cli-kind-$k" cli "$tmp/b-cli" fb-rsa:rsa2048 fb-ec:ecdsa-p256
done
printf 'fb-rsa\trsa2048\tencrypted-host\n' > "$tmp/b-api-missing"
rejects api-missing-row api "$tmp/b-api-missing" fb-rsa:rsa2048 fb-ec:ecdsa-p256
printf 'fb-rsa\trsa2048\tencrypted-host\nfb-rsa\trsa2048\tencrypted-host\nfb-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/b-api-two"
rejects api-two-rows api "$tmp/b-api-two" fb-rsa:rsa2048 fb-ec:ecdsa-p256
printf 'fb-rsa\tecdsa-p256\tencrypted-host\nfb-ec\tecdsa-p256\tencrypted-host\n' > "$tmp/b-api-type"
rejects api-wrong-type api "$tmp/b-api-type" fb-rsa:rsa2048 fb-ec:ecdsa-p256
printf 'id: fb-rsa\n  type: rsa2048\n  kind: encrypted-host\n' > "$tmp/b-cli-missing"
rejects cli-missing-row cli "$tmp/b-cli-missing" fb-rsa:rsa2048 fb-ec:ecdsa-p256
printf 'id: fb-rsa\n  type: rsa2048\n\nid: fb-ec\n  type: ecdsa-p256\n  kind: encrypted-host\n' > "$tmp/b-cli-nokind"
rejects cli-row-without-kind cli "$tmp/b-cli-nokind" fb-rsa:rsa2048 fb-ec:ecdsa-p256
# a kind on another key's row does not count
printf 'id: fb-rsa\n  type: rsa2048\n\nid: other\n  kind: encrypted-host\n\nid: fb-ec\n  type: ecdsa-p256\n  kind: encrypted-host\n' > "$tmp/b-cli-other"
rejects cli-kind-on-other-row cli "$tmp/b-cli-other" fb-rsa:rsa2048 fb-ec:ecdsa-p256

# ---- F161: a VM run (fallback.py --mode, fallback-run.sh with E2E_VM=1): the tpmbound cases run in both modes and are judged
VJ() { python3 -I "$ROOT/e2e/fallback.py" "$@"; }
VETPM="Storage: encrypted-tpm. This key is weaker than a TPM key: the TPM of this machine lacks a capability the key type needs, so the key is a file encrypted with a key bound to this TPM."
vmset() { # DIR KIND TEXT [RSA-KIND]: the files of the step; the RSA key has RSA-KIND (default KIND)
    local d=$1 k=$2 t=$3 rk=${4:-$2}
    mkdir -p "$d"
    imp fb-rsa rsa2048 "$t" > "$d/import-rsa.out"
    imp fb-ec ecdsa-p256 "$t" > "$d/import-ec.out"
    printf 'fb-rsa\trsa2048\t%s\nfb-ec\tecdsa-p256\t%s\n' "$rk" "$k" > "$d/api.out"
    printf 'id: fb-rsa\n  type: rsa2048\n  kind: %s\n\nid: fb-ec\n  type: ecdsa-p256\n  kind: %s\n' "$rk" "$k" > "$d/cli.out"
    : > "$d/api-after.out"
}
vmjudge() { # MODE DIR: all four judgements; prints the problems
    VJ --mode "$1" import "$2/import-rsa.out" fb-rsa rsa2048
    VJ --mode "$1" import "$2/import-ec.out" fb-ec ecdsa-p256
    VJ --mode "$1" api "$2/api.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256
    VJ --mode "$1" why "$2/import-rsa.out" "$2/import-ec.out"
    VJ --mode "$1" cli "$2/cli.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256
}
vmset "$tmp/vl" encrypted-tpm "$VETPM"
vmset "$tmp/vf" tpm "$TPM_TEXT"
[ -z "$(vmjudge lacking "$tmp/vl")" ] || bad "lacking: good evidence rejected: $(vmjudge lacking "$tmp/vl")"
[ -z "$(vmjudge full "$tmp/vf")" ] || bad "full: good evidence rejected: $(vmjudge full "$tmp/vf")"
[ -n "$(vmjudge lacking "$tmp/vf")" ] || bad "lacking accepts the full evidence"
[ -n "$(vmjudge full "$tmp/vl")" ] || bad "full accepts the lacking evidence"
[ -z "$(VJ import "$tmp/good-import" fb-rsa rsa2048)" ] || bad "the container judgement changed"
# lacking: each wrong place is rejected, for the RSA key and for P-256 apart
for w in tpm encrypted-host; do
    vmset "$tmp/x1" encrypted-tpm "$VETPM" "$w"; [ -n "$(VJ --mode lacking api "$tmp/x1/api.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)" ] || bad "lacking: RSA $w in the API accepted"
    [ -n "$(VJ --mode lacking cli "$tmp/x1/cli.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)" ] || bad "lacking: RSA $w in the CLI list accepted"
    vmset "$tmp/x2" "$w" "$VETPM" encrypted-tpm; [ -n "$(VJ --mode lacking api "$tmp/x2/api.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)" ] || bad "lacking: P-256 $w in the API accepted"
    [ -n "$(VJ --mode lacking cli "$tmp/x2/cli.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)" ] || bad "lacking: P-256 $w in the CLI list accepted"
done
imp fb-rsa rsa2048 "$TPM_TEXT" > "$tmp/x3"; [ -n "$(VJ --mode lacking import "$tmp/x3" fb-rsa rsa2048)" ] || bad "lacking: RSA tpm in the import text accepted"
imp fb-ec ecdsa-p256 "$TPM_TEXT" > "$tmp/x3"; [ -n "$(VJ --mode lacking import "$tmp/x3" fb-ec ecdsa-p256)" ] || bad "lacking: P-256 tpm in the import text accepted"
imp fb-rsa rsa2048 "$HOST_TEXT" > "$tmp/x3"; [ -n "$(VJ --mode lacking import "$tmp/x3" fb-rsa rsa2048)" ] || bad "lacking: RSA encrypted-host in the import text accepted"
imp fb-rsa rsa2048 "Storage: encrypted-tpm. The key is in a file." > "$tmp/x4"; [ -n "$(VJ --mode lacking why "$tmp/x4")" ] || bad "lacking: a text without weaker accepted"
imp fb-rsa rsa2048 "Storage: encrypted-tpm. This key is weaker than a TPM key: it is a file." > "$tmp/x4"; [ -n "$(VJ --mode lacking why "$tmp/x4")" ] || bad "lacking: a text without the reason accepted"
# full: either key encrypted-tpm, or a weaker line
vmset "$tmp/x5" tpm "$TPM_TEXT" encrypted-tpm; [ -n "$(VJ --mode full api "$tmp/x5/api.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)" ] || bad "full: RSA encrypted-tpm accepted"
vmset "$tmp/x5" encrypted-tpm "$TPM_TEXT" tpm; [ -n "$(VJ --mode full api "$tmp/x5/api.out" fb-rsa:rsa2048 fb-ec:ecdsa-p256)" ] || bad "full: P-256 encrypted-tpm accepted"
imp fb-rsa rsa2048 "$TPM_TEXT"$'\nThis key is weaker than a TPM key.' > "$tmp/x6"; [ -n "$(VJ --mode full why "$tmp/x6")" ] || bad "full: a weaker line accepted"

# fallback-run.sh in a VM run, on fixtures: `su` is a stub that writes the evidence into the step's directory
vmrun() { # MODE EVIDENCE-DIR [STATE-DIR]: runs the VM branch; prints its output, exit status in the file $tmp/vmrc
    local m=$1 ev=$2 st=${3:-$tmp/state-none} work
    work=$(mktemp -d "$tmp/work.XXXX"); mkdir -p "$tmp/stub"
    cat > "$tmp/stub/su" <<STUB
#!/usr/bin/env bash
cp "$ev"/*.out "$work/fallback/"; [ -n "${STUB_NOIMPORTED:-}" ] || : > "$work/fallback/imported"
exit 0
STUB
    chmod +x "$tmp/stub/su"
    mkdir -p "$tmp/state-none"
    ( PATH=$tmp/stub:$PATH WORK=$work E2E_VM=1 E2E_TPM=$m VM_STATE_DIR=$st VM_CRED_DIR=${VM_CRED_DIR:-$ROOT/e2e/vm} VM_SYSTEMD_VERSION=259 E2E_SELECT_FILE=/nonexistent \
        bash "${RUN_COPY:-$ROOT/e2e/fallback-run.sh}" > "$tmp/vmout" 2>&1; echo $? > "$tmp/vmrc" ) || true
}
# shellcheck source=scripts/lib/e2e-vm-cred-fixtures.sh
source "$ROOT/scripts/lib/e2e-vm-cred-fixtures.sh"
cred "$tmp/ok.cred" ef4ac13679a9480ea7db68897f9f165d 0; cred "$tmp/pcr.cred" ef4ac13679a9480ea7db68897f9f165d 0x80
rec "$tmp/st-ok" fb-rsa 2 "$tmp/ok.cred"; rec "$tmp/st-ok" fb-ec 2 "$tmp/ok.cred"
rec "$tmp/st-pcr" fb-rsa 2 "$tmp/ok.cred"; rec "$tmp/st-pcr" fb-ec 2 "$tmp/pcr.cred"
vmrun lacking "$tmp/vl" "$tmp/st-ok"
[ "$(cat "$tmp/vmrc")" = 0 ] || bad "VM run lacking on good evidence fails: $(tail -5 "$tmp/vmout")"
[ "$(grep -c '^E2E-CASE run fallback-tpmbound-' "$tmp/vmout")" = 2 ] || bad "VM run lacking does not report both tpmbound cases run"
! grep -q 'E2E-CASE skipped' "$tmp/vmout" || bad "VM run lacking skips a case"
! grep -q 'fallback-host-' "$tmp/vmout" || bad "VM run lacking reports a host case"
vmrun swtpm "$tmp/vf"
[ "$(cat "$tmp/vmrc")" = 0 ] && [ "$(grep -c '^E2E-CASE run fallback-tpmbound-' "$tmp/vmout")" = 2 ] || bad "VM run full on good evidence does not report both tpmbound cases run"
vmrun lacking "$tmp/vf" "$tmp/st-ok"   # a wrong mode in one direction
{ [ "$(cat "$tmp/vmrc")" != 0 ] && ! grep -q '^E2E-CASE run' "$tmp/vmout"; } || bad "VM run lacking on tpm evidence passes or reports a case run"
vmrun swtpm "$tmp/vl"                   # and the other
{ [ "$(cat "$tmp/vmrc")" != 0 ] && ! grep -q '^E2E-CASE run' "$tmp/vmout"; } || bad "VM run full on encrypted-tpm evidence passes or reports a case run"
vmrun lacking "$tmp/vl" "$tmp/st-pcr"   # the reader fails on one key
[ "$(cat "$tmp/vmrc")" != 0 ] || bad "VM run lacking passes with a credential of a nonzero PCR mask"
grep -q 'fb-ec' "$tmp/vmout" || bad "VM run lacking: the reader failure does not name the key"
# alice never writes `imported`: the credentials are not read, so the run fails and says so
STUB_NOIMPORTED=1 vmrun lacking "$tmp/vl" "$tmp/st-ok"
{ [ "$(cat "$tmp/vmrc")" != 0 ] && grep -q 'the keys were never imported' "$tmp/vmout"; } || bad "VM run lacking passes when the keys were never imported"
# a control copy that reports the case without judging fails the run check
mkdir "$tmp/ctl"; cp "$ROOT"/e2e/fallback-run.sh "$ROOT"/e2e/fallback-cases.sh "$ROOT"/e2e/fallback.py "$ROOT"/e2e/tpmkind-lib.sh "$ROOT"/e2e/report.sh "$ROOT"/e2e/select.sh "$tmp/ctl/"
cp -r "$ROOT/e2e/vm" "$tmp/ctl/vm"
sed -i 's|^    judge fallback-tpmbound-cli-list .*|    case_run fallback-tpmbound-cli-list|' "$tmp/ctl/fallback-run.sh"
cp -r "$tmp/vl" "$tmp/vbadcli"; sed -i 's/kind: encrypted-tpm/kind: tpm/' "$tmp/vbadcli/cli.out"
vmrun lacking "$tmp/vbadcli" "$tmp/st-ok"
{ [ "$(cat "$tmp/vmrc")" != 0 ] && ! grep -q '^E2E-CASE run fallback-tpmbound-cli-list' "$tmp/vmout"; } || bad "VM run lacking passes or reports a case run on a wrong CLI list"
RUN_COPY=$tmp/ctl/fallback-run.sh vmrun lacking "$tmp/vbadcli" "$tmp/st-ok"
grep -q '^E2E-CASE run fallback-tpmbound-cli-list' "$tmp/vmout" || bad "the control copy that reports the CLI case unjudged does not report it run on a wrong CLI list"
exit "$fail"
