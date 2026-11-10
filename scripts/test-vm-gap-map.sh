#!/usr/bin/env bash
# F168: e2e/vm/gap-map.sh, the reader of the gap table of contracts/F168.md. Fixtures are temp files, never edited copies of the real contract.
# Each negative control is one change to a good input; the same check must fail on it.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GM=$ROOT/e2e/vm/gap-map.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-vm-gap-map: $*" >&2; fail=1; }

# the real table against the real lists
bash "$GM" > /dev/null 2>&1 || bad "the real contract does not pass against the real lists"

# fixtures: table, case list, skip list, logs
table() { # table FILE [grep -v pattern]: the real table, minus one row
    { echo '```gap-table'; awk '/^```gap-table$/{on=1;next} /^```$/{on=0} on' "$ROOT/contracts/F168.md" | grep -v "${2:-^\$}" || true; echo '```'; } > "$1"
}
table "$tmp/good.md"
cases=$tmp/cases.list; skip=$tmp/skip.list
grep -v '^[[:space:]]*\(#\|$\)' "$ROOT/e2e/vm/cases.list" > "$cases"
: > "$skip"
mklog() { # mklog FILE reader(0|1): every mapped case once, the rest of the list run too
    { sed "s/^/E2E-CASE run /" "$cases"; [ "$2" = 1 ] && echo "reader: key sg-rsa: ok"; echo "check-cases: 38 cases accounted for"; } > "$1"
}
run() { GAP_CONTRACT=$1 GAP_CASES=${GAP_CASES:-$cases} GAP_SKIP=${GAP_SKIP:-$skip} bash "$GM" "${@:2}" > "$tmp/out" 2>&1; }
ok() { run "$@" || bad "good input fails ($*): $(tail -n 3 "$tmp/out")"; }
ko() { local why=$1; shift; if run "$@"; then bad "control passes: $why"; elif ! grep -q "$why" "$tmp/out"; then bad "control fails for another reason ($why): $(cat "$tmp/out")"; fi; }

mkdir -p "$tmp/vm"; mklog "$tmp/vm/vm.lacking.log" 1; mklog "$tmp/vm/vm.full.log" 0
ok "$tmp/good.md"
ok "$tmp/good.md" "$tmp/vm/vm.lacking.log"
ok "$tmp/good.md" "$tmp/vm/vm.full.log"

# static controls
for g in F134 F135 F137 F138 F140 F141; do
    table "$tmp/nogap.md" "^$g "
    ko "no row for the gap $g\|no row for RSA-PSS" "$tmp/nogap.md"
done
table "$tmp/nopss.md" '^F134 RSA-PSS'; ko "RSA-PSS" "$tmp/nopss.md"
sed 's/ noplain-ec / noplain-nonexistent /' "$tmp/good.md" > "$tmp/unk.md"; cmp -s "$tmp/good.md" "$tmp/unk.md" && bad "unknown-case fixture equals the good one"
ko "noplain-nonexistent is not in the VM case list" "$tmp/unk.md"
awk 'NR==2{sub(/ \|.*/," | ")} {print}' "$tmp/good.md" > "$tmp/empty.md"; ko "malformed row\|maps no case" "$tmp/empty.md"
echo 'noplain-ec: a reason' > "$tmp/skip-ec"; GAP_SKIP=$tmp/skip-ec ko "noplain-ec is on the skip list" "$tmp/good.md"
grep -v '^noplain-ec$' "$cases" > "$tmp/cases-no"; GAP_CASES=$tmp/cases-no ko "noplain-ec is not in the VM case list" "$tmp/good.md"
echo "no table here" > "$tmp/notable.md"; ko "no gap-table" "$tmp/notable.md"

# log controls
mkdir -p "$tmp/c"
grep -v 'run sign-rsa-pkcs$' "$tmp/vm/vm.lacking.log" > "$tmp/c/vm.lacking.log"; ko "sign-rsa-pkcs is reported run 0 times" "$tmp/good.md" "$tmp/c/vm.lacking.log"
{ cat "$tmp/vm/vm.lacking.log"; echo "E2E-CASE run sign-rsa-pkcs"; } > "$tmp/c/vm.lacking.log"; ko "sign-rsa-pkcs is reported run 2 times" "$tmp/good.md" "$tmp/c/vm.lacking.log"
sed 's/^E2E-CASE run pcr-restarted-signs$/E2E-CASE skipped pcr-restarted-signs/' "$tmp/vm/vm.lacking.log" > "$tmp/c/vm.lacking.log"; ko "pcr-restarted-signs is reported" "$tmp/good.md" "$tmp/c/vm.lacking.log"
grep -v '^reader: key' "$tmp/vm/vm.lacking.log" > "$tmp/c/vm.lacking.log"; ko "no 'reader: key' line" "$tmp/good.md" "$tmp/c/vm.lacking.log"
cp "$tmp/vm/vm.lacking.log" "$tmp/c/vm.full.log"; ko "the full log has" "$tmp/good.md" "$tmp/c/vm.full.log"
ko "no such file" "$tmp/good.md" "$tmp/c/none.log"
cp "$tmp/vm/vm.full.log" "$tmp/c/odd.log"; ko "is not full or lacking" "$tmp/good.md" "$tmp/c/odd.log"

[ "$fail" = 0 ] && echo "test-vm-gap-map: ok"
exit "$fail"
