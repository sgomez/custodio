#!/usr/bin/env bash
# F142: the judgements of e2e/upgradem3.py on good and bad evidence, without a container: a seed with no old files or with half a pair, an old file left, the old content kept under
# another name, a file named like the old format under any uid, a listed purged key through the API or the CLI, a listing that failed, a missing, extra, duplicated or wrong-owner purge entry,
# a purge entry with a caller, and a reimport that failed or listed an id under the wrong owner.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-m3-judge: $*" >&2; fail=1; }
um3() { python3 -I "$ROOT/e2e/upgradem3.py" "$@"; }
# --- the judgements of upgradem3.py
T=$tmp/j
mkdir -p "$T"
h() { printf '%064d' "$1"; }
printf '1000/rsa1\t%s\n1000/rsa1-cert\t%s\n1000/ec1\t%s\n1000/ec1-cert\t%s\n4711/rsa1\t%s\n4711/rsa1-cert\t%s\n4711/bobonly\t%s\n4711/bobonly-cert\t%s\n' \
    "$(h 1)" "$(h 2)" "$(h 3)" "$(h 4)" "$(h 5)" "$(h 6)" "$(h 7)" "$(h 8)" > "$T/before"
: > "$T/after"
printf '1000/other\t%s\n' "$(h 9)" > "$T/after-other"
ok() { # WHAT ARGS...: the judgement prints nothing
    local what=$1 out
    shift
    out=$(um3 "$@" 2>&1) || bad "$what: the judgement crashed: $out"
    [ -z "$out" ] || bad "$what: good evidence refused: $out"
}
refuses() { # WHAT PATTERN ARGS...: the judgement names the problem
    local what=$1 pat=$2 out
    shift 2
    out=$(um3 "$@" 2>&1) || true
    grep -q -- "$pat" <<< "$out" || bad "$what: not refused with '$pat': $out"
}
ok "seeded" seeded 1000 4711 "$T/before"
ok "purged" purged 1000 4711 "$T/before" "$T/after"
ok "purged, another file after" purged 1000 4711 "$T/before" "$T/after-other"
# a seed with no old files, or with a missing one of the pair
: > "$T/empty"
refuses "empty seed" 'is not there before' seeded 1000 4711 "$T/empty"
grep -v '4711/bobonly-cert' "$T/before" > "$T/before-short"
refuses "missing cert file" '4711/bobonly-cert is not there' seeded 1000 4711 "$T/before-short"
refuses "nothing to purge" 'nothing to purge' purged 1000 4711 "$T/empty" "$T/after"
# an old file left
grep '1000/ec1' "$T/before" > "$T/left"
refuses "old file left" 'old file 1000/ec1 is still there' purged 1000 4711 "$T/before" "$T/left"
# the old content kept under another name
printf 'moved/x\t%s\n' "$(h 3)" > "$T/moved"
refuses "old content moved" 'holds the content of an old file' purged 1000 4711 "$T/before" "$T/moved"
# a file of the old format under another uid directory
printf '2000/rsa1\t%s\n' "$(h 11)" > "$T/otheruid"
refuses "old name under another uid" 'named like a file of the old format' purged 1000 4711 "$T/before" "$T/otheruid"
printf '1000/ec1-cert\t%s\n' "$(h 12)" > "$T/certname"
refuses "cert name" 'named like a file of the old format' purged 1000 4711 "$T/before" "$T/certname"
refuses "unreadable snapshot" 'cannot be read' purged 1000 4711 "$T/before" "$T/none"
# the listings
mk_list() { # DIR: both accounts, API and CLI, empty and succeeded
    mkdir -p "$1"
    for u in alice bob; do for e in api cli; do : > "$1/$u.$e"; echo 0 > "$1/$u.$e.rc"; done; done
}
mk_list "$T/empty-lists"
ok "empty" empty "$T/empty-lists"
cp -r "$T/empty-lists" "$T/listed-api"
printf 'rsa1\trsa2048\ttpm\n' > "$T/listed-api/alice.api"
refuses "listed through the API" "alice is shown 'rsa1' (a purged key)" empty "$T/listed-api"
cp -r "$T/empty-lists" "$T/listed-cli"
printf 'id: bobonly\n  type: rsa2048\n' > "$T/listed-cli/bob.cli"
refuses "listed through the CLI" "bob.cli: bob is shown 'bobonly'" empty "$T/listed-cli"
cp -r "$T/empty-lists" "$T/err"
echo 1 > "$T/err/alice.cli.rc"
refuses "an error is not empty" 'alice.cli.rc: the listing did not succeed' empty "$T/err"
rm "$T/err/bob.api"
refuses "missing listing" 'bob.api: missing' empty "$T/err"
# the journal
entry() { printf '{"CUSTODIO_OPERATION":"purge","CUSTODIO_OUTCOME":"purged","CUSTODIO_OWNER_UID":"%s","CUSTODIO_KEY_ID":"%s"%s}\n' "$1" "$2" "${3:-}"; }
{ entry 1000 rsa1; entry 1000 ec1; entry 4711 rsa1; entry 4711 bobonly; echo '{"CUSTODIO_OPERATION":"sign","CUSTODIO_KEY_ID":"rsa1"}'; echo '{"MESSAGE":"started"}'; } > "$T/j-good"
ok "journal" journal 1000 4711 "$T/j-good"
{ entry 1000 rsa1; entry 1000 ec1; entry 4711 rsa1; } > "$T/j-missing"
refuses "missing entry" 'owner 4711 key bobonly: 0 purge entries, expected 1' journal 1000 4711 "$T/j-missing"
{ cat "$T/j-good"; entry 1000 rsa1; } > "$T/j-dup"
refuses "duplicated entry" 'owner 1000 key rsa1: 2 purge entries, expected 1' journal 1000 4711 "$T/j-dup"
{ cat "$T/j-good"; entry 1000 other; } > "$T/j-extra"
refuses "extra entry" 'owner 1000 key other: 1 purge entries, expected 0' journal 1000 4711 "$T/j-extra"
{ entry 1000 rsa1; entry 1000 ec1; entry 1000 rsa1; entry 4711 bobonly; } > "$T/j-owner"
refuses "wrong owner" 'owner 4711 key rsa1: 0 purge entries, expected 1' journal 1000 4711 "$T/j-owner"
{ entry 1000 rsa1 ',"CUSTODIO_UID":"0"'; entry 1000 ec1; entry 4711 rsa1; entry 4711 bobonly; } > "$T/j-caller"
refuses "a caller" 'carries a caller' journal 1000 4711 "$T/j-caller"
sed 's/"purged"/"failed"/' "$T/j-good" > "$T/j-outcome"
refuses "outcome" "has outcome 'failed'" journal 1000 4711 "$T/j-outcome"
{ cat "$T/j-good"; echo 'not json'; } > "$T/j-junk"
refuses "junk line" 'not JSON' journal 1000 4711 "$T/j-junk"
: > "$T/j-none"
refuses "no purge entry at all" '0 purge entries' journal 1000 4711 "$T/j-none"
if um3 journal 1000 1000 "$T/j-good" > /dev/null 2>&1; then bad "the same uid for both accounts passed"; fi
# the reimport
mk_reimp() { # DIR
    mk_list "$1"
    mkdir -p "$1/import"
    for k in alice-rsa1 alice-ec1 bob-rsa1 bob-bobonly; do echo 0 > "$1/import/$k.rc"; done
    echo 2 > "$1/import/alice.requests"; echo 2 > "$1/import/bob.requests"
    printf 'ec1\tecdsa-p256\ttpm\nrsa1\trsa2048\ttpm\n' > "$1/alice.api"
    printf 'id: ec1\n  type: x\nid: rsa1\n  type: y\n' > "$1/alice.cli"
    printf 'bobonly\trsa2048\ttpm\nrsa1\trsa2048\ttpm\n' > "$1/bob.api"
    printf 'id: bobonly\nid: rsa1\n' > "$1/bob.cli"
}
mk_reimp "$T/re"
ok "reimport" reimport 1000 4711 "$T/re"
cp -r "$T/re" "$T/re-fail"
echo 1 > "$T/re-fail/import/bob-rsa1.rc"
refuses "a failed import" "import of bob's rsa1 did not succeed" reimport 1000 4711 "$T/re-fail"
cp -r "$T/re" "$T/re-missing"
printf 'rsa1\trsa2048\ttpm\n' > "$T/re-missing/alice.api"
refuses "an id not listed" "alice lists \['rsa1'\], expected \['ec1', 'rsa1'\]" reimport 1000 4711 "$T/re-missing"
cp -r "$T/re" "$T/re-swapped"
cp "$T/re/bob.cli" "$T/re-swapped/alice.cli"
refuses "listed under the wrong owner" 'alice lists' reimport 1000 4711 "$T/re-swapped"
cp -r "$T/re" "$T/re-norc"
rm "$T/re-norc/import/alice-ec1.rc"
refuses "no status of an import" "import of alice's ec1 did not succeed" reimport 1000 4711 "$T/re-norc"
cp -r "$T/re" "$T/re-nopolkit"
echo 0 > "$T/re-nopolkit/import/alice.requests"
refuses "an import without polkit" "polkit saw '0' requests for alice's imports, expected 2" reimport 1000 4711 "$T/re-nopolkit"
cp -r "$T/re" "$T/re-noreq"
rm "$T/re-noreq/import/bob.requests"
refuses "no request count" "polkit saw None requests for bob" reimport 1000 4711 "$T/re-noreq"
if um3 bogus > /dev/null 2>&1; then bad "a bad subcommand passed"; fi


exit "$fail"
