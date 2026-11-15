#!/usr/bin/env bash
# F142: the judgements of e2e/upgradem3.py (the purge of the old key files on upgrade), without a container: each accepts good evidence and refuses one fault.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-upgrade-purge-judge: $*" >&2; fail=1; }
um3() { python3 -I "$ROOT/e2e/upgradem3.py" "$@"; }
# --- the judgements of upgradem3.py
T=$tmp/j
mkdir -p "$T"
h() { printf '%064d' "$1"; }
printf '1000/rsa1\t%s\n1000/rsa1-cert\t%s\n1000/ec1\t%s\n1000/ec1-cert\t%s\n4711/rsa1\t%s\n4711/rsa1-cert\t%s\n4711/bobonly\t%s\n4711/bobonly-cert\t%s\n' \
    "$(h 1)" "$(h 2)" "$(h 3)" "$(h 4)" "$(h 5)" "$(h 6)" "$(h 7)" "$(h 8)" > "$T/before"
: > "$T/after"
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
: > "$T/empty"
refuses "empty seed" 'is not there before' seeded 1000 4711 "$T/empty"
# an old file left
grep '1000/ec1' "$T/before" > "$T/left"
refuses "old file left" 'old file 1000/ec1 is still there' purged 1000 4711 "$T/before" "$T/left"
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
# the journal
entry() { printf '{"CUSTODIO_OPERATION":"purge","CUSTODIO_OUTCOME":"purged","CUSTODIO_OWNER_UID":"%s","CUSTODIO_KEY_ID":"%s"%s}\n' "$1" "$2" "${3:-}"; }
{ entry 1000 rsa1; entry 1000 ec1; entry 4711 rsa1; entry 4711 bobonly; echo '{"CUSTODIO_OPERATION":"sign","CUSTODIO_KEY_ID":"rsa1"}'; echo '{"MESSAGE":"started"}'; } > "$T/j-good"
ok "journal" journal 1000 4711 "$T/j-good"
{ entry 1000 rsa1; entry 1000 ec1; entry 4711 rsa1; } > "$T/j-missing"
refuses "missing entry" 'owner 4711 key bobonly: 0 purge entries, expected 1' journal 1000 4711 "$T/j-missing"
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
exit "$fail"
