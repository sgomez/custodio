#!/usr/bin/env bash
# F144: container-free checks of the journal-kind-* cases: the placement (debian13 list, group, not in e2e/cases.list, no skip-list line), the accounting (a skip refused in every mode),
# the extractor (the queries are the document's, only the placeholders replaced; a changed document fails the extraction) and the judgements of e2e/journalkind.py on good and bad
# records (a missing entry, a stray entry, a forged entry returned, a wrong kind or cause, a purge count that is not one per key, another owner's entry in an owner query, a successful
# signature in a cause query, an entry from before the cursor, a caller on a purge entry, a vacuous control, a secret). NOT checked here: a real run (`just e2e-cases debian13
# 'journal-kind-*'` in swtpm, lacking and none).
# shellcheck disable=SC2086 # the ids are words
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-journalkind: $*" >&2; fail=1; }
D=$ROOT/e2e/targets/debian13
ids="journal-kind-import journal-kind-purge journal-kind-owner journal-kind-key-lost journal-kind-temporarily-unavailable"
jk() { python3 -I "$ROOT/e2e/journalkind.py" "$@"; }

# placement
for id in $ids; do
    grep -qx "$id" "$D/cases.list" || bad "$id is not in $D/cases.list"
    ! grep -q "^$id:" "$D/skip.list" || bad "$id is on the skip list: it runs in every mode"
    ! grep -qx "$id" "$ROOT/e2e/cases.list" || bad "$id is in e2e/cases.list (every target)"
done
[ "$(grep -c '^journal-kind-' "$D/cases.list")" = 5 ] || bad "debian13 cases.list lists other journal-kind cases than the five"
# shellcheck source=e2e/select.sh
source "$ROOT/e2e/select.sh"
for id in $ids journal-kind-x; do [ "$(case_group "$id")" = journalkind ] || bad "case_group $id is '$(case_group "$id")', expected journalkind"; done
for id in journal-entries journal-catalog journal-ops-sign journal-ops-queries tpm-slots-import; do [ "$(case_group "$id")" != journalkind ] || bad "case_group $id is journalkind"; done
# shellcheck source=e2e/journalkind-cases.sh
source "$ROOT/e2e/journalkind-cases.sh"
[ "$(printf '%s\n' $JOURNALKIND_CASES | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "JOURNALKIND_CASES differ from the listed cases"
[ "$(jk cases | sort)" = "$(printf '%s\n' $ids | sort)" ] || bad "journalkind.py cases differ from the listed cases"

# accounting: a run of all five is accepted in every mode; a skip is refused in every mode, also with a skip list that names it
printf '%s\n' $ids > "$tmp/cases"
for id in $ids; do echo "E2E-CASE run $id"; done > "$tmp/out-run"
{ echo "E2E-CASE skipped journal-kind-import"; tail -n 4 "$tmp/out-run"; } > "$tmp/out-skip"
sed -n 's/^E2E-CASE skipped \(.*\)/\1: not applicable/p' "$tmp/out-skip" > "$tmp/skip-named"
check() { CHECK_TPM_MODE=$1 bash "$ROOT/e2e/check-cases.sh" check "$tmp/cases" "$2" "$3" > /dev/null 2>&1; }
for m in swtpm lacking none; do
    check $m "$D/skip.list" "$tmp/out-run" || bad "mode $m: run cases are refused"
    ! check $m "$D/skip.list" "$tmp/out-skip" || bad "mode $m: a skipped case is accepted"
    ! check $m "$tmp/skip-named" "$tmp/out-skip" || bad "mode $m: a skip list naming the case lets the skip through"
done

expect_ok() { local out; out=$("$@" 2>&1) || { bad "failed to run: $*"; return; }; [ -z "$out" ] || bad "good evidence rejected ($*): $out"; }
expect_bad() { local out; out=$("$@" 2>&1) || true; [ -n "$out" ] || bad "bad evidence accepted ($*)"; }

# the extractor, over the real document and over edited copies
DOC=$ROOT/docs/audit.md
jk extract "$DOC" 998 1000 1001 tpm encrypted-tpm encrypted-host > "$tmp/q" 2> "$tmp/q.err" || bad "the extractor fails on docs/audit.md: $(cat "$tmp/q.err")"
[ "$(wc -l < "$tmp/q")" = 8 ] || bad "the extractor does not give eight queries"
U="_SYSTEMD_UNIT=custodio.service _UID=998"
q() { awk -F'\t' -v n="$1" '$1 == n { print $2 }' "$tmp/q"; }
[ "$(q kind:tpm)" = "$U CUSTODIO_OPERATION=import CUSTODIO_STORAGE_KIND=tpm" ] || bad "kind:tpm is '$(q kind:tpm)'"
[ "$(q kind:encrypted-host)" = "$U CUSTODIO_OPERATION=import CUSTODIO_STORAGE_KIND=encrypted-host" ] || bad "kind:encrypted-host is '$(q kind:encrypted-host)'"
[ "$(q purge)" = "$U CUSTODIO_OPERATION=purge" ] || bad "purge is '$(q purge)'"
[ "$(q owner:1000)" = "$U CUSTODIO_OPERATION=purge CUSTODIO_OWNER_UID=1000" ] || bad "owner:1000 is '$(q owner:1000)'"
[ "$(q owner:1001)" = "$U CUSTODIO_OPERATION=purge CUSTODIO_OWNER_UID=1001" ] || bad "owner:1001 is '$(q owner:1001)'"
[ "$(q key-lost)" = "$U CUSTODIO_OPERATION=sign CUSTODIO_CAUSE=key_lost" ] || bad "key-lost is '$(q key-lost)'"
[ "$(q temporarily-unavailable)" = "$U CUSTODIO_OPERATION=sign CUSTODIO_CAUSE=temporarily_unavailable" ] || bad "temporarily-unavailable is '$(q temporarily-unavailable)'"
# a document with a changed or missing query fails, it is not skipped
# shellcheck disable=SC2016 # sed programs; one holds a literal $(
for edit in 's/CUSTODIO_OPERATION=import CUSTODIO_STORAGE_KIND=encrypted-host/CUSTODIO_OPERATION=import CUSTODIO_STORAGE_KIND=encrypted-host CUSTODIO_UID=1/' \
    's/CUSTODIO_OPERATION=purge CUSTODIO_OWNER_UID=1000/CUSTODIO_OPERATION=purge CUSTODIO_OWNER=1000/' \
    's/CUSTODIO_CAUSE=key_lost/CUSTODIO_CAUSE=key_gone/' \
    's/CUSTODIO_CAUSE=temporarily_unavailable/CUSTODIO_CAUSE=later/' \
    's/_SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_OPERATION=purge$/CUSTODIO_OPERATION=purge/' \
    's/^journalctl /journalctl-x /'; do
    sed "$edit" "$DOC" > "$tmp/doc-edit"
    cmp -s "$DOC" "$tmp/doc-edit" && bad "the edit '$edit' changed nothing"
    expect_bad jk extract "$tmp/doc-edit" 998 1000 1001 tpm encrypted-tpm encrypted-host
done
: > "$tmp/doc-empty"; expect_bad jk extract "$tmp/doc-empty" 998 1000 1001 tpm
expect_bad jk extract "$DOC" 998 1000 1001 weird
expect_bad jk extract "$DOC" x 1000 1001 tpm
expect_bad jk extract "$tmp/missing" 998 1000 1001 tpm

# rows
S=998
row() { # FILE CURSOR KEY OP OUTCOME KIND CAUSE OWNER [UNIT UID [CALLER]]: one journal row ('-' for a field the entry does not have)
    python3 -I - "$@" << 'PY'
import json, sys
f, cur, key, op, outcome, kind, cause, owner = sys.argv[1:9]
unit = sys.argv[9] if len(sys.argv) > 9 else "custodio.service"
uid = sys.argv[10] if len(sys.argv) > 10 else "998"
e = {"__CURSOR": cur, "_SYSTEMD_UNIT": unit, "_UID": uid, "CUSTODIO_KEY_ID": key, "CUSTODIO_OPERATION": op, "CUSTODIO_OUTCOME": outcome}
for name, v in (("CUSTODIO_STORAGE_KIND", kind), ("CUSTODIO_CAUSE", cause), ("CUSTODIO_OWNER_UID", owner)):
    if v != "-":
        e[name] = v
if len(sys.argv) > 11:
    e["CUSTODIO_UID"] = "1000"
with open(f, "a") as out:
    out.write(json.dumps(e) + "\n")
PY
}
t() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@"; }
W=$tmp/w
mkdir -p "$W"
# the window: two imports, an approved and a denied sign, one failed sign of each cause, four purges, a forged entry of each kind by root (no unit) and by another uid
: > "$W/window"; : > "$W/pre"
row "$W/pre" p1 old-key import stored tpm - -
row "$W/pre" p2 old-purge purge purged - - 1000
for k in jk-a jk-b; do row "$W/window" "i-$k" $k import stored tpm - -; done
row "$W/window" s1 jk-a sign signed tpm - -
row "$W/window" s2 jk-a sign denied tpm - -
row "$W/window" s3 jk-b sign signing_failed tpm key_lost -
row "$W/window" s4 jk-a sign signing_failed tpm temporarily_unavailable -
row "$W/window" u1 jk-old-a1 purge purged - - 1000
row "$W/window" u2 jk-old-a2 purge purged - - 1000
row "$W/window" u3 jk-old-b1 purge purged - - 1001
row "$W/window" u4 jk-old-b2 purge purged - - 1001
row "$W/window" f1 jk-forged-root import stored tpm - - session-1.scope 0
row "$W/window" f2 jk-forged-alice import stored tpm - - session-2.scope 1000
row "$W/window" f3 jk-forged-root purge purged - - 1000 session-1.scope 0
row "$W/window" f4 jk-forged-root sign signing_failed tpm key_lost - session-1.scope 0
FORGED=(--forged jk-forged-root --forged jk-forged-alice)
PRESENT=(--present jk-a:signed --present jk-a:denied)
mk() { # NAME ROWSPEC...: a result file from "CURSOR KEY OP OUTCOME KIND CAUSE OWNER [UNIT UID [CALLER]]" specs
    local name=$1 spec
    shift
    : > "$W/$name"
    for spec in "$@"; do
        # shellcheck disable=SC2086 # the spec is words
        row "$W/$name" $spec
    done
}
# shellcheck disable=SC2329 # run through expect_ok and expect_bad
chk() { jk check "$W/$1" "$W/pre" "$W/window" $S "$W/$2" "${@:3}"; }
t jk-a import stored tpm - - > "$W/e-kind"; t jk-b import stored tpm - - >> "$W/e-kind"
: > "$W/e-none"
mk r-kind "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -"
expect_ok chk r-kind e-kind "${FORGED[@]}"
mk r-none
expect_ok chk r-none e-none "${FORGED[@]}"                        # another kind: nothing
mk r-missing "i-jk-a jk-a import stored tpm - -"
expect_bad chk r-missing e-kind "${FORGED[@]}"                    # a missing entry
mk r-stray "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -" "x jk-c import stored tpm - -"
expect_bad chk r-stray e-kind "${FORGED[@]}"                      # a stray entry
mk r-twice "i-jk-a jk-a import stored tpm - -" "i-jk-a jk-a import stored tpm - -"
expect_bad chk r-twice e-kind "${FORGED[@]}"                      # one entry twice instead of two
mk r-forged "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -" "f1 jk-forged-root import stored tpm - - session-1.scope 0"
expect_bad chk r-forged e-kind "${FORGED[@]}"                     # a forged entry returned
mk r-forged2 "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -" "f2 jk-forged-alice import stored tpm - - session-2.scope 1000"
expect_bad chk r-forged2 e-kind "${FORGED[@]}"
mk r-otheruid "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - - custodio.service 1000"
expect_bad chk r-otheruid e-kind "${FORGED[@]}"                   # the unit's name with another user (the query must name the service user)
mk r-otherunit "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - - other.service 998"
expect_bad chk r-otherunit e-kind "${FORGED[@]}"
mk r-wrongkind "i-jk-a jk-a import stored encrypted-host - -" "i-jk-b jk-b import stored encrypted-host - -"
expect_bad chk r-wrongkind e-kind "${FORGED[@]}"                  # a wrong kind
mk r-kind-in-none "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -"
expect_bad chk r-kind-in-none e-none "${FORGED[@]}"               # the other kinds must return none
mk r-pre "i-jk-a jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -" "p1 old-key import stored tpm - -"
expect_bad chk r-pre e-kind "${FORGED[@]}"                        # an entry from before the cursor
mk r-pre-only "p1 jk-a import stored tpm - -" "i-jk-b jk-b import stored tpm - -"
expect_bad chk r-pre-only e-kind "${FORGED[@]}"                   # the right fields, but the entry is the one from before the cursor
expect_bad chk r-kind e-kind --forged jk-forged-nobody            # a control that finds no forged entry is vacuous
expect_bad chk r-kind e-kind --forged jk-a                        # a "forged" entry that is the service's is not one
expect_bad chk r-kind e-kind "${FORGED[@]}" --present jk-a:replaced # a successful call that is not in the window
expect_ok chk r-kind e-kind "${FORGED[@]}" "${PRESENT[@]}"
expect_bad chk r-missing-file e-kind
expect_bad jk check "$W/r-kind" "$W/pre" "$W/window" $S "$W/missing"
printf 'jk-a\timport\n' > "$W/e-short"; expect_bad chk r-kind e-short
expect_ok chk r-kind e-kind --secret not-in-any-entry
sed 's/forged by/e2e-password and/; s/"CUSTODIO_KEY_ID": "jk-forged-alice"/"MESSAGE": "e2e-password", "CUSTODIO_KEY_ID": "jk-forged-alice"/' "$W/window" > "$W/window-secret"
jk check "$W/r-kind" "$W/pre" "$W/window-secret" $S "$W/e-kind" "${FORGED[@]}" --secret e2e-password | grep -q secret || bad "a secret in the window is not reported"

# purge: one entry per key; the owner queries; no caller
{ t jk-old-a1 purge purged - - 1000; t jk-old-a2 purge purged - - 1000; t jk-old-b1 purge purged - - 1001; t jk-old-b2 purge purged - - 1001; } > "$W/e-purge"
head -n 2 "$W/e-purge" > "$W/e-own-a"; tail -n 2 "$W/e-purge" > "$W/e-own-b"
mk r-purge "u1 jk-old-a1 purge purged - - 1000" "u2 jk-old-a2 purge purged - - 1000" "u3 jk-old-b1 purge purged - - 1001" "u4 jk-old-b2 purge purged - - 1001"
expect_ok chk r-purge e-purge "${FORGED[@]}"
mk r-purge3 "u1 jk-old-a1 purge purged - - 1000" "u2 jk-old-a2 purge purged - - 1000" "u3 jk-old-b1 purge purged - - 1001"
expect_bad chk r-purge3 e-purge "${FORGED[@]}"                    # not one per key
mk r-purge-forged "u1 jk-old-a1 purge purged - - 1000" "u2 jk-old-a2 purge purged - - 1000" "u3 jk-old-b1 purge purged - - 1001" "u4 jk-old-b2 purge purged - - 1001" "f3 jk-forged-root purge purged - - 1000 session-1.scope 0"
expect_bad chk r-purge-forged e-purge "${FORGED[@]}"
mk r-purge-caller "u1 jk-old-a1 purge purged - - 1000 custodio.service 998 caller" "u2 jk-old-a2 purge purged - - 1000" "u3 jk-old-b1 purge purged - - 1001" "u4 jk-old-b2 purge purged - - 1001"
expect_bad chk r-purge-caller e-purge "${FORGED[@]}"              # a purge entry with a caller
mk r-purge-outcome "u1 jk-old-a1 purge failed - - 1000" "u2 jk-old-a2 purge purged - - 1000" "u3 jk-old-b1 purge purged - - 1001" "u4 jk-old-b2 purge purged - - 1001"
expect_bad chk r-purge-outcome e-purge "${FORGED[@]}"
mk r-own-a "u1 jk-old-a1 purge purged - - 1000" "u2 jk-old-a2 purge purged - - 1000"
expect_ok chk r-own-a e-own-a "${FORGED[@]}"
mk r-own-b "u3 jk-old-b1 purge purged - - 1001" "u4 jk-old-b2 purge purged - - 1001"
expect_ok chk r-own-b e-own-b "${FORGED[@]}"
expect_bad chk r-purge e-own-a "${FORGED[@]}"                     # the owner query returned the other owner's entries
expect_bad chk r-purge e-own-b "${FORGED[@]}"
expect_bad chk r-own-b e-own-a "${FORGED[@]}"
mk r-own-a-leak "u1 jk-old-a1 purge purged - - 1000" "u2 jk-old-a2 purge purged - - 1000" "u3 jk-old-b1 purge purged - - 1001"
expect_bad chk r-own-a-leak e-own-a "${FORGED[@]}"                # another owner's entry in the result
mk r-own-wrong "u1 jk-old-a1 purge purged - - 1001" "u2 jk-old-a2 purge purged - - 1001"
expect_bad chk r-own-wrong e-own-a "${FORGED[@]}"                 # the owner field is another uid

# the failed loads
t jk-b sign signing_failed tpm key_lost - > "$W/e-lost"
t jk-a sign signing_failed tpm temporarily_unavailable - > "$W/e-temp"
mk r-lost "s3 jk-b sign signing_failed tpm key_lost -"
expect_ok chk r-lost e-lost "${FORGED[@]}" "${PRESENT[@]}"
mk r-temp "s4 jk-a sign signing_failed tpm temporarily_unavailable -"
expect_ok chk r-temp e-temp "${FORGED[@]}" "${PRESENT[@]}"
expect_bad chk r-temp e-lost "${FORGED[@]}" "${PRESENT[@]}"       # the wrong cause
mk r-lost-signed "s3 jk-b sign signing_failed tpm key_lost -" "s1 jk-a sign signed tpm - -"
expect_bad chk r-lost-signed e-lost "${FORGED[@]}" "${PRESENT[@]}" # a signature that succeeded
mk r-lost-denied "s3 jk-b sign signing_failed tpm key_lost -" "s2 jk-a sign denied tpm - -"
expect_bad chk r-lost-denied e-lost "${FORGED[@]}" "${PRESENT[@]}" # a signature that was denied
mk r-lost-forged "s3 jk-b sign signing_failed tpm key_lost -" "f4 jk-forged-root sign signing_failed tpm key_lost - session-1.scope 0"
expect_bad chk r-lost-forged e-lost "${FORGED[@]}" "${PRESENT[@]}"
mk r-lost-nokind "s3 jk-b sign signing_failed - key_lost -"
expect_bad chk r-lost-nokind e-lost "${FORGED[@]}" "${PRESENT[@]}"
mk r-lost-kind "s3 jk-b sign signing_failed encrypted-host key_lost -"
expect_bad chk r-lost-kind e-lost "${FORGED[@]}" "${PRESENT[@]}"
mk r-lost-none
expect_bad chk r-lost-none e-lost "${FORGED[@]}" "${PRESENT[@]}"
: > "$W/window-nosign"; grep -v '"jk-a"' "$W/window" > "$W/window-nosign"
expect_bad jk check "$W/r-lost" "$W/pre" "$W/window-nosign" $S "$W/e-lost" "${FORGED[@]}" "${PRESENT[@]}" # the approved and denied signatures are not in the window: the control proves nothing

for f in journalkind-run.sh journalkind-user.sh journalkind-cases.sh; do bash -n "$ROOT/e2e/$f" || bad "$f does not parse"; done
exit "$fail"
