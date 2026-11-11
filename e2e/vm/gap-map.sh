#!/usr/bin/env bash
# F168: the gap table of e2e/vm/gaps.md (SPEC acceptance 12) against the VM case list and, given a run log, against what the run reported.
#   gap-map.sh                 the fenced `gap-table` block is well formed: one row per gap F134 F135 F137 F138 F140 F141 plus the PSS row, every mapped
#                              case is in cases.list and none is on skip.list
#   gap-map.sh LOG [MODE]      also: every mapped case is reported `E2E-CASE run` exactly once in LOG; in lacking the log has `reader: key` lines, in full none
#                              (MODE full|lacking, default read from the name vm.<mode>.log)
# Overrides for the self-test: GAP_TABLE, GAP_CASES, GAP_SKIP.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TABLE=${GAP_TABLE:-$ROOT/e2e/vm/gaps.md}
CASES=${GAP_CASES:-$ROOT/e2e/vm/cases.list}
SKIP=${GAP_SKIP:-$ROOT/e2e/vm/skip.list}
LOG=${1:-} MODE=${2:-}
fail=0
bad() { echo "gap-map: $*" >&2; fail=1; }
for f in "$TABLE" "$CASES" "$SKIP"; do [ -f "$f" ] || { echo "gap-map: $f: no such file" >&2; exit 2; }; done

rows=$(awk '/^```gap-table$/{on=1;next} /^```$/{on=0} on' "$TABLE")
[ -n "$rows" ] || { echo "gap-map: no gap-table block in $TABLE" >&2; exit 2; }
ids=$(grep -v '^[[:space:]]*\(#\|$\)' "$CASES")
skips=$({ grep -v '^[[:space:]]*\(#\|$\)' "$SKIP" || true; } | sed 's/:.*//')

for g in F134 F135 F137 F138 F140 F141; do
    printf '%s\n' "$rows" | grep -q "^$g " || bad "no row for the gap $g"
done
printf '%s\n' "$rows" | grep -q '^F134 RSA-PSS' || bad "no row for RSA-PSS with a real TPM-sealed credential"
mapped=
while IFS= read -r row; do
    [[ $row =~ ^[A-Za-z0-9]+\ [^|]+\ \|\ ([A-Za-z0-9._\ -]+)$ ]] || { bad "malformed row: $row"; continue; }
    read -ra cs <<< "${BASH_REMATCH[1]}"
    [ ${#cs[@]} -gt 0 ] || bad "row maps no case: $row"
    for c in "${cs[@]}"; do
        printf '%s\n' "$ids" | grep -qx -- "$c" || bad "mapped case $c is not in the VM case list"
        printf '%s\n' "$skips" | grep -qx -- "$c" && bad "mapped case $c is on the skip list"
        mapped="$mapped $c"
    done
done <<< "$rows"

if [ -n "$LOG" ]; then
    [ -f "$LOG" ] || { echo "gap-map: $LOG: no such file" >&2; exit 2; }
    if [ -z "$MODE" ]; then b=$(basename "$LOG"); b=${b#vm.}; MODE=${b%%.*}; fi
    case $MODE in full | lacking) ;; *) echo "gap-map: mode '$MODE' is not full or lacking" >&2; exit 2 ;; esac
    for c in $mapped; do
        n=$(grep -cx "E2E-CASE run $c" "$LOG" || true)
        [ "$n" = 1 ] || bad "$c is reported run $n times (expected once)"
        grep -qx "E2E-CASE skipped $c" "$LOG" && bad "$c is reported skipped"
    done
    r=$(grep -c '^reader: key ' "$LOG" || true)
    if [ "$MODE" = lacking ]; then [ "$r" -gt 0 ] || bad "the lacking log has no 'reader: key' line"
    else [ "$r" = 0 ] || bad "the full log has $r 'reader: key' lines"; fi
fi
[ "$fail" = 0 ] && echo "gap-map: ok"
exit "$fail"
