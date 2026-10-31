#!/usr/bin/env bash
# Runs the `scripts/...` lines of the given just recipes in parallel (JOBS, default nproc), slowest first by
# the last run's times, and prints the log of each one that fails. Logs and times: target/script-tests/.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
out=target/script-tests
log_of() { echo "$out/logs/$(tr -c 'A-Za-z0-9._-' _ <<< "$1").log"; }

if [ "${1:-}" = --one ]; then # one command: its log, and "SECONDS EXIT COMMAND" in results
    rc=0 t0=$(date +%s)
    bash -c "$2" > "$(log_of "$2")" 2>&1 || rc=$?
    printf '%s %s %s\n' "$(($(date +%s) - t0))" "$rc" "$2" >> "$out/results"
    if [ "$rc" = 0 ]; then echo "ok    $2"; else echo "FAIL  $2"; fi
    exit 0
fi
mkdir -p "$out/logs"
rm -f "$out"/logs/* "$out"/results

cmds=$(for r in "$@"; do just --show "$r" | tail -n +2 | sed 's/^[[:space:]]*//' | grep '^scripts/'; done)
[ -n "$cmds" ] || { echo "run-script-tests: no scripts in: $*" >&2; exit 1; }
# Unknown ones (new tests) first, then slowest first.
ordered=$(while IFS= read -r c; do
    t=$(awk -v c="$c" '$0 ~ /^[0-9]/ { s = $1; $1 = ""; sub(/^ /, ""); if ($0 == c) print s }' "$out/times" 2> /dev/null | tail -n 1)
    printf '%s\t%s\n' "${t:-999999}" "$c"
done <<< "$cmds" | sort -t$'\t' -k1,1nr | cut -f2-)

t0=$(date +%s)
tr '\n' '\0' <<< "$ordered" | xargs -0 -r -P "${JOBS:-$(nproc)}" -I{} "$ROOT/scripts/run-script-tests.sh" --one {}

awk '{ s = $1; $2 = ""; $1 = ""; sub(/^  /, ""); print s, $0 }' "$out/results" > "$out/times"
fail=0
while read -r secs rc c; do
    [ "$rc" = 0 ] && continue
    fail=1
    echo "---- $c (exit $rc, ${secs}s), last lines of $out/logs:" >&2
    tail -n 40 "$(log_of "$c")" >&2
done < "$out/results"
echo "run-script-tests: $(wc -l < "$out/results") scripts in $(($(date +%s) - t0))s"
exit "$fail"
