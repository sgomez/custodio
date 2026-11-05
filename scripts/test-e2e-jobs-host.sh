#!/usr/bin/env bash
# e2e/run.sh runs the target-mode pairs at once, at most E2E_JOBS, with the stub `podman` of scripts/lib/e2e-host-fixtures.sh: the limit, the
# order of the output, timings.tsv, phases.tsv, one container name per pair, and a refused E2E_JOBS. No container is started.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-jobs-host
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh"

# two installing targets of the real tree in their own directory, so `all` is short
mkdir -p "$tmp/targets"
for t in alma10 debian13; do cp -r "$ROOT/e2e/targets/$t" "$tmp/targets/"; done
touch "$tmp/targets/alma10/tpm-none" # both run both modes: four pairs
run_all() { : > "$tmp/log"; rm -f "$tmp/log.conc"; rm -rf "$tmp/o"; STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_TARGETS="$tmp/targets" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" all > "$tmp/out" 2>&1; }
max_conc() { sort -n "$tmp/log.conc" | tail -n 1; }

for j in 1 2 4; do
    E2E_JOBS=$j STUB_SLEEP=1 run_all || bad "E2E_JOBS=$j: failed: $(tail -n 3 "$tmp/out")"
    [ "$(wc -l < "$tmp/log.conc")" -eq 4 ] || bad "E2E_JOBS=$j: expected 4 guest runs: $(wc -l < "$tmp/log.conc")"
    [ "$(max_conc)" -le "$j" ] || bad "E2E_JOBS=$j: $(max_conc) runs at once"
    [ "$j" = 1 ] || [ "$(max_conc)" -ge 2 ] || bad "E2E_JOBS=$j: the runs did not overlap"
done

# the output is whole per pair and in the order of the modes, then the targets, whatever ends first
E2E_JOBS=4 run_all || bad "order: failed"
[ "$(sed -n 's/^e2e\[\([a-z0-9]*\)\]: record: tpm=\(.*\)/\1 \2/p' "$tmp/out" | tr '\n' ' ')" = "alma10 swtpm debian13 swtpm alma10 none debian13 none " ] \
    || bad "order: the records are not in mode, target order: $(grep 'record: tpm=' "$tmp/out" | tr '\n' ' ')"
[ "$(grep -c '^e2e: ended ' "$tmp/out")" -eq 4 ] || bad "order: not one end line per pair"

# timings.tsv: a header and one line per pair, with seconds and the result
[ "$(head -n 1 "$tmp/o/timings.tsv")" = "$(printf 'target\tmode\tseconds\tresult')" ] || bad "timings: no header"
[ "$(tail -n +2 "$tmp/o/timings.tsv" | awk -F'\t' '$3 ~ /^[0-9]+$/ && $4 == "passed"' | wc -l)" -eq 4 ] || bad "timings: $(cat "$tmp/o/timings.tsv")"
# phases.tsv: a header and the guest's E2E-PHASE lines of each pair, the old-path run's among them
[ "$(head -n 1 "$tmp/o/phases.tsv")" = "$(printf 'target\tmode\tphase\tseconds')" ] || bad "phases: no header"
for p in alma10:swtpm debian13:swtpm alma10:none debian13:none; do
    for ph in install:3 oldpath-upgrade:2; do
        line=$(printf '%s\t%s\t%s\t%s' "${p%:*}" "${p#*:}" "${ph%:*}" "${ph#*:}")
        grep -qxF "$line" "$tmp/o/phases.tsv" || bad "phases: no '$ph' line for $p: $(cat "$tmp/o/phases.tsv")"
    done
done
[ "$(wc -l < "$tmp/o/phases.tsv")" -eq 9 ] || bad "phases: not two lines per pair: $(cat "$tmp/o/phases.tsv")"

STUB_FAIL=alma10 E2E_JOBS=4 run_all && bad "a failing pair did not fail the run"
grep -qP '^alma10\tswtpm\t[0-9]+\tfailed$' "$tmp/o/timings.tsv" || bad "timings: the failed pair is not marked: $(cat "$tmp/o/timings.tsv")"
grep -qP '^debian13\tnone\t[0-9]+\tpassed$' "$tmp/o/timings.tsv" || bad "timings: a pair after the failure did not pass"

# one container per pair, named by target and mode, each removed
names=$(sed -n 's/^run .*--name \(custodio-e2e-[a-z0-9]*-[a-z]*\)-[0-9]* .*/\1/p' "$tmp/log" | sort -u | tr '\n' ' ')
[ "$names" = "custodio-e2e-alma10-none custodio-e2e-alma10-swtpm custodio-e2e-debian13-none custodio-e2e-debian13-swtpm " ] || bad "names: $names"
for n in $names; do grep -q "^rm -f $n-[0-9]*$" "$tmp/log" || bad "$n is not removed"; done

# a refused E2E_JOBS: exit 1, named, the engine never called
for v in 0 -1 x 1.5 '' ' 2'; do
    if E2E_JOBS=$v run_all; then bad "E2E_JOBS='$v' was accepted"; fi
    grep -q "E2E_JOBS='$v' is not a positive number" "$tmp/out" || bad "E2E_JOBS='$v': not named: $(tail -n 2 "$tmp/out")"
    grep -Eq '^(build|run|exec) ' "$tmp/log" && bad "E2E_JOBS='$v': the engine ran"
done

exit "$fail"
