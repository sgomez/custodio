#!/usr/bin/env bash
# F131: the host script e2e/run.sh with the stub `podman` of scripts/lib/e2e-host-fixtures.sh, for E2E_TPM: the default and each value, a refused value, the filter
# program of `lacking`, E2E_ENGINE, the two passes of `all`, the record and the log per mode. No container is started; the real runs are `just e2e-cases`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-tpm-host
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh"

# --- F131: E2E_TPM (swtpm by default, none, lacking), the two passes of `all`, the record and the log per mode
tpm_of_guest_calls() { sed -n 's/.*-e E2E_TPM=\([^ ]*\).* bash \/e2e\/guest.sh.*/\1/p' "$tmp/log"; }
# unset and swtpm are the same run; none and lacking reach the guest as such
expect_ok "tpm unset" debian13 || true
cp "$tmp/log" "$tmp/log.unset"; cp "$tmp/o/debian13.swtpm.record" "$tmp/rec.unset"
E2E_TPM=swtpm expect_ok "tpm swtpm" debian13 || true
[ "$(sed 's/-[0-9][0-9]* / /g;s/-[0-9][0-9]*$//' "$tmp/log")" = "$(sed 's/-[0-9][0-9]* / /g;s/-[0-9][0-9]*$//' "$tmp/log.unset")" ] || bad "E2E_TPM unset and swtpm are not the same run"
for m in swtpm none lacking; do
    E2E_TPM=$m expect_ok "tpm $m" debian13 || true
    [ "$(tpm_of_guest_calls | sort -u)" = "$m" ] || bad "E2E_TPM=$m did not reach the guest as $m: $(tpm_of_guest_calls | sort -u | tr '\n' ' ')"
    # the mode is part of the record's and the log's name, and the record names it
    grep -qx "tpm=$m" "$tmp/o/debian13.$m.record" || bad "the record of $m lacks tpm=$m: $(cat "$tmp/o/debian13.$m.record" 2> /dev/null)"
    [ -s "$tmp/o/debian13.$m.log" ] || bad "no log for the mode $m"
    grep -q "record: tpm=$m" "$tmp/out" || bad "the record line tpm=$m is not printed"
    for other in swtpm none lacking; do [ "$other" = "$m" ] || [ ! -e "$tmp/o/debian13.$other.record" ] || bad "a run with $m left a record of $other"; done
done
# a refused value: exit 1, the allowed values named, and the engine never called
for v in bogus SWTPM None '' ' ' 'swtpm none' 'swtpm;x'; do
    : > "$tmp/log"
    if E2E_TPM=$v STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "E2E_TPM='$v' was accepted"; fi
    grep -q 'swtpm, none, lacking' "$tmp/out" || bad "E2E_TPM='$v': the allowed values are not named: $(tail -n 2 "$tmp/out")"
    [ ! -s "$tmp/log" ] || bad "E2E_TPM='$v': the engine was called: $(cat "$tmp/log")"
done
# --cases honours it too, and refuses before starting anything
: > "$tmp/log"
if E2E_TPM=bogus STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 --cases pkcs11-tool-approve-rsa > "$tmp/out" 2>&1; then bad "--cases accepted a bogus E2E_TPM"; fi
[ ! -s "$tmp/log" ] || bad "--cases with a bogus E2E_TPM called the engine"
for m in swtpm none lacking; do
    E2E_TPM=$m expect_ok "cases $m" debian13 --cases pkcs11-tool-approve-rsa || true
    [ "$(tpm_of_guest_calls | sort -u)" = "$m" ] || bad "--cases with E2E_TPM=$m: the guest was not asked for $m"
    grep -qx "tpm=$m" "$tmp/o/debian13.$m.record" || bad "--cases with E2E_TPM=$m: the record lacks tpm=$m"
done
# lacking: the filter program is mounted read-only into the container, and a run without it is refused before the engine is called; the other modes mount nothing of it
printf '#!/bin/sh\n' > "$tmp/tpm-filter"; chmod +x "$tmp/tpm-filter"
E2E_TPM_FILTER=$tmp/tpm-filter E2E_TPM=lacking expect_ok "lacking mounts the filter" debian13 || true
grep '^run ' "$tmp/log" | grep -q -- "-v $tmp/tpm-filter:/e2e-bin/tpm-filter:ro" || bad "lacking: the filter is not mounted read-only at /e2e-bin/tpm-filter: $(grep '^run ' "$tmp/log" | head -n 1)"
for m in swtpm none; do
    E2E_TPM_FILTER=$tmp/tpm-filter E2E_TPM=$m expect_ok "$m has no filter" debian13 || true
    grep -q 'tpm-filter' "$tmp/log" && bad "$m: the filter is mounted"
done
: > "$tmp/log"
if E2E_TPM_FILTER=$tmp/missing-filter E2E_TPM=lacking STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "lacking without the filter program passed"; fi
grep -q 'tpm-filter' "$tmp/out" || bad "lacking without the program: the filter is not named: $(tail -n 2 "$tmp/out")"
[ ! -s "$tmp/log" ] || bad "lacking without the program called the engine"
# E2E_ENGINE (CI: docker) names the engine; a name that is no program is refused before anything starts
: > "$tmp/log"
E2E_ENGINE="$tmp/bin/podman" expect_ok "E2E_ENGINE" debian13 || true
grep -q '^build ' "$tmp/log" || bad "E2E_ENGINE: the named engine was not used"
if E2E_ENGINE="$tmp/no-such-engine" STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1; then bad "E2E_ENGINE with no program passed"; fi
# `all` with E2E_TPM unset: every target with swtpm, and with none too only where a tpm-none marker is (debian13), never lacking; both records and logs
run_all_real() { : > "$tmp/log"; rm -rf "$tmp/o"; STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" "$@" > "$tmp/out" 2>&1; }
[ "$(cd "$ROOT/e2e/targets" && echo */tpm-none)" = debian13/tpm-none ] || bad "the tpm-none marker is not on debian13 alone: $(cd "$ROOT/e2e/targets" && echo */tpm-none)"
run_all_real all || bad "all: failed: $(tail -n 5 "$tmp/out")"
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    modes=swtpm; [ ! -f "$ROOT/e2e/targets/$T/tpm-none" ] || modes='swtpm none'
    n=$(wc -w <<< "$modes")
    [ "$(grep -c "guest.sh $T\$" "$tmp/log")" -eq "$n" ] || bad "all: $T guest was not run $n times: $(grep -c "guest.sh $T" "$tmp/log")"
    for m in swtpm none; do
        if [[ " $modes " = *" $m "* ]]; then
            grep -q -- "-e E2E_TPM=$m.* bash /e2e/guest.sh $T\$" "$tmp/log" || bad "all: $T did not run with $m"
            grep -qx "tpm=$m" "$tmp/o/$T.$m.record" || bad "all: the record of $T for $m lacks tpm=$m"
            [ -s "$tmp/o/$T.$m.log" ] || bad "all: no log of $T for $m"
        else
            grep -q -- "-e E2E_TPM=$m.* bash /e2e/guest.sh $T\$" "$tmp/log" && bad "all: $T ran with $m without a tpm-none marker"
            [ ! -e "$tmp/o/$T.$m.record" ] || bad "all: a record of $T for $m without a tpm-none marker"
        fi
    done
done
grep -q 'E2E_TPM=lacking' "$tmp/log" && bad "all ran the lacking mode"
grep -q "^e2e: passed:.* debian13 (none)" "$tmp/out" || bad "all: the passed line does not name debian13 (none): $(tail -n 1 "$tmp/out")"
# a set variable runs every target in that mode, marker or not
E2E_TPM=none run_all_real all || bad "all with E2E_TPM=none failed"
for T in $(cd "$ROOT/e2e/targets" && echo *); do grep -q -- "-e E2E_TPM=none.* bash /e2e/guest.sh $T\$" "$tmp/log" || bad "all with E2E_TPM=none: $T did not run"; done
grep -q 'E2E_TPM=swtpm' "$tmp/log" && bad "all with E2E_TPM=none ran swtpm"
[ ! -e "$tmp/o/debian13.swtpm.record" ] || bad "all with E2E_TPM=none made a swtpm record"
# a failing mode does not stop the other one, and the exit is non-zero; the mode is named
for failing in swtpm none; do
    other=none; [ "$failing" = none ] && other=swtpm
    if STUB_FAIL_TPM=$failing run_all_real all; then bad "all: a failing $failing run did not fail the command"; fi
    grep -q "E2E_TPM=$other.* bash /e2e/guest.sh debian13\$" "$tmp/log" || bad "all: the $other run did not happen after $failing failed"
    grep -q "failed targets:.*debian13 ($failing)" "$tmp/out" || bad "all: the failed mode $failing is not named: $(tail -n 2 "$tmp/out")"
    grep "failed targets:" "$tmp/out" | grep -q "debian13 ($other)" && bad "all: the passing mode $other is named as failed"
    [ -f "$tmp/o/debian13.$other.record" ] || bad "all: no record for the passing mode $other"
done
# the record must hold the line, and the guest must report the mode that was asked for
STUB_NOTPM=1 expect_fail "record without tpm" debian13 || true
grep -q 'reported no tpm' "$tmp/out" || bad "a probe without tpm= was not named: $(tail -n 3 "$tmp/out")"
E2E_TPM=none STUB_TPM_REPORT=swtpm expect_fail "record with the wrong mode" debian13 || true
grep -q "reported tpm=swtpm, expected none" "$tmp/out" || bad "a guest that reports another mode was not named: $(tail -n 3 "$tmp/out")"
# control: a run.sh that ignores the variable accepts a bogus value, so the refusal checks above would fail on it
sed 's/E2E_TPM/E2E_TPM_IGNORED/g' "$ROOT/e2e/run.sh" > "$tmp/run-ignoring.sh"
: > "$tmp/log"
E2E_TPM=bogus STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" bash "$tmp/run-ignoring.sh" debian13 > "$tmp/out" 2>&1 || true
[ -s "$tmp/log" ] || bad "control: a run.sh that ignores E2E_TPM was refused, so the refusal test proves nothing"

exit "$fail"
