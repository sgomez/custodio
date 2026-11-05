#!/usr/bin/env bash
# F63: `just e2e-cases` and the subset mode of e2e/run.sh, with the stub `podman` of scripts/lib/e2e-host-fixtures.sh (no container is started). Checked here: the
# recipes (one shared package build), the selection of names and globs on the host and what the guest exec carries, which extra guest runs a subset makes, the
# accounting of a subset as wired in the host, the refusals before any engine call, and the engine calls of a run without a subset.
# NOT checked here: a real guest honouring the selection (test-e2e-select.sh, and the verify of F63 in a container).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_NAME=test-e2e-select-host
# shellcheck source=scripts/lib/e2e-host-fixtures.sh
. "$ROOT/scripts/lib/e2e-host-fixtures.sh"

# --- F63: a subset of the cases on one target (`just e2e-cases`)
# the recipes: both depend on one shared package-build recipe and have no build lines of their own
recipe_lines() { just --justfile "$ROOT/justfile" --show "$1" | grep -v '^[[:space:]]*#'; }
shared=$(recipe_lines e2e-packages)
for want in 'e2e-packages: package' 'scripts/package-next.sh' 'scripts/package-oldpath.sh'; do grep -qF "$want" <<< "$shared" || bad "the shared build recipe lacks '$want'"; done
grep -qF 'package-'old.sh <<< "$shared" && bad "the shared build recipe still builds the old package"
for r in e2e e2e-cases; do
    head=$(recipe_lines "$r" | head -n 1)
    grep -Eq ": e2e-packages$" <<< "$head" || bad "the $r recipe does not depend only on the shared build: '$head'"
    recipe_lines "$r" | grep -Eq 'scripts/package|cargo|nfpm' && bad "the $r recipe has build lines of its own"
    [ "$(recipe_lines "$r" | wc -l)" -eq 2 ] || bad "the $r recipe has more than the header and the call of run.sh: $(recipe_lines "$r")"
done
recipe_lines e2e-cases | grep -Eq '^[[:space:]]*bash e2e/run.sh \{\{ ?target ?\}\} --cases \{\{ ?quote\(names\) ?\}\}$' || bad "e2e-cases does not pass the target and the quoted names to run.sh"
listing=$(just --justfile "$ROOT/justfile" --list 2>&1)
grep -q 'e2e-cases' <<< "$listing" || bad "e2e-cases is not in just --list"
# the line the recipe would run, with a glob and a file that matches it in the working directory: the shell must not expand it
line=$(just --justfile "$ROOT/justfile" --dry-run e2e-cases debian13 pkcs11-tool-approve-rsa 'nss-*' 2>&1 | tail -n 1)
# (inside the repository, which run.sh needs: it changes to the top level after the shell has expanded its arguments)
mkdir -p "$ROOT/target"; cwd=$(mktemp -d "$ROOT/target/test-e2e-host-cwd.XXXXXX"); : > "$cwd/nss-x"
: > "$tmp/log"; rm -rf "$tmp/o"
(cd "$cwd" && STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" bash -c "${line/bash e2e\/run.sh/$ROOT/e2e/run.sh}") > "$tmp/out" 2>&1 || bad "the line of the recipe ($line) failed: $(tail -n 3 "$tmp/out")"
rm -rf "$cwd"
grep -q 'E2E_SELECT=pkcs11-tool-approve-rsa nss-approve nss-deny nss-asks-again ' "$tmp/log" || bad "the recipe line did not reach the guest with the selection: $(grep exec "$tmp/log")"

sel_guest() { grep 'guest.sh' "$tmp/log" | head -n 1; }
# the selection reaches the guest, in the order of the lists, one build, one container
expect_ok subset debian13 --cases pkcs11-tool-approve-rsa 'nss-*' || true
grep -q 'exec -e E2E_TPM=swtpm -e E2E_SELECT=pkcs11-tool-approve-rsa nss-approve nss-deny nss-asks-again custodio-e2e-debian13-[0-9]* bash /e2e/guest.sh debian13$' "$tmp/log" || bad "subset: the guest exec lacks exactly the selection: $(sel_guest)"
[ "$(grep -c '^build ' "$tmp/log")" -eq 1 ] || bad "subset: not one build"
[ "$(grep -c '^run ' "$tmp/log")" -eq 1 ] || bad "subset: not one container"
[ "$(grep -c 'guest.sh' "$tmp/log")" -eq 1 ] || bad "subset: more than one guest run"
grep -q '4 cases accounted for' "$tmp/out" || bad "subset: the accounting is not of 4 cases: $(tail -n 3 "$tmp/out")"
grep -q 'record: polkit-version=126' "$tmp/out" || bad "subset: the record is not saved"
# the same selection as one word (how the recipe passes it)
expect_ok subset-one-word debian13 --cases 'pkcs11-tool-approve-rsa nss-*' || true
grep -q 'E2E_SELECT=pkcs11-tool-approve-rsa nss-approve nss-deny nss-asks-again ' "$tmp/log" || bad "subset-one-word: $(sel_guest)"
# an exact name only, a glob only, a glob that overlaps a name (no duplicates), a glob in the middle
expect_ok exact debian13 --cases nss-deny || true
grep -q 'E2E_SELECT=nss-deny custodio' "$tmp/log" || bad "exact: $(sel_guest)"
grep -q '1 cases accounted for' "$tmp/out" || bad "exact: not one case accounted for"
expect_ok glob debian13 --cases 'provider-*' || true
grep -q 'E2E_SELECT=provider-rsa1 provider-ec1 provider-several-updates provider-deny custodio' "$tmp/log" || bad "glob: $(sel_guest)"
expect_ok overlap debian13 --cases nss-approve 'nss-*' 'nss-approve' || true
grep -q 'E2E_SELECT=nss-approve nss-deny nss-asks-again custodio' "$tmp/log" || bad "overlap: $(sel_guest)"
expect_ok question-mark debian13 --cases 'nss-deny' 'nss-?pprove' || true
grep -q 'E2E_SELECT=nss-approve nss-deny custodio' "$tmp/log" || bad "question-mark: $(sel_guest)"
# a target-own case: debian13 accepts its own purge cycle in the main container only; ubuntu2604 refuses an id that only another target owns
expect_ok own-case debian13 --cases 'purge-*' || true
[ "$(grep -c '^run ' "$tmp/log")" -eq 1 ] || bad "own-case: expected the main container only: $(grep -c '^run ' "$tmp/log")"
grep -q 'guest.sh debian13 oldpath' "$tmp/log" && bad "own-case: the old-path run started"
grep -q '6 cases accounted for' "$tmp/out" || bad "own-case: $(tail -n 3 "$tmp/out")"
grep -q 'E2E_SELECT=purge-service-stopped .*custodio-e2e-debian13-[0-9]* bash /e2e/guest.sh debian13$' "$tmp/log" || bad "own-case: the main run lacks the selection"
expect_ok own-case-oldpath debian13 --cases 'upgrade-oldpath-no-manual-step' || true
[ "$(grep -c '^run ' "$tmp/log")" -eq 2 ] || bad "oldpath case: expected the main and the old-path container"
grep -q 'guest.sh debian13 oldpath$' "$tmp/log" || bad "oldpath case: no old-path run"
expect_fail own-case-other-target ubuntu2604 --cases 'refusal-*' || true
grep -q "refusal-\*" "$tmp/out" || bad "own-case-other-target: the glob is not named: $(tail -n 3 "$tmp/out")"
# an Arch target has no old-path run: its cases are skipped in the main run and accounted there
expect_ok arch-oldpath arch --cases 'upgrade-oldpath-*' || true
[ "$(grep -c '^run ' "$tmp/log")" -eq 1 ] || bad "arch-oldpath: more than one container"
grep -q '6 cases accounted for' "$tmp/out" || bad "arch-oldpath: $(tail -n 3 "$tmp/out")"
# every target with a shared case, and the no-subset run unchanged
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    [ ! -f "$ROOT/e2e/targets/$T/refusal-only" ] || continue
    expect_ok "subset $T" "$T" --cases nss-approve || true
    grep -q '1 cases accounted for' "$tmp/out" || bad "subset $T: $(tail -n 3 "$tmp/out")"
done
# the accounting of a subset: the selection reaches `check`
STUB_EXTRA=nss-deny expect_fail subset-extra debian13 --cases nss-approve || true
grep -q "'nss-deny' was reported and is not selected" "$tmp/out" || bad "subset-extra: an unselected case reported was not named: $(tail -n 3 "$tmp/out")"
STUB_OMIT=nss-approve expect_fail subset-omit debian13 --cases nss-approve nss-deny || true
grep -q "'nss-approve' was not reported" "$tmp/out" || bad "subset-omit: $(tail -n 3 "$tmp/out")"
STUB_DUP=nss-deny expect_fail subset-dup debian13 --cases nss-approve nss-deny || true
grep -q "'nss-deny' reported twice" "$tmp/out" || bad "subset-dup: $(tail -n 3 "$tmp/out")"
STUB_SKIP=nss-deny expect_fail subset-skip debian13 --cases nss-deny || true
grep -q "'nss-deny' was skipped and is not on the skip list" "$tmp/out" || bad "subset-skip: $(tail -n 3 "$tmp/out")"
# a refusal-only target: its own ids run, a shared id is refused as matching nothing
expect_fail refusal-shared ubuntu2404 --cases nss-approve || true
grep -q "no case matches 'nss-approve'" "$tmp/out" || bad "refusal-shared: $(tail -n 3 "$tmp/out")"
[ ! -s "$tmp/log" ] || bad "refusal-shared: the engine was called"
expect_ok refusal-own ubuntu2404 --cases 'refusal-no-*' || true
grep -q 'E2E_SELECT=refusal-no-custodio-file custodio' "$tmp/log" || bad "refusal-own: $(sel_guest)"
grep -q '1 cases accounted for' "$tmp/out" || bad "refusal-own: $(tail -n 3 "$tmp/out")"

# refused before anything starts: no build, run or exec, and the offending name in the message
refused() { # refused NAME NEEDLE ARGS...
    local n=$1 needle=$2; shift 2
    expect_fail "$n" "$@" || true
    grep -qF -- "$needle" "$tmp/out" || bad "$n: the message lacks '$needle': $(tail -n 3 "$tmp/out")"
    [ ! -s "$tmp/log" ] || bad "$n: the engine was called: $(cat "$tmp/log")"
}
refused unknown-name no-such-case debian13 --cases no-such-case
refused unknown-glob 'no-such-*' debian13 --cases 'no-such-*'
refused good-and-bad no-such-case debian13 --cases nss-approve no-such-case
refused bad-and-good no-such-case debian13 --cases no-such-case nss-approve
refused prefix-only 'nss' debian13 --cases nss
refused empty-list '--cases needs' debian13 --cases
refused all-target "'all'" all --cases nss-approve
refused unknown-target debian13x debian13x --cases nss-approve
refused other-target-case 'purge-account-kept' alma10 --cases purge-account-kept
refused bad-characters 'a;b' debian13 --cases 'a;b'
refused extra-argument 'unexpected argument' debian13 nss-approve

# no subset: the whole list of engine calls of a run of debian13 (old path included) is this one, written out
expect_ok no-subset-calls debian13 || true
mnt="-v ROOT/TMP/pkgs/custodio_0.1.0-1_amd64.deb:/pkg/custodio_0.1.0-1_amd64.deb:ro -v ROOT/TMP/next/custodio_0.1.1-1_amd64.deb:/pkg-next/custodio_0.1.1-1_amd64.deb:ro -v ROOT/TMP/oldpath/custodio_0.1.0-1_amd64.deb:/pkg-oldpath/custodio_0.1.0-1_amd64.deb:ro"
boot="run -d --name custodio-e2e-debian13-PID --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock --tmpfs /tmp $mnt -v ROOT/e2e:/e2e:ro -v ROOT/docs/audit.md:/e2e-docs/audit.md:ro -v ROOT/crates/custodiod/src/app_id_source.rs:/e2e-src/app_id_source.rs:ro -v ROOT/e2e/targets/debian13:/e2e-target:ro custodio-e2e-debian13
exec custodio-e2e-debian13-PID systemctl is-system-running"
expected="build -q -t custodio-e2e-debian13 -f e2e/targets/debian13/Containerfile e2e/targets/debian13
$boot
exec -e E2E_TPM=swtpm custodio-e2e-debian13-PID bash /e2e/guest.sh debian13
rm -f custodio-e2e-debian13-PID
$boot
exec -e E2E_TPM=swtpm custodio-e2e-debian13-PID bash /e2e/guest.sh debian13 oldpath
rm -f custodio-e2e-debian13-PID
rm -f custodio-e2e-debian13-PID"
got=$(sed -E "s|$ROOT|ROOT|g; s|ROOT$tmp|ROOT/TMP|g; s|$tmp|TMP|g; s|debian13-[0-9]+|debian13-PID|g" "$tmp/log")
got=${got//ROOT\/ROOT\/TMP/ROOT/TMP}
[ "$got" = "$expected" ] || bad "no subset: the engine calls changed: $(diff <(echo "$expected") <(echo "$got") | head -n 6)"

exit "$fail"
