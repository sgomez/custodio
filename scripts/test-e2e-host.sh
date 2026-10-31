#!/usr/bin/env bash
# F45: the host script e2e/run.sh with a stub `podman` on PATH that logs its arguments; no container is started. Checked here: the order
# and shape of the engine calls, the target choice and `all`, the read-only package mount, the record, the case accounting and the skip
# enforcement as wired in the host, the Containerfiles (no package copied, real polkit and bus daemon), the lint file list.
# NOT checked here: that a real container boots and the suite passes in it; that is the real run of `just e2e debian13`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-host: $*" >&2; fail=1; }

mkdir -p "$tmp/bin" "$tmp/pkgs"
: > "$tmp/pkgs/custodio_0.1.0-1_amd64.deb"
cat > "$tmp/bin/podman" <<'STUB'
#!/usr/bin/env bash
# Logs the arguments; `exec ... guest.sh` prints what the fake guest would, from STUB_* variables.
echo "$*" >> "$STUB_LOG"
case $1 in
exec)
    case "$*" in
    *"is-system-running"*) echo running ;;
    *"/e2e/guest.sh"*)
        t=${*: -1}
        echo "e2e: installed custodio_0.1.0-1_amd64.deb from the mounted file"
        while IFS= read -r c; do
            case $c in '' | '#'*) continue ;; esac
            [ "$c" = "${STUB_OMIT:-}" ] && continue
            if [ "$c" = "${STUB_SKIP:-}" ]; then echo "E2E-CASE skipped $c"; else echo "E2E-CASE run $c"; fi
            [ "$c" = "${STUB_DUP:-}" ] && echo "E2E-CASE run $c"
        done < "$STUB_ROOT/e2e/cases.list"
        [ -z "${STUB_EXTRA:-}" ] || echo "E2E-CASE run $STUB_EXTRA"
        if [ -z "${STUB_NOPROBE:-}" ]; then
            echo "E2E-RECORD bus-daemon=dbus-daemon"
            echo "E2E-RECORD polkit-version=126"
        fi
        [ "$t" != "${STUB_FAIL:-}" ] || { echo "e2e: FAIL: stubbed"; exit 1; }
        echo "e2e: all checks passed"
        ;;
    esac
    ;;
esac
STUB
chmod +x "$tmp/bin/podman"
export STUB_ROOT=$ROOT

# run_host NAME ARGS...: runs e2e/run.sh with the stub; the log of the engine in $tmp/log, the output in $tmp/out.
run_host() {
    : > "$tmp/log"
    rm -rf "$tmp/o"
    STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" "$@" > "$tmp/out" 2>&1
}
expect_ok() { local n=$1; shift; run_host "$@" || { bad "$n: failed: $(tail -n 5 "$tmp/out")"; return 1; }; }
expect_fail() { local n=$1; shift; if run_host "$@"; then bad "$n: passed"; return 1; fi; }

# --- every real target: the order and shape of the calls
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    expect_ok "$T" "$T" || true
    b=$(grep -n '^build ' "$tmp/log" | head -n 1 | cut -d: -f1)
    r=$(grep -n '^run ' "$tmp/log" | head -n 1 | cut -d: -f1)
    x=$(grep -n 'guest.sh' "$tmp/log" | head -n 1 | cut -d: -f1)
    { [ -n "$b" ] && [ -n "$r" ] && [ -n "$x" ] && [ "$b" -lt "$r" ] && [ "$r" -lt "$x" ]; } || bad "build, run, exec of the guest are not in this order: $(cat "$tmp/log")"
    grep '^build ' "$tmp/log" | grep -q -- "-f e2e/targets/$T/Containerfile" || bad "the build does not use the target's Containerfile"
    grep '^run ' "$tmp/log" | grep -q -- '--privileged' || bad "the container is not privileged"
    grep '^run ' "$tmp/log" | grep -q -- "$tmp/pkgs/custodio_0.1.0-1_amd64.deb:/pkg/custodio_0.1.0-1_amd64.deb:ro" || bad "the package is not mounted read-only"
    grep -q "exec .* bash /e2e/guest.sh $T" "$tmp/log" || bad "the shared guest script is not executed"
    grep -q 'installed custodio_0.1.0-1_amd64.deb from the mounted file' "$tmp/out" || bad "the guest's output is not passed through"
    grep -qi 'cargo\|nfpm\|just package' "$tmp/log" && bad "the engine log shows a package build"
    grep -q 'cargo\|nfpm\|just package' "$ROOT/e2e/run.sh" && bad "the host script builds packages"
done
# the recipe: package is its dependency and the default target is all
grep -Eq '^e2e target="all": package$' "$ROOT/justfile" || bad "the e2e recipe does not take a target (default all) and depend on package"
grep -q 'bash e2e/run.sh {{target}}' "$ROOT/justfile" || bad "the e2e recipe does not pass the target"

# --- the record
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    expect_ok "$T" "$T" || true
    rec=$tmp/o/$T.record
    [ -f "$rec" ] || bad "no record file"
    { grep -qx "target=$T" "$rec" && grep -qx 'bus-daemon=dbus-daemon' "$rec" && grep -qx 'polkit-version=126' "$rec"; } || bad "the record lacks target, daemon or polkit version: $(cat "$rec" 2> /dev/null)"
    { grep -q 'record: bus-daemon=dbus-daemon' "$tmp/out" && grep -q 'record: polkit-version=126' "$tmp/out"; } || bad "the record is not printed"
    STUB_NOPROBE=1 expect_fail probe-empty "$T" || true
    grep -q 'reported no bus-daemon' "$tmp/out" || bad "an empty probe was not named: $(tail -n 3 "$tmp/out")"
done

# --- unknown target: names the targets, never calls the engine
expect_fail unknown-target nope || true
grep -q 'available targets: debian13 ubuntu2604' "$tmp/out" || bad "an unknown target does not name the available ones"
[ ! -s "$tmp/log" ] || bad "the engine was called for an unknown target"
expect_fail path-target ../targets/debian13 || true
[ ! -s "$tmp/log" ] || bad "the engine was called for a target with a path"

# --- all, with the real targets directory: every real target runs
: > "$tmp/log"; rm -rf "$tmp/o"
STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" all > "$tmp/out" 2>&1 || bad "all (real targets): failed: $(tail -n 5 "$tmp/out")"
for T in $(cd "$ROOT/e2e/targets" && echo *); do
    grep -q "guest.sh $T" "$tmp/log" || bad "all (real targets): $T did not run"
    [ -f "$tmp/o/$T.record" ] || bad "all (real targets): no record for $T"
done

# --- all, with two fake targets copied in with no edit to any script
fake=$tmp/targets
mkdir -p "$fake"
cp -r "$ROOT/e2e/targets/debian13" "$fake/alpha"
cp -r "$ROOT/e2e/targets/debian13" "$fake/beta"
run_all() { : > "$tmp/log"; rm -rf "$tmp/o"; STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_TARGETS="$fake" E2E_PACKAGES="$tmp/pkgs" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" "$@" > "$tmp/out" 2>&1; }
run_all || bad "all: failed: $(tail -n 5 "$tmp/out")"
for t in alpha beta; do
    grep -q "guest.sh $t" "$tmp/log" || bad "all: $t did not run"
    [ -f "$tmp/o/$t.record" ] || bad "all: no record for $t"
done
run_all alpha || bad "a single fake target failed"
grep -q 'guest.sh beta' "$tmp/log" && bad "only alpha was asked for, beta ran"
if STUB_FAIL=alpha run_all; then bad "all: a failing target did not fail the command"; fi
grep -q 'guest.sh beta' "$tmp/log" || bad "all: beta did not run after alpha failed"
grep -q 'failed targets: alpha' "$tmp/out" || bad "all: the failed target is not named"

# --- the case accounting and the skip enforcement, wired in the host
first=$(grep -v '^[[:space:]]*\(#\|$\)' "$ROOT/e2e/cases.list" | head -n 1)
STUB_OMIT=$first expect_fail omitted debian13 || true
grep -q "'$first' was not reported" "$tmp/out" || bad "an omitted case was not named"
STUB_EXTRA=made-up-case expect_fail unknown debian13 || true
grep -q "unknown case 'made-up-case'" "$tmp/out" || bad "an unknown case was not named"
STUB_DUP=$first expect_fail duplicated debian13 || true
grep -q "'$first' reported twice" "$tmp/out" || bad "a duplicated case was not named"
STUB_SKIP=$first expect_fail skip-unlisted debian13 || true
grep -q "'$first' was skipped and is not on the skip list" "$tmp/out" || bad "an unlisted skip did not fail the run"
cp -r "$ROOT/e2e/targets/debian13" "$fake/gamma"
printf '%s: not available on this target\n' "$first" >> "$fake/gamma/skip.list"
STUB_SKIP=$first run_all gamma || bad "a listed skip failed the run: $(tail -n 5 "$tmp/out")"
printf 'bad line without colon\n' >> "$fake/gamma/skip.list"
run_all gamma && bad "a malformed skip list was accepted by the host"
: > "$tmp/log"
# a missing file of a target
rm -rf "$fake/gamma" "$fake/beta"; rm "$fake/alpha/install.sh"
run_all alpha && bad "a target without install.sh was accepted"
! grep -Eq '^(build|run|exec) ' "$tmp/log" || bad "the engine built or ran an incomplete target"

# --- the packages come from the packages directory: none there, the run fails
mkdir -p "$tmp/empty"
STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_PACKAGES="$tmp/empty" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" debian13 > "$tmp/out" 2>&1 && bad "a run without a package passed"

# --- the targets: no Containerfile copies a package, the install step uses the target's tool, the real polkit and bus daemon
for cf in "$ROOT"/e2e/targets/*/Containerfile; do
    if grep -Eqi '^[[:space:]]*(COPY|ADD)\b|\bcp\b.*(\.deb|\.rpm|\.pkg|custodio)|/pkg/' "$cf"; then bad "$cf copies or names a package"; fi
done
printf 'FROM debian:trixie\nCOPY custodio.deb /tmp/\n' > "$tmp/CF.bad"
grep -Eqi '^[[:space:]]*(COPY|ADD)\b' "$tmp/CF.bad" || bad "control: a Containerfile that copies a .deb was not seen"
grep -q 'install.sh' "$ROOT/e2e/guest.sh" || bad "the guest does not call the target's install step"
if grep -En '\b(dpkg|apt|apt-get|rpm|pacman|dnf)\b|\b(cp|install)\b.* /(usr|etc)' "$ROOT/e2e/guest.sh" | grep -v '^[0-9]*:[[:space:]]*#' | grep -q .; then bad "the shared guest script calls a package tool or copies into /usr or /etc"; fi
# target_problems DIR: what is wrong with a target directory (empty output: nothing). The install step uses the tool of the
# distribution on the mounted file (ubuntu* must use apt, not only dpkg), the image has the real polkit and a default bus daemon.
target_problems() {
    local d=$1 n
    n=$(basename "$d")
    for f in Containerfile install.sh probe.sh skip.list package.pattern; do [ -f "$d/$f" ] || echo "$n: no $f"; done
    grep -Eq 'polkitd' "$d/Containerfile" 2> /dev/null || echo "$n: does not install polkitd"
    grep -Eq '\bdbus\b' "$d/Containerfile" 2> /dev/null || echo "$n: does not install dbus"
    if grep -qi 'dbus-broker' "$d/Containerfile" 2> /dev/null; then echo "$n: installs dbus-broker"; fi
    grep -Eq 'dpkg|apt|rpm|dnf|pacman' "$d/install.sh" 2> /dev/null || echo "$n: install.sh uses no package tool"
    # shellcheck disable=SC2016 # the pattern looks for a literal "$1" in the script
    case $n in
    ubuntu*) grep -Eq '(^|[[:space:]])(apt|apt-get)[[:space:]].*\binstall\b.*"\$1"' "$d/install.sh" 2> /dev/null || echo "$n: install.sh does not apt install the mounted file" ;;
    esac
}
for d in "$ROOT"/e2e/targets/*/; do
    d=${d%/}
    p=$(target_problems "$d")
    [ -z "$p" ] || bad "$p"
done
[ -d "$ROOT/e2e/targets/ubuntu2604" ] || bad "no target ubuntu2604"
# control: a fixture Ubuntu target whose install.sh uses only dpkg is rejected, an apt one is not
mkdir -p "$tmp/fx"
cp -r "$ROOT/e2e/targets/debian13" "$tmp/fx/ubuntu9999"
[ -n "$(target_problems "$tmp/fx/ubuntu9999")" ] || bad "control: an ubuntu target that installs with dpkg -i only was accepted"
# shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
printf '#!/usr/bin/env bash\nset -euo pipefail\napt-get install -y "$1" > /dev/null\n' > "$tmp/fx/ubuntu9999/install.sh"
[ -z "$(target_problems "$tmp/fx/ubuntu9999")" ] || bad "control: an ubuntu target that installs with apt was rejected: $(target_problems "$tmp/fx/ubuntu9999")"
rm "$tmp/fx/ubuntu9999/probe.sh"
[ -n "$(target_problems "$tmp/fx/ubuntu9999")" ] || bad "control: a target without probe.sh was accepted"
grep -rqi 'polkit' "$ROOT/e2e/targets" || bad "no target mentions polkit"

# --- shellcheck covers the new scripts
list=$("$ROOT/scripts/list-shell-scripts.sh")
targets_scripts=()
for d in "$ROOT"/e2e/targets/*/; do targets_scripts+=("e2e/targets/$(basename "$d")/install.sh" "e2e/targets/$(basename "$d")/probe.sh"); done
for f in e2e/run.sh e2e/check-cases.sh e2e/report.sh "${targets_scripts[@]}" scripts/test-e2e-host.sh scripts/test-e2e-skips.sh scripts/test-e2e-catalog.sh; do
    grep -qx "$f" <<< "$list" || bad "$f is not in the shellcheck list"
done

exit "$fail"
