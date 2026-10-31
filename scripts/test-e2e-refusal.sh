#!/usr/bin/env bash
# F50: the refusal-only target ubuntu2404. Runs the self-test of the refusal checks; checks the target directory (the marker, the 24.04 image on
# its default dbus-daemon, no package copied, nothing discarded by install.sh, its own case ids); the guest's refusal path (no service step); and
# e2e/run.sh with a stub engine: the marker lifts the demand for package N+1 and the old package, the accounting is the target's own ids only, and a
# target without the marker still demands N+1 and the common ids.
# NOT checked here: that Ubuntu 24.04 really boots and refuses; that is the real run of `just e2e ubuntu2404`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$ROOT/e2e/targets/ubuntu2404
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-refusal: $*" >&2; fail=1; }
ids_of() { grep -v '^[[:space:]]*\(#\|$\)' "$1" 2> /dev/null || true; }

bash "$ROOT/e2e/refusal-selftest.sh" > /dev/null || bad "the self-test of the refusal checks failed: $(bash "$ROOT/e2e/refusal-selftest.sh" 2>&1 | tail -n 3)"

# --- the target directory
[ -f "$T/refusal-only" ] || bad "ubuntu2404 has no refusal-only marker"
grep -Eq '^FROM .*ubuntu:24\.04' "$T/Containerfile" || bad "the Containerfile does not start FROM ubuntu:24.04"
grep -qi 'dbus-broker' "$T/Containerfile" && bad "the Containerfile installs dbus-broker"
grep -Eqi '^[[:space:]]*(COPY|ADD)\b|/pkg' "$T/Containerfile" && bad "the Containerfile copies or names a package"
grep -Eq '(^|[[:space:]])polkitd([[:space:]]|$)' "$T/Containerfile" || bad "the Containerfile does not install polkitd"
grep -Eq '(^|[[:space:]])dbus([[:space:]]|$)' "$T/Containerfile" || bad "the Containerfile does not install dbus"
[ ! -e "$T/old.pattern" ] || bad "the refusal target has an old.pattern"
# shellcheck disable=SC2016 # the pattern looks for a literal "$1"
grep -Eq 'apt-get .*install .*"\$1"' "$T/install.sh" || bad "install.sh does not apt install the mounted file"
grep -q 'dev/null' "$T/install.sh" && bad "install.sh discards output"
want='refusal-bus-lacks-processfd refusal-install-fails-naming-processfd refusal-no-custodio-file refusal-dpkg-not-configured refusal-nothing-listens'
# shellcheck disable=SC2086 # the id list is words on purpose
[ "$(ids_of "$T/cases.list" | sort | tr '\n' ' ')" = "$(printf '%s\n' $want | sort | tr '\n' ' ')" ] || bad "cases.list is not the five refusal ids: $(ids_of "$T/cases.list" | tr '\n' ' ')"
[ -z "$(ids_of "$T/skip.list")" ] || bad "the refusal target skips a case"
for id in $(ids_of "$T/cases.list"); do
    ids_of "$ROOT/e2e/cases.list" | grep -qx "$id" && bad "$id is in the common cases.list"
    grep -q "case_run $id\|need $id" "$ROOT/e2e/refusal.sh" || grep -q "$id" "$ROOT/e2e/refusal.sh" || bad "refusal.sh never reports $id"
done
grep -rq 'ProcessFD' "$ROOT/e2e" || bad "no ProcessFD under e2e"
# the other targets are not marked
for d in "$ROOT"/e2e/targets/*/; do
    [ "$(basename "$d")" = ubuntu2404 ] || [ ! -e "$d/refusal-only" ] || bad "$(basename "$d") is marked refusal-only"
done

# --- the guest: the refusal path ends before every step that needs a service
g=$ROOT/e2e/guest.sh
m=$(grep -n -- '-f /e2e-target/refusal-only' "$g" | head -n 1 | cut -d: -f1)
i=$(grep -n 'bash /e2e-target/install.sh' "$g" | head -n 1 | cut -d: -f1)
if [ -z "$m" ] || [ -z "$i" ] || [ "$m" -ge "$i" ]; then bad "the guest does not test the marker before the install step"; fi
block=$(sed -n "${m},/^fi\$/p" "$g")
grep -q 'refusal.sh' <<< "$block" || bad "the refusal path does not run refusal.sh"
grep -q 'refusal-selftest.sh' <<< "$block" || bad "the refusal path does not run the self-test first"
grep -q 'exit 0' <<< "$block" || bad "the refusal path does not end the run"
if grep -Eq 'import\.py|upgrade\.sh|lifecycle\.sh|user\.sh|unavailable\.sh|journal|systemctl (start|reload)|pkg-next|pkg_next' <<< "$block"; then bad "the refusal path runs a step that needs a service"; fi

# --- the host, with a stub engine
mkdir -p "$tmp/bin" "$tmp/pkgs" "$tmp/nonext" "$tmp/noold" "$tmp/targets"
: > "$tmp/pkgs/custodio_0.1.0-1_amd64.deb"
cat > "$tmp/bin/podman" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case $1 in
exec)
    case "$*" in
    *is-system-running*) echo running ;;
    *"/e2e/guest.sh"*)
        t=${*: -1}
        { [ -f "$STUB_TARGETS/$t/refusal-only" ] || cat "$STUB_ROOT/e2e/cases.list"; ids=$STUB_TARGETS/$t/cases.list; cat "$ids"; } | grep -v '^[[:space:]]*\(#\|$\)' | while read -r c; do
            [ "$c" = "${STUB_OMIT:-}" ] || echo "E2E-CASE run $c"
        done
        [ -z "${STUB_EXTRA:-}" ] || echo "E2E-CASE run $STUB_EXTRA"
        echo "E2E-RECORD bus-daemon=dbus-daemon"
        echo "E2E-RECORD polkit-version=124"
        ;;
    esac
    ;;
esac
STUB
chmod +x "$tmp/bin/podman"
export STUB_ROOT=$ROOT STUB_TARGETS=$tmp/targets
cp -r "$T" "$tmp/targets/ubuntu2404"
run() { : > "$tmp/log"; rm -rf "$tmp/o"; STUB_LOG=$tmp/log PATH="$tmp/bin:$PATH" E2E_TARGETS="$tmp/targets" E2E_PACKAGES="$tmp/pkgs" E2E_PACKAGES_NEXT="$tmp/nonext" E2E_PACKAGES_OLD="$tmp/noold" E2E_OUT="$tmp/o" "$ROOT/e2e/run.sh" "$@" > "$tmp/out" 2>&1; }
run ubuntu2404 || bad "the refusal target failed with no N+1 and no old package: $(tail -n 4 "$tmp/out")"
grep -q 'guest.sh ubuntu2404' "$tmp/log" || bad "the guest did not run"
[ "$(grep '^run ' "$tmp/log" | grep -o -- '-v [^ ]*:/pkg[^ ]*:ro' | sort -u | wc -l)" -eq 1 ] || bad "the refusal target mounts more than the package"
grep -q 'cases accounted for' "$tmp/out" || bad "the cases were not accounted for"
grep -q 'bus-daemon=dbus-daemon' "$tmp/o/ubuntu2404.record" || bad "no record"
for id in $want; do
    STUB_OMIT=$id run ubuntu2404 && bad "a run that omits $id passed"
    grep -q "'$id' was not reported" "$tmp/out" || bad "the omitted $id was not named"
done
first=$(ids_of "$ROOT/e2e/cases.list" | head -n 1)
STUB_EXTRA=$first run ubuntu2404 && bad "a common id was accepted from the refusal target"
grep -q "unknown case '$first'" "$tmp/out" || bad "a common id on the refusal target was not named: $(tail -n 3 "$tmp/out")"
# without the marker the same directory demands N+1 (and the common ids)
cp -r "$T" "$tmp/targets/ubuntu9999"
rm "$tmp/targets/ubuntu9999/refusal-only"
run ubuntu9999 && bad "a target without the marker ran with no package N+1"
grep -q 'no package N+1' "$tmp/out" || bad "the missing N+1 was not named: $(tail -n 3 "$tmp/out")"
grep -Eq '^(build|run|exec) ' "$tmp/log" && bad "the engine ran for a target without the marker and without N+1"
# a marked target with an old.pattern, or without its own cases, is refused
cp -r "$T" "$tmp/targets/ubuntu9998"
echo 'custodio_*.deb' > "$tmp/targets/ubuntu9998/old.pattern"
run ubuntu9998 && bad "a refusal-only target with an old.pattern was accepted"
rm -rf "$tmp/targets/ubuntu9998"
cp -r "$T" "$tmp/targets/ubuntu9997"
rm "$tmp/targets/ubuntu9997/cases.list"
run ubuntu9997 && bad "a refusal-only target without cases.list was accepted"
exit "$fail"
