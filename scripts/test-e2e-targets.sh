#!/usr/bin/env bash
# F45-F47: the target directories of e2e/targets/ (Containerfile, install.sh, probe.sh): no package is copied into an image, the install step
# uses the tool of the distribution on the mounted file, the real polkit and default bus daemon; controls per family; the shellcheck list.
# Split from test-e2e-host.sh, which tests the host script e2e/run.sh with a stub engine.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-targets: $*" >&2; fail=1; }

# --- the targets: no Containerfile copies a package, the install step uses the target's tool, the real polkit and bus daemon
for cf in "$ROOT"/e2e/targets/*/Containerfile; do
    if grep -Eqi '^[[:space:]]*(COPY|ADD)\b|\bcp\b.*(\.deb|\.rpm|\.pkg|custodio)|/pkg' "$cf"; then bad "$cf copies or names a package"; fi
done
printf 'FROM debian:trixie\nCOPY custodio.deb /tmp/\n' > "$tmp/CF.bad"
grep -Eqi '^[[:space:]]*(COPY|ADD)\b' "$tmp/CF.bad" || bad "control: a Containerfile that copies a .deb was not seen"
grep -q 'install.sh' "$ROOT/e2e/guest.sh" || bad "the guest does not call the target's install step"
if grep -En '\b(dpkg|apt|apt-get|rpm|pacman|dnf)\b|\b(cp|install)\b.* /(usr|etc)' "$ROOT/e2e/guest.sh" | grep -v '^[0-9]*:[[:space:]]*#' | grep -q .; then bad "the shared guest script calls a package tool or copies into /usr or /etc"; fi
# target_problems DIR: what is wrong with a target directory (empty output: nothing). The install step uses the tool of the
# distribution on the mounted file (ubuntu* must use apt, not only dpkg), the image has the real polkit and a default bus daemon.
target_problems() {
    local d=$1 n cf inst
    n=$(basename "$d")
    cf="$d/Containerfile"
    inst="$d/install.sh"
    for f in Containerfile install.sh probe.sh skip.list package.pattern; do [ -f "$d/$f" ] || echo "$n: no $f"; done
    # The package lists sit on the lines of the install command (with their continuations), not anywhere in the file.
    pkgs=$(sed -n '/\(apt-get\|apt\|dnf\)[^#]*install\|pacman[^#]*[[:space:]]-S/,/[^\\]$/p' "$cf" 2> /dev/null | grep -v '^[[:space:]]*#' || true)
    case $n in
    debian* | ubuntu*)
        grep -Eq '(^|[[:space:]])polkitd([[:space:]]|$)' <<< "$pkgs" || echo "$n: does not install polkitd"
        grep -Eq '(^|[[:space:]])dbus([[:space:]]|$)' <<< "$pkgs" || echo "$n: does not install dbus"
        if grep -qi 'dbus-broker' "$cf" 2> /dev/null; then echo "$n: installs dbus-broker"; fi
        if grep -Eq '(^|[[:space:]])dbus-daemon([[:space:]]|$)' <<< "$pkgs"; then echo "$n: forces dbus-daemon"; fi
        ;;
    fedora* | alma*)
        grep -Eq '(^|[[:space:]])polkit([[:space:]\\]|$)' <<< "$pkgs" || echo "$n: does not install polkit"
        grep -Eq '(^|[[:space:]])dbus([[:space:]\\]|$)' <<< "$pkgs" || echo "$n: does not install the dbus meta package"
        if grep -Eq '(^|[[:space:]])(dbus-broker|dbus-daemon)([[:space:]\\]|$)' <<< "$pkgs"; then echo "$n: names a bus daemon package"; fi
        ;;
    arch*)
        grep -Eq '(^|[[:space:]])polkit([[:space:]\\]|$)' <<< "$pkgs" || echo "$n: does not install polkit"
        if grep -Eq '(^|[[:space:]])(dbus|dbus-broker|dbus-broker-units|dbus-daemon-units)([[:space:]\\]|$)' <<< "$pkgs"; then echo "$n: names a bus package"; fi
        ;;
    esac
    grep -Eq 'dpkg|apt|rpm|dnf|pacman' "$inst" 2> /dev/null || echo "$n: install.sh uses no package tool"
    # shellcheck disable=SC2016 # the pattern looks for a literal "$1" in the script
    case $n in
    ubuntu*) grep -Eq '(^|[[:space:]])(apt|apt-get)[[:space:]].*\binstall\b.*"\$1"' "$inst" 2> /dev/null || echo "$n: install.sh does not apt install the mounted file" ;;
    fedora* | alma*) grep -Eq '(^|[[:space:]])dnf[[:space:]].*\binstall\b.*"\$1"' "$inst" 2> /dev/null || echo "$n: install.sh does not dnf install the mounted file" ;;
    arch*) grep -Eq '(^|[[:space:]])pacman[[:space:]]+(-[A-Za-z-]+[[:space:]]+)*-U[A-Za-z]*([[:space:]]+-[A-Za-z-]+)*[[:space:]]+"\$1"' "$inst" 2> /dev/null || echo "$n: install.sh does not pacman -U the mounted file" ;;
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
# controls for the rpm family: an accepted variant, then one change at a time that must be rejected
fx_rpm() { # NAME: a fedora-style fixture target with polkit + dbus + dnf install "$1"
    mkdir -p "$tmp/fx/$1"
    cp "$ROOT"/e2e/targets/debian13/{probe.sh,skip.list,package.pattern} "$tmp/fx/$1/"
    printf 'FROM docker.io/library/fedora:44\nRUN dnf install -y systemd dbus polkit python3-dbus && dnf clean all\n' > "$tmp/fx/$1/Containerfile"
    # shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
    printf '#!/usr/bin/env bash\nset -euo pipefail\ndnf install -y "$1" > /dev/null\n' > "$tmp/fx/$1/install.sh"
}
fx_rpm fedora9999
[ -z "$(target_problems "$tmp/fx/fedora9999")" ] || bad "control: a correct rpm target was rejected: $(target_problems "$tmp/fx/fedora9999")"
fx_rpm alma9999
[ -z "$(target_problems "$tmp/fx/alma9999")" ] || bad "control: a correct alma target was rejected: $(target_problems "$tmp/fx/alma9999")"
fx_rpm fedora9999
sed -i 's/ polkit / polkitd /' "$tmp/fx/fedora9999/Containerfile"
[ -n "$(target_problems "$tmp/fx/fedora9999")" ] || bad "control: a fedora target with polkitd instead of polkit was accepted"
fx_rpm fedora9999
sed -i 's/ dbus / dbus dbus-daemon /' "$tmp/fx/fedora9999/Containerfile"
[ -n "$(target_problems "$tmp/fx/fedora9999")" ] || bad "control: a fedora target that installs dbus-daemon was accepted"
fx_rpm fedora9999
sed -i 's/ dbus / dbus dbus-broker /' "$tmp/fx/fedora9999/Containerfile"
[ -n "$(target_problems "$tmp/fx/fedora9999")" ] || bad "control: a fedora target that installs dbus-broker was accepted"
fx_rpm fedora9999
sed -i 's/ dbus / /' "$tmp/fx/fedora9999/Containerfile"
[ -n "$(target_problems "$tmp/fx/fedora9999")" ] || bad "control: a fedora target without the dbus meta package (python3-dbus only) was accepted"
fx_rpm fedora9999
# shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
printf '#!/usr/bin/env bash\nset -euo pipefail\nrpm -i "$1"\n' > "$tmp/fx/fedora9999/install.sh"
[ -n "$(target_problems "$tmp/fx/fedora9999")" ] || bad "control: a fedora target that installs with rpm -i only was accepted"
# controls for the arch family
fx_arch() { # NAME: an arch-style fixture target with polkit, no bus package, pacman -U "$1"
    mkdir -p "$tmp/fx/$1"
    cp "$ROOT"/e2e/targets/debian13/{probe.sh,skip.list,package.pattern} "$tmp/fx/$1/"
    printf 'FROM docker.io/library/archlinux:latest\nRUN pacman -Syu --noconfirm --needed systemd polkit python-gobject && find /var/cache/pacman -type f -delete\n' > "$tmp/fx/$1/Containerfile"
    # shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
    printf '#!/usr/bin/env bash\nset -euo pipefail\npacman -U --noconfirm "$1" > /dev/null\n' > "$tmp/fx/$1/install.sh"
}
fx_arch arch9999
[ -z "$(target_problems "$tmp/fx/arch9999")" ] || bad "control: a correct arch target was rejected: $(target_problems "$tmp/fx/arch9999")"
arch_rejects() { # DESCRIPTION MESSAGE: the fixture arch9999 must be rejected with exactly this message
    local got
    got=$(target_problems "$tmp/fx/arch9999")
    grep -q "$2" <<< "$got" || bad "control: $1: expected '$2', got '$got'"
}
fx_arch arch9999
sed -i 's/ polkit / polkitd /' "$tmp/fx/arch9999/Containerfile"
arch_rejects "an arch target with polkitd instead of polkit" 'does not install polkit'
for pkg in dbus dbus-broker dbus-broker-units dbus-daemon-units; do
    fx_arch arch9999
    sed -i "s/ polkit / polkit $pkg /" "$tmp/fx/arch9999/Containerfile"
    arch_rejects "an arch target that names $pkg" 'names a bus package'
done
fx_arch arch9999
# shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
printf '#!/usr/bin/env bash\nset -euo pipefail\nbsdtar -xf "$1" -C /\n' > "$tmp/fx/arch9999/install.sh"
arch_rejects "an arch target that unpacks the files instead of pacman -U" 'install.sh uses no package tool'
fx_arch arch9999
# shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
printf '#!/usr/bin/env bash\nset -euo pipefail\ncp "$1" /tmp/x.pkg.tar.zst\npacman -U --noconfirm /tmp/x.pkg.tar.zst\n' > "$tmp/fx/arch9999/install.sh"
arch_rejects "an arch target that runs pacman -U on a copy" 'does not pacman -U the mounted file'
fx_arch arch9999
# shellcheck disable=SC2016 # the fixture script must contain a literal "$1"
printf '#!/usr/bin/env bash\nset -euo pipefail\npacman -S --noconfirm "$1"\n' > "$tmp/fx/arch9999/install.sh"
arch_rejects "an arch target that pacman -S the file" 'does not pacman -U the mounted file'
# a Debian target must not take the rpm names, and must not force dbus-daemon
cp -r "$ROOT/e2e/targets/debian13" "$tmp/fx/debian9999"
sed -i 's/ dbus / dbus dbus-daemon /' "$tmp/fx/debian9999/Containerfile"
[ -n "$(target_problems "$tmp/fx/debian9999")" ] || bad "control: a debian target that forces dbus-daemon was accepted"
rm "$tmp/fx/ubuntu9999/probe.sh"
[ -n "$(target_problems "$tmp/fx/ubuntu9999")" ] || bad "control: a target without probe.sh was accepted"
grep -rqi 'polkit' "$ROOT/e2e/targets" || bad "no target mentions polkit"

# --- shellcheck covers the new scripts
list=$("$ROOT/scripts/list-shell-scripts.sh")
targets_scripts=()
for d in "$ROOT"/e2e/targets/*/; do targets_scripts+=("e2e/targets/$(basename "$d")/install.sh" "e2e/targets/$(basename "$d")/probe.sh" "e2e/targets/$(basename "$d")/remove.sh")
    [ ! -f "$d/purge.sh" ] || targets_scripts+=("e2e/targets/$(basename "$d")/purge.sh"); done
for f in e2e/run.sh e2e/check-cases.sh e2e/check-next.sh e2e/report.sh e2e/upgrade.sh e2e/upgrade-lib.sh e2e/upgrade-selftest.sh e2e/upgrade-user.sh e2e/lifecycle.sh e2e/lifecycle-lib.sh e2e/lifecycle-selftest.sh scripts/test-e2e-lifecycle.sh scripts/package-next.sh scripts/package-old.sh scripts/test-e2e-old.sh "${targets_scripts[@]}" scripts/test-e2e-host.sh scripts/test-e2e-targets.sh scripts/test-e2e-upgrade.sh scripts/test-e2e-skips.sh scripts/test-e2e-catalog.sh; do
    grep -qx "$f" <<< "$list" || bad "$f is not in the shellcheck list"
done

exit "$fail"
