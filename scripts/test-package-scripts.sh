#!/usr/bin/env bash
# The post scripts of the three packages do only what the M1 postinst did: three recorded calls, each with `|| true`. The pre-install
# scripts are the ProcessFD check of F42 (scripts/test-bus-check.sh runs them). Builds fixture packages with nfpm and runs the extracted
# scripts with recording stubs for systemd-sysusers and systemctl.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"

fx_init
tmp=$(mktemp -d)
trap 'fx_cleanup; rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-package-scripts: $*" >&2; fail=1; }

# Stubs record "name args" lines in $tmp/calls; with STUB_EXIT=1 they fail.
mkdir "$tmp/stubs"
for s in systemd-sysusers systemctl deb-systemd-invoke; do
    # shellcheck disable=SC2016 # the stub expands $CALLS and $STUB_EXIT itself
    printf '#!/bin/sh\necho "%s $*" >> "$CALLS"\nexit "${STUB_EXIT:-0}"\n' "$s" > "$tmp/stubs/$s"
    chmod +x "$tmp/stubs/$s"
done
expected=$'systemd-sysusers custodio.conf\nsystemctl daemon-reload\nsystemctl reload dbus'
expected_deb=$'systemd-sysusers custodio.conf\nsystemctl daemon-reload\ndeb-systemd-invoke reload dbus.service'

# run_case LABEL EXPECTED_CALLS STUB_EXIT COMMAND...: run the command with the stubs first on PATH.
run_case() {
    local label=$1 want=$2 stub_exit=$3 status=0
    shift 3
    : > "$tmp/calls"
    PATH="$tmp/stubs:/usr/bin:/bin" CALLS="$tmp/calls" STUB_EXIT=$stub_exit "$@" || status=$?
    [ "$status" -eq 0 ] || bad "$label: exit status $status"
    [ "$(cat "$tmp/calls")" = "$want" ] || bad "$label: calls were: $(tr '\n' ';' < "$tmp/calls")"
}

fx_build real 0.1.0 "" none
for fmt in "${FORMATS[@]}"; do fx_scripts real "$fmt" "$tmp/$fmt"; done

# Source files and rendered scripts are valid shell and pass shellcheck.
for f in packaging/deb/postinst packaging/rpm/post packaging/arch/post_install packaging/arch/post_upgrade \
    packaging/deb/preinst packaging/rpm/pre packaging/arch/pre_install packaging/arch/pre_upgrade packaging/arch/custodio-bus-check; do
    head -n 1 "$ROOT/$f" | grep -qx '#!/bin/sh' || bad "$f does not start with #!/bin/sh"
    sh -n "$ROOT/$f" || bad "$f: sh -n failed"
    shellcheck "$ROOT/$f" || bad "$f: shellcheck failed"
done
# Eight lifecycle script files, the hook script and the hook definition, each its own path.
[ "$(find "$ROOT/packaging/deb" "$ROOT/packaging/rpm" "$ROOT/packaging/arch" -mindepth 1 -type f | wc -l)" -eq 10 ] || bad "the script files are not ten distinct paths"
for f in "$tmp/deb/postinst" "$tmp/rpm/post" "$tmp/deb/preinst" "$tmp/rpm/pre" "$tmp/archlinux/hook-check"; do sh -n "$f" || bad "rendered $f: sh -n failed"; done
bash -n "$tmp/archlinux/INSTALL" || bad "rendered .INSTALL: bash -n failed"
shellcheck -s bash "$tmp/archlinux/INSTALL" "$tmp/deb/postinst" "$tmp/rpm/post" "$tmp/deb/preinst" "$tmp/rpm/pre" "$tmp/archlinux/hook-check" || bad "rendered scripts: shellcheck failed"

# The exact set of scripts per format.
for f in prerm postrm; do [ ! -e "$tmp/deb/ctl/$f" ] || bad "deb has a $f"; done
# The embedded check is a function of its own; the others are the four lifecycle functions.
[ "$(grep -oE '^ *(function )?[a-z_]+\(\)' "$tmp/archlinux/INSTALL" | sed 's/^ *//; s/^function //; s/()//' | sort | tr '\n' ' ')" = "custodio_bus_check custodio_bus_check post_install post_upgrade pre_install pre_upgrade " ] \
    || bad ".INSTALL does not define exactly pre_install, pre_upgrade, post_install and post_upgrade (and the check twice)"
for tag in PREUN POSTUN PRETRANS POSTTRANS; do
    [ -z "$(fx_rpm -qp --qf "%{$tag}" "$(fx_file real rpm)" | grep -v '(none)' || true)" ] || bad "rpm has a $tag scriptlet"
done

for stub_exit in 0 1; do
    suffix=; [ "$stub_exit" = 0 ] || suffix=" (every stub fails)"
    run_case "deb postinst configure$suffix" "$expected_deb" $stub_exit sh "$tmp/deb/postinst" configure
    run_case "deb postinst abort-upgrade$suffix" "" $stub_exit sh "$tmp/deb/postinst" abort-upgrade
    run_case "rpm post 1$suffix" "$expected" $stub_exit sh "$tmp/rpm/post" 1
    run_case "rpm post 2$suffix" "$expected" $stub_exit sh "$tmp/rpm/post" 2
    for fn in post_install post_upgrade; do
        run_case "arch $fn$suffix" "$expected" $stub_exit bash -c ". '$tmp/archlinux/INSTALL'; $fn"
    done
done

exit "$fail"
