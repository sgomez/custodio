#!/usr/bin/env bash
# The pre-install scripts of the Arch package are the ProcessFD check of F42 (scripts/test-bus-check.sh runs them) and the account of F58; its
# other four functions and its restart hook are F58's (scripts/test-arch-lifecycle.sh runs them). The four maintainer scripts of the deb are F43's
# (scripts/test-deb-lifecycle.sh runs them) and the four scriptlets of the rpm are F44's (scripts/test-rpm-lifecycle.sh); here they are
# only checked to be shell, to pass shellcheck and to be in the package.
# Builds fixture packages with nfpm and runs the extracted scripts with recording stubs for systemd-sysusers and systemctl.
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
for f in packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm packaging/rpm/post packaging/rpm/preun packaging/rpm/postun packaging/arch/post_install packaging/arch/post_upgrade packaging/arch/pre_remove packaging/arch/post_remove \
    packaging/deb/preinst packaging/rpm/pre packaging/arch/pre_install packaging/arch/pre_upgrade packaging/arch/custodio-bus-check; do
    head -n 1 "$ROOT/$f" | grep -qx '#!/bin/sh' || bad "$f does not start with #!/bin/sh"
    sh -n "$ROOT/$f" || bad "$f: sh -n failed"
    shellcheck "$ROOT/$f" || bad "$f: shellcheck failed"
done
# Twelve lifecycle script files (four of the deb, four of the rpm, four of the Arch .INSTALL scripts besides pre_install and pre_upgrade counted
# below), the hook script and the two hook definitions: seventeen files, each its own path.
[ "$(find "$ROOT/packaging/deb" "$ROOT/packaging/rpm" "$ROOT/packaging/arch" -mindepth 1 -type f | wc -l)" -eq 17 ] || bad "the script files are not seventeen distinct paths"
for f in "$tmp/deb/postinst" "$tmp/deb/prerm" "$tmp/deb/postrm" "$tmp/rpm/post" "$tmp/rpm/preun" "$tmp/rpm/postun" "$tmp/deb/preinst" "$tmp/rpm/pre" "$tmp/archlinux/hook-check"; do sh -n "$f" || bad "rendered $f: sh -n failed"; done
bash -n "$tmp/archlinux/INSTALL" || bad "rendered .INSTALL: bash -n failed"
shellcheck -s bash "$tmp/archlinux/INSTALL" "$tmp/deb/postinst" "$tmp/deb/prerm" "$tmp/deb/postrm" "$tmp/rpm/post" "$tmp/rpm/preun" "$tmp/rpm/postun" "$tmp/deb/preinst" "$tmp/rpm/pre" "$tmp/archlinux/hook-check" || bad "rendered scripts: shellcheck failed"

# The exact set of scripts per format: the deb has all four maintainer scripts, executable, and the packaged ones are the source files.
for f in preinst postinst prerm postrm; do
    [ -x "$tmp/deb/ctl/$f" ] || bad "the deb has no executable $f"
    [ "$(stat -c %a "$tmp/deb/ctl/$f")" = 755 ] || bad "deb $f is not mode 0755"
    cmp -s "$tmp/deb/ctl/$f" "$ROOT/packaging/deb/$f" || bad "deb $f is not packaging/deb/$f"
done
[ "$(find "$tmp/deb/ctl" -type f -not -name md5sums -not -name control | sort | xargs -n1 basename | tr '\n' ' ')" = "postinst postrm preinst prerm " ] || bad "the deb control archive holds other files than the four scripts"
# The embedded check is a function of its own; the others are the four lifecycle functions.
[ "$(grep -oE '^ *(function )?[a-z_]+\(\)' "$tmp/archlinux/INSTALL" | sed 's/^ *//; s/^function //; s/()//' | sort | tr '\n' ' ')" = "custodio_bus_check custodio_bus_check custodio_create_account custodio_create_account post_install post_remove post_upgrade pre_install pre_remove pre_upgrade " ] \
    || bad ".INSTALL does not define exactly pre_install, pre_upgrade, post_install, post_upgrade, pre_remove and post_remove (and the check and the account twice)"
# The rpm has the four scriptlets (the packaged ones are the source files) and no %pretrans or %posttrans.
for pair in pre:PREIN post:POSTIN preun:PREUN postun:POSTUN; do
    cmp -s "$tmp/rpm/${pair%%:*}" "$ROOT/packaging/rpm/${pair%%:*}" || bad "rpm ${pair##*:} is not packaging/rpm/${pair%%:*}"
done
for tag in PRETRANS POSTTRANS; do
    [ -z "$(fx_rpm -qp --qf "%{$tag}" "$(fx_file real rpm)" | grep -v '(none)' || true)" ] || bad "rpm has a $tag scriptlet"
done

# post_install and post_upgrade of the built .INSTALL call nothing (the hooks do): no recorded call, whether the stubs fail or not.
for stub_exit in 0 1; do
    suffix=; [ "$stub_exit" = 0 ] || suffix=" (every stub fails)"
    for fn in post_install post_upgrade; do
        run_case "arch $fn$suffix" "" $stub_exit bash -c ". '$tmp/archlinux/INSTALL'; $fn"
    done
done

exit "$fail"
