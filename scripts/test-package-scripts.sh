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
    PATH="$tmp/stubs:/usr/bin:/bin" CALLS="$tmp/calls" STUB_EXIT=$stub_exit "$@" 2>/dev/null || status=$?
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

# post_install and post_upgrade of the built .INSTALL only enable and start the socket of the Firefox snap (F173); the hooks do the rest. The calls
# depend on the stubs: with every stub succeeding the socket is already active after the upgrade, with every stub failing it is not and the service
# is not either.
SOCK=custodio-firefox.socket
for stub_exit in 0 1; do
    suffix=; [ "$stub_exit" = 0 ] || suffix=" (every stub fails)"
    for fn in post_install post_upgrade; do
        case $fn:$stub_exit in
        post_install:*) want="systemctl enable $SOCK"$'\n'"systemctl start $SOCK" ;;
        post_upgrade:0) want="systemctl enable $SOCK"$'\n'"systemctl is-active --quiet $SOCK" ;;
        post_upgrade:1) want="systemctl enable $SOCK"$'\n'"systemctl is-active --quiet $SOCK"$'\n'"systemctl is-active --quiet custodio.service"$'\n'"systemctl start $SOCK" ;;
        esac
        run_case "arch $fn$suffix" "$want" $stub_exit bash -c ". '$tmp/archlinux/INSTALL'; $fn"
    done
done

# The install notice (acceptance 5): the real install script of each format, extracted from the fixture package, prints it on stderr after a first install
# and prints nothing on an upgrade; the exit status and the calls are those of the cases above. The removal scripts say nothing about PAM or the fingerprint.
# err_case LABEL WANT(notice|none) COMMAND...: stderr of the command, run with the stubs, holds the notice or is empty of "fingerprint".
err_case() {
    local label=$1 want=$2 status=0
    shift 2
    : > "$tmp/calls"
    PATH="$tmp/stubs:/usr/bin:/bin" CALLS="$tmp/calls" "$@" 2> "$tmp/err" > /dev/null || status=$?
    [ "$status" -eq 0 ] || bad "$label: exit status $status"
    if [ "$want" = notice ]; then
        grep -qF 'fingerprint is off' "$tmp/err" || bad "$label: the notice does not say the fingerprint is off: $(cat "$tmp/err")"
        grep -qF 'sudo custodio fingerprint enable' "$tmp/err" || bad "$label: the notice lacks the enable command"
        grep -qF 'custodio doctor' "$tmp/err" || bad "$label: the notice lacks custodio doctor"
    else
        grep -qiE 'fingerprint|doctor' "$tmp/err" && bad "$label: unexpected notice: $(cat "$tmp/err")"
    fi
    return 0
}
err_case "deb postinst configure (install)" notice sh "$tmp/deb/postinst" configure
err_case "deb postinst configure (upgrade)" none sh "$tmp/deb/postinst" configure 0.0.9
err_case "rpm post (install)" notice sh "$tmp/rpm/post" 1
err_case "rpm post (upgrade)" none sh "$tmp/rpm/post" 2
err_case "arch post_install" notice bash -c ". '$tmp/archlinux/INSTALL'; post_install"
err_case "arch post_upgrade" none bash -c ". '$tmp/archlinux/INSTALL'; post_upgrade"

# no_pam LABEL COMMAND...: the removal script prints nothing about PAM or the fingerprint (stdout and stderr).
no_pam() {
    local label=$1
    shift
    : > "$tmp/calls"
    PATH="$tmp/stubs:/usr/bin:/bin" CALLS="$tmp/calls" "$@" > "$tmp/out" 2>&1 || true
    ! grep -qiE 'pam\.d|pam_|fingerprint' "$tmp/out" || bad "$label: the removal output mentions PAM or the fingerprint: $(cat "$tmp/out")"
}
no_pam "deb prerm remove" sh "$tmp/deb/prerm" remove
no_pam "deb postrm remove" sh "$tmp/deb/postrm" remove
no_pam "deb postrm purge" sh "$tmp/deb/postrm" purge
no_pam "rpm preun" sh "$tmp/rpm/preun" 0
no_pam "rpm postun" sh "$tmp/rpm/postun" 0
no_pam "arch pre_remove" bash -c ". '$tmp/archlinux/INSTALL'; pre_remove"
no_pam "arch post_remove" bash -c ". '$tmp/archlinux/INSTALL'; post_remove"

exit "$fail"
