#!/usr/bin/env bash
# Gates on the scriptlets as the built .rpm says them (F44, `rpm -qp`): the four are there and equal the source files, none holds an rpm
# macro (nfpm writes the text as it is), and the package has no trigger, no %pretrans or %posttrans and provides no account. What the
# scriptlets do is in scripts/test-rpm-lifecycle.sh.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
SRC=$ROOT/packaging/rpm
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-rpm-scripts-static: $*" >&2; fail=1; }

# macro_hits TEXT: an rpm macro left in a scriptlet text.
macro_hits() { grep -E '%\{|%systemd_|%sysusers_|%tmpfiles_' <<< "$1" || true; }

fx_build real 0.1.0 "" none
pkg=$(fx_file real rpm)
scripts=$(fx_rpm -qp --scripts "$pkg")
for tag in preinstall postinstall preuninstall postuninstall; do grep -q "^$tag scriptlet" <<< "$scripts" || bad "the built rpm has no $tag scriptlet"; done
[ -z "$(macro_hits "$scripts")" ] || bad "the built rpm has an unexpanded macro: $(macro_hits "$scripts")"
for tag in PRETRANS POSTTRANS; do [ -z "$(fx_rpm -qp --qf "%{$tag}" "$pkg" | grep -v '(none)' || true)" ] || bad "the built rpm has a $tag scriptlet"; done
# The scriptlets in the package are the source files.
for pair in PREIN:pre POSTIN:post PREUN:preun POSTUN:postun; do
    [ "$(fx_rpm -qp --qf "%{${pair%%:*}}" "$pkg")" = "$(cat "$SRC/${pair##*:}")" ] || bad "rpm ${pair%%:*} is not packaging/rpm/${pair##*:}"
done
# rpm's own sysusers step would create the account for a user() or group() provide before the F42 check runs (docs/decisions/packaging.md, F44).
account_provides() { grep -E '^(user|group)\(' <<< "$(fx_rpm -qp --provides "$1")" || true; }
[ -z "$(account_provides "$pkg")" ] || bad "the built rpm provides an account: $(account_provides "$pkg")"
[ -z "$(fx_rpm -qp --triggers "$pkg" | grep -v '^$' || true)" ] || bad "the built rpm has a trigger"

# A package built with a macro in a scriptlet is seen in `rpm -qp --scripts`.
{ cat "$SRC/postun"; echo '%systemd_postun_with_restart custodio.service'; } > "$FX_DIR/postun-macro"
python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$ROOT/packaging/nfpm.yaml" "$FX_DIR/nfpm-macro.yaml" script-set rpm postremove postun-macro
(cd "$FX_DIR" && NFPM_VERSION=0.1.0 NFPM_PRERELEASE='' nfpm package -f nfpm-macro.yaml -p rpm -t "$FX_DIR/out" > /dev/null)
macro_pkg=$(ls "$FX_DIR"/out/*.rpm)
[ -n "$(macro_hits "$(fx_rpm -qp --scripts "$macro_pkg")")" ] || bad "control: the macro gate did not see a macro in a built rpm"

# A package with a user() provide is seen by the account gate.
fx_build userprov 0.1.0 "" provides-add rpm 'user(custodio)'
[ -n "$(account_provides "$(fx_file userprov rpm)")" ] || bad "control: the account-provides gate did not see user(custodio)"
fx_build groupprov 0.1.0 "" provides-add rpm 'group(custodio)'
[ -n "$(account_provides "$(fx_file groupprov rpm)")" ] || bad "control: the account-provides gate did not see group(custodio)"
exit "$fail"
