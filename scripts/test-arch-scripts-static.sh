#!/usr/bin/env bash
# Gates on the install scripts as the built Arch package says them (F58): the .INSTALL defines the six functions with the source files'
# commands and parses, and the two hooks are in the package as the source files, the restart hook with mode 0644. What the scripts and
# the hook do is in scripts/test-arch-lifecycle.sh; the real pacman is in scripts/test-arch-lifecycle-real.sh.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
SRC=$ROOT/packaging/arch
fx_init
trap fx_cleanup EXIT
fail=0
bad() { echo "test-arch-scripts-static: $*" >&2; fail=1; }

fx_build real 0.1.0 "" none
tmp=$FX_DIR/arch-scripts
fx_scripts real archlinux "$tmp"
for fn in pre_install post_install pre_upgrade post_upgrade pre_remove post_remove; do
    grep -qE "^(function )?$fn\\(\\)" "$tmp/INSTALL" || bad "the .INSTALL of the built package does not define $fn"
done
bash -n "$tmp/INSTALL" || bad "the .INSTALL: bash -n failed"
pkg=$(fx_file real archlinux)
listing=$(bsdtar -tvf "$pkg")
grep -qE '^-rw-r--r-- .* usr/share/libalpm/hooks/zz-custodio-restart.hook$' <<< "$listing" || bad "the package does not hold zz-custodio-restart.hook with mode 0644"
cmp -s <(bsdtar -xOf "$pkg" usr/share/libalpm/hooks/zz-custodio-restart.hook) "$SRC/zz-custodio-restart.hook" || bad "the packaged restart hook is not packaging/arch/zz-custodio-restart.hook"
cmp -s <(bsdtar -xOf "$pkg" usr/share/libalpm/hooks/custodio-bus-check.hook) "$SRC/custodio-bus-check.hook" || bad "the packaged check hook is not packaging/arch/custodio-bus-check.hook"
# The functions of the .INSTALL hold the source files' commands (the wrapper adds only the function line and the closing brace).
for fn in pre_install pre_upgrade post_install post_upgrade pre_remove post_remove; do
    body=$(awk -v fn="$fn" '$0 ~ "^function " fn "\\(\\)" { on = 1; next } /^function / { on = 0 } on { print }' "$tmp/INSTALL" | tac | sed '0,/^}$/d' | tac)
    [ "$body" = "$(cat "$SRC/$fn")" ] || bad "the $fn of the built .INSTALL is not packaging/arch/$fn"
done
exit "$fail"
