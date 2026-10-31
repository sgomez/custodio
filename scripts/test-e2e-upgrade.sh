#!/usr/bin/env bash
# F48: the self-test of the upgrade checks of the e2e suite (e2e/upgrade-selftest.sh) and the host check of the package pair
# (e2e/check-next.sh) on fixture packages built with nfpm: N+1 with only the version raised passes; the same version, another
# custodiod, another file list, another format and the same file are each rejected with their own message.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
fail=0
bad() { echo "test-e2e-upgrade: $*" >&2; fail=1; }

bash "$ROOT/e2e/upgrade-selftest.sh" > /dev/null || bad "the upgrade self-test failed"

fx_init
trap fx_cleanup EXIT
fx_build cur 0.1.0 '' none
fx_build next 0.1.1 '' none
fx_build same 0.1.0 '' none
fx_build files 0.1.1 '' add /usr/share/custodio/extra
printf 'another build\n' >> "$FX_DIR/target/release/custodiod"
fx_build bin 0.1.1 '' none

CHECK=$ROOT/e2e/check-next.sh
# expect CASE WORD N N1: the check rejects with WORD in its message ('' when it must pass)
expect() {
    local what=$1 word=$2 out
    shift 2
    if out=$(bash "$CHECK" "$@" 2>&1); then
        [ -z "$word" ] || bad "$what: accepted"
    else
        [ -n "$word" ] || { bad "$what: rejected: $out"; return; }
        grep -q -- "$word" <<< "$out" || bad "$what: rejected without '$word': $out"
    fi
}
for fmt in deb rpm archlinux; do
    c=$(fx_file cur "$fmt")
    expect "$fmt: only the version raised" '' "$c" "$(fx_file next "$fmt")"
    expect "$fmt: the same version" 'same version' "$c" "$(fx_file same "$fmt")"
    expect "$fmt: another custodiod" 'custodiod of N+1 differs' "$c" "$(fx_file bin "$fmt")"
    expect "$fmt: another file list" 'file lists' "$c" "$(fx_file files "$fmt")"
    expect "$fmt: N and N+1 are one file" 'same file' "$c" "$c"
done
expect "formats differ" 'not in the same format' "$(fx_file cur deb)" "$(fx_file next rpm)"
expect "no such file" 'no such file' "$(fx_file cur deb)" "$FX_DIR/none.deb"
exit "$fail"
