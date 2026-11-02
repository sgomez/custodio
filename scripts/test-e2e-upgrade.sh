#!/usr/bin/env bash
# F48: the self-test of the upgrade checks of the e2e suite (e2e/upgrade-selftest.sh) and the host check of the package pair
# (e2e/check-next.sh) on fixture packages built with nfpm: N+1 with only the version raised passes; the same version, another
# custodiod, another file list, another format and the same file are each rejected with their own message.
# shellcheck disable=SC2016 # the patterns handed to mutant and before are text for sed and grep: single quotes keep the dollar signs literal
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
fail=0
bad() { echo "test-e2e-upgrade: $*" >&2; fail=1; }

bash "$ROOT/e2e/upgrade-selftest.sh" > /dev/null || bad "the upgrade self-test failed"
bash "$ROOT/e2e/upgrade-accts-selftest.sh" || bad "the upgrade accounts self-test failed"

# --- F96: a mutant of each judgement of upgrade-accts-lib.sh makes the self-test fail.
mt=$(mktemp -d)
cp "$ROOT/e2e/upgrade-accts-selftest.sh" "$mt/"
# mutant NAME SED-EXPRESSION: the library with one change; the self-test must fail on it (and the change must change the file)
mutant() {
    sed "$2" "$ROOT/e2e/upgrade-accts-lib.sh" > "$mt/upgrade-accts-lib.sh"
    if cmp -s "$mt/upgrade-accts-lib.sh" "$ROOT/e2e/upgrade-accts-lib.sh"; then bad "mutant $1 changed nothing"; return; fi
    if bash "$mt/upgrade-accts-selftest.sh" > /dev/null 2>&1; then bad "mutant $1: the self-test still passed"; fi
}
mutant list-exact 's/\[ "\$got" = "\$want" \] && return/return/'
mutant same-cert 's/\[ "\$(acct_sha "\$dir\/alice-rsa1.der")" = "\$(acct_sha "\$dir\/bob-rsa1.der")" \]/false/'
mutant old-cert 's/\[ "\$(acct_sha "\$acc\/after\/bob-rsa1.der")" != "\$(acct_sha "\$acc\/bob-old.der")" \]/true/'
mutant new-cert 's/\[ "\$(acct_sha "\$acc\/after\/bob-rsa1.der")" = "\$(acct_sha "\$acc\/bob-new.der")" \]/true/'
mutant certs-kept 's/\[ "\$(acct_sha "\$acc\/before\/\$u-\$id.der")" = "\$(acct_sha "\$acc\/after\/\$u-\$id.der")" \]/true/'
mutant list-kept 's/"\$(acct_sha "\$acc\/before\/\$u.list")" != "\$(acct_sha "\$acc\/after\/\$u.list")"/false/'
mutant state-owner 's/\[ "\$owner" = "\$cu" \] || echo "state: \.\/\$uid/true || echo "state: .\/$uid/'
mutant state-mode 's/\[ "\$mode" = 600 \]/true/'
mutant state-stray 's/\[\[ " \$want " == \*" \$path "\* \]\]/true/'
mutant state-same-file 's/\[ "\${seen\[\.\/\$au\/rsa1\]##\* }" != "\${seen\[\.\/\$bu\/rsa1\]##\* }" \]/true/'
mutant sign-requests 's/\[ "\$req" = 1 \] || echo "\$u: the signature/true || echo "$u: the signature/'
mutant sign-own 's/acct_verifies "\$f.sig" "\$acc\/sign\/data.bin" "\$acc\/after\/\$u-\$id.der" "\$id" ||/true ||/'
mutant sign-other 's/! acct_verifies "\$f.sig" "\$acc\/sign\/data.bin" "\$acc\/after\/\$o-\$n.der" "\$id" ||/true ||/'
mutant denied-status 's/\[ "\$st" != 0 \]/true/'
mutant denied-asked 's/\[ "\${req:-}" = 1 \] || echo "\$u: the denied/true || echo "$u: the denied/'
rm -rf "$mt"

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

# --- F60: the case itself (e2e/upgrade.sh) with stub tools: an equal, a lower or a mismatching version never reaches the install command.
# The install command is a marker script (E2E_INSTALL) that fails, so a pair that gets as far as the install stops there.
t=$(mktemp -d)
trap 'fx_cleanup; rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/state"
printf 'key\n' > "$t/state/a.p12"
printf 'key\n' > "$t/state/b.p12"
printf '%s\n' 0.1.0-1 > "$t/from.deb"
printf '%s\n' 0.1.0-1 > "$t/equal.deb"
printf '%s\n' 0.0.9-1 > "$t/lower.deb"
printf '%s\n' 0.1.1-1 > "$t/greater.deb"
cat > "$t/bin/dpkg-deb" <<'STUB'
#!/bin/sh
# dpkg-deb -f FILE Version: the first line of the fixture file
head -n 1 "$2"
STUB
cat > "$t/bin/dpkg-query" <<'STUB'
#!/bin/sh
printf '%s' "$STUB_INSTALLED"
STUB
cat > "$t/bin/systemctl" <<'STUB'
#!/bin/sh
case "$*" in
"is-active --quiet custodio") [ -n "$STUB_ACTIVE" ] ;;
"show -p MainPID --value custodio") echo "$STUB_PID" ;;
"show -p FragmentPath --value custodio") echo "$STUB_UNIT" ;;
*) echo "unexpected systemctl $*" >&2; exit 9 ;;
esac
STUB
cat > "$t/bin/su" <<'STUB'
#!/bin/sh
printf 'Slot 0\n token label: rsa1\nSlot 1\n token label: ec1\n'
STUB
cat > "$t/bin/id" <<'STUB'
#!/bin/sh
echo 4242
STUB
cat > "$t/install.sh" <<'STUB'
#!/bin/sh
echo "$1" >> "$MARKER"
exit 1
STUB
chmod +x "$t/bin/"* "$t/install.sh"
# resolve the binary first: reading /proc/PID/exe right after the fork can still name bash
sleep_bin=$(readlink -f "$(command -v sleep)")
"$sleep_bin" 300 &
sleeper=$!
trap 'kill $sleeper 2> /dev/null || true; fx_cleanup; rm -rf "$t"' EXIT
printf '[Service]\nExecStart=-%s --arg\n' "$sleep_bin" > "$t/custodio.service"
# case_upgrade INSTALLED TO_FILE [ACTIVE]: the case from from.deb to TO_FILE; the output in $t/out, the status returned
case_upgrade() {
    rm -f "$t/marker"
    env PATH="$t/bin:$PATH" MARKER="$t/marker" STUB_INSTALLED="$1" STUB_ACTIVE="${3-1}" STUB_PID="$sleeper" STUB_UNIT="$t/custodio.service" \
        E2E_NO_SELFTEST=1 E2E_NO_ACCOUNTS=1 E2E_INSTALL="$t/install.sh" STATE_LINK="$t/state" WORK="$t" MODULE=/none \
        bash "$ROOT/e2e/upgrade.sh" "$t/from.deb" "$2" > "$t/out" 2>&1
}
# stops WORD: the case fails with WORD in its output and the install command was not run
stops() {
    local what=$1 word=$2
    shift 2
    if case_upgrade "$@"; then bad "$what: the case passed"; return; fi
    grep -q -- "$word" "$t/out" || bad "$what: no '$word' in the output: $(tail -n 3 "$t/out")"
    [ ! -e "$t/marker" ] || bad "$what: the install command was reached"
}
stops "an equal version" 'same version' 0.1.0-1 "$t/equal.deb"
stops "a lower version" 'not greater' 0.1.0-1 "$t/lower.deb"
stops "a database that does not hold the old version" 'the database holds' 0.5.0-1 "$t/greater.deb"
stops "the same file twice" 'two package files' 0.1.0-1 "$t/from.deb"
# a greater version passes the gate and, with the service up, reaches the install command (so the marker does detect it)
if case_upgrade 0.1.0-1 "$t/greater.deb"; then bad "a stubbed install that fails let the case pass"; fi
grep -q 'is greater than 0.1.0-1' "$t/out" || bad "a greater version did not pass the gate: $(tail -n 3 "$t/out")"
{ [ -e "$t/marker" ] && grep -q greater.deb "$t/marker"; } || bad "control: a greater version did not reach the install command: $(tail -n 4 "$t/out")"
# the service is not running: the case stops before the install as well
stops "a service that is not running" 'was not running' 0.1.0-1 "$t/greater.deb" ''
# the case ids are registered for the old-package run, as the case reports them
for suffix in version-greater service-new-binary state-unchanged keys-listed signs-with-polkit no-manual-step; do
    grep -q "case_run \"\$id-$suffix\"" "$ROOT/e2e/upgrade.sh" || bad "upgrade.sh does not report \$id-$suffix"
done
# --- F96: the accounts part sits where the cases need it (the seed before the install, each judgement before its case).
line() { grep -n -- "$1" "$ROOT/e2e/upgrade.sh" | head -n 1 | cut -d: -f1; }
before() { # WHAT A B: line A is found and comes before line B
    local a b
    a=$(line "$2")
    b=$(line "$3")
    { [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; } || bad "upgrade.sh: $1 does not come before it should ('$2' at '${a:-none}', '$3' at '${b:-none}')"
}
before "the seed" 'accts seed' 'snapshot_state "$STATE_LINK" > "$WORK/state.before"'
before "the seed judgement" 'acct_seed_problems' 'snapshot_state "$STATE_LINK" > "$WORK/state.before"'
before "the seed" 'accts seed' 'bash "$install"'
before "the state judgement" 'acct_state_problems' 'case_run "$id-state-unchanged"'
before "the lists judgement" 'acct_after_problems' 'case_run "$id-keys-listed"'
before "alice's signatures" 'acct_sign_problems "$ACC" alice' 'case_run "$id-signs-with-polkit"'
before "bob's signatures" 'acct_sign_problems "$ACC" bob' 'case_run "$id-signs-with-polkit"'
before "the cleanup" 'accts cleanup' '^# END upgrade-case'
exit "$fail"
