#!/usr/bin/env bash
# F97: container-free checks of the cli-* cases: the self-test of the judgements (e2e/cli-selftest.sh) passes, a weakened judgement makes it fail, guest.sh runs the
# step behind phase_runs after appid and before the upgrade, and cli-run.sh reports every id of the list.
# NOT checked here: a real run (`just e2e-cases debian13 'cli-*'`).
# shellcheck disable=SC2016 # the sed expressions of the mutants hold literal $ on purpose
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-cli: $*" >&2; fail=1; }

bash "$ROOT/e2e/cli-selftest.sh" || bad "the self-test of the cli judgements fails"
mutant() { # NAME SED-EXPRESSION: a copy of cli-lib.sh whose judgement is weakened must be caught by the self-test
    mkdir "$tmp/$1"
    cp "$ROOT"/e2e/cli-selftest.sh "$ROOT"/e2e/rd-lib.sh "$ROOT"/e2e/ops-lib.sh "$ROOT"/e2e/owner-lib.sh "$tmp/$1/"
    sed "$2" "$ROOT/e2e/cli-lib.sh" > "$tmp/$1/cli-lib.sh"
    if cmp -s "$ROOT/e2e/cli-lib.sh" "$tmp/$1/cli-lib.sh"; then bad "mutant $1 changes nothing"; fi
    if bash "$tmp/$1/cli-selftest.sh" > /dev/null 2>&1; then bad "mutant $1 was not caught"; fi
}
mutant type-ignored 's/grep -qxF "  type: \$3" ||/true ||/'
mutant subject-ignored 's/grep -qxF "  subject: \$4" ||/true ||/'
mutant end-ignored 's/grep -qxF "  valid until: \$5" ||/true ||/'
mutant only-ignored 's/\[ "\$want" = "\$got" \] ||/true ||/'
mutant none-exit 's/\[ "\$2" = 0 \] || echo "the list of an account/true || echo "the list of an account/'
mutant none-keys 's/! grep -q .\^id: . "\$1" || echo "\$1 shows a key block/true || echo "\$1 shows a key block/'
mutant has-keys 's/grep -q .\^id: . "\$1" || echo "\$1 shows no key/true || echo "\$1 shows no key/'
mutant confirm-late 's/\$3 != "requests=0" \&\& //'
mutant confirm-text 's/grep -qF .cannot be recovered. "\$1" ||/true ||/'
mutant prompt-header 's/grep -qF "AUTHENTICATING FOR \$3" "\$1" ||/true ||/'
mutant prompt-account 's/grep -qiE "authenticating as[^"]*" "\$1" ||/true ||/'
mutant prompt-password 's/if (!found) print "the driver never saw the account password prompt"//'
mutant events 's/! grep -q .\^missing. "\$1" ||/true ||/'
mutant leftover 's/! grep -qE .pkttyagent. "\$2" ||/true ||/'
mutant test-agent 's/! grep -qE .agent\\.py. "\$1" ||/true ||/'
mutant secret 's/! grep -qF -- "\$s" "\$file" ||/true ||/'
mutant pam-unix 's/grep -qE .\^auth.*pam_unix.*"\$1" ||/true ||/'
mutant pam-permit 's/! grep -qE .pam_permit. "\$1" ||/true ||/'
mutant no-token-listed 's/! grep -qE "^\[\[:space:\]\]\*token label.*\$2.*"\$1" ||/true ||/'
mutant no-token-failed 's/! grep -qiE .failed|error|cannot. "\$1" ||/true ||/'
mutant outcome-complete 's/grep -qF .==== AUTHENTICATION COMPLETE ====. "\$1" ||/true ||/'
mutant outcome-failed 's/grep -qF .==== AUTHENTICATION FAILED ====. "\$1" ||/true ||/'
mutant outcome-not-complete 's/! grep -qF .==== AUTHENTICATION COMPLETE ====. "\$1" ||/true ||/'
mutant state-present 's/\[ "\$n" -gt 0 \] ||/true ||/'
mutant state-absent 's/\[ "\$n" -eq 0 \] ||/true ||/'
mutant state-only 's/cmp -s - "\$2" ||/true ||/'

g=$ROOT/e2e/guest.sh
line() { grep -n -m1 -E -e "$1" "$g" | cut -d: -f1; }
a=$(line 'phase_runs appid')
c=$(line 'phase_runs cli')
u=$(line 'phase_runs upgrade')
[ -n "$a" ] && [ -n "$c" ] && [ -n "$u" ] || bad "guest.sh lacks a step"
[ "${a:-0}" -lt "${c:-0}" ] && [ "${c:-0}" -lt "${u:-0}" ] || bad "the cli step is not between appid and the upgrade ($a $c $u)"
grep -q 'cli-run.sh' "$g" || bad "guest.sh does not run cli-run.sh"
while IFS= read -r id; do
    grep -q "judge $id " "$ROOT/e2e/cli-run.sh" || bad "cli-run.sh does not report $id"
done < <(grep -E '^cli-' "$ROOT/e2e/cases.list")
# the order inside the run: the PAM file is restored before the end checks, and the pkttyagent session runs after the PAM set-up
r=$ROOT/e2e/cli-run.sh
s1=$(grep -n -m1 'pam_unix.so' "$r" | cut -d: -f1)
s2=$(grep -n -m1 '^session carol' "$r" | cut -d: -f1)
s3=$(grep -n -m1 'cp -p "\$CLI/polkit-1.orig" "\$PAM"$' "$r" | cut -d: -f1)
{ [ -n "$s1" ] && [ -n "$s2" ] && [ -n "$s3" ] && [ "$s1" -lt "$s2" ] && [ "$s2" -lt "$s3" ]; } || bad "cli-run.sh: PAM set-up, carol's session and the restore are not in this order"
exit "$fail"
