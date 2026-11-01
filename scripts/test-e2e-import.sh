#!/usr/bin/env bash
# F73: import asks polkit, so the e2e setup imports through the test agent. Static checks of e2e/import-user.sh and of the call in
# e2e/guest.sh, each with negative controls that must fail. NOT checked here: a real run (that is `just e2e` at F90/F100).
#
# import-user.sh: (1) it starts agent.py and calls import.py, so both share one `su -l` session; (2) it waits for the agent to
# register before it writes `approve`, and writes `approve` before the first import.py; (3) it checks for exactly 2 requests after
# the imports; (4) its agent state directory is $WORK/agent-import, never $WORK/agent.
# guest.sh: (5) import.py is not called from guest.sh; import-user.sh is called once, under `su -l alice`, before the oldpath branch,
# before user.sh and before upgrade.sh, and the .p12 files are removed after it.
# shellcheck disable=SC2016 # the patterns and the mutant lines hold literal $ on purpose
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-import: $*" >&2; fail=1; }

code() { grep -v '^[[:space:]]*#' "$1"; }
# line N of the first code line matching a pattern, or empty
first() { code "$1" | grep -n -m1 -E -e "$2" | cut -d: -f1 || true; }
count() { code "$1" | grep -c -E -e "$2" || true; }

# Problems of an import-user.sh copy, one per line.
script_problems() {
    local f=$1 reg approve imp
    [ -n "$(first "$f" 'agent\.py')" ] || echo "it does not start agent.py"
    imp=$(first "$f" 'import\.py')
    [ -n "$imp" ] || { echo "it never calls import.py"; return; }
    reg=$(first "$f" 'grep -q registered')
    approve=$(first "$f" 'echo approve > ')
    [ -n "$reg" ] || echo "it does not wait for the agent to register"
    [ -n "$approve" ] || echo "it never writes approve"
    if [ -n "$reg" ] && [ -n "$approve" ] && [ "$approve" -le "$reg" ]; then echo "approve is written before the agent registered"; fi
    if [ -n "$approve" ] && [ "$approve" -ge "$imp" ]; then echo "approve is written after the first import.py"; fi
    code "$f" | grep -Eq 'wc -l < "\$E2E_DIR/requests".*-eq 2 ' || echo "it does not check for exactly 2 requests"
    code "$f" | grep -Eq '^export E2E_DIR=\$WORK/agent-import$' || echo "the agent state directory is not \$WORK/agent-import"
    ! code "$f" | grep -Eq 'WORK/agent([^-]|$)' || echo "it uses \$WORK/agent"
}

# Problems of a guest.sh copy, one per line.
guest_problems() {
    local f=$1 call oldpath user upgrade
    [ "$(count "$f" 'import\.py')" -eq 0 ] || echo "guest.sh calls import.py itself"
    [ "$(count "$f" 'import-user\.sh')" -eq 1 ] || echo "import-user.sh is not called from exactly one place"
    call=$(first "$f" 'import-user\.sh')
    [ -n "$call" ] || return 0
    code "$f" | sed -n "${call}p" | grep -Eq 'su -l alice -c ' || echo "the call is not under su -l alice"
    oldpath=$(first "$f" 'mode" = oldpath')
    user=$(first "$f" '/e2e/user\.sh')
    upgrade=$(first "$f" '/e2e/upgrade\.sh')
    for pair in "oldpath:$oldpath" "user.sh:$user" "upgrade.sh:$upgrade"; do
        [ -n "${pair#*:}" ] || { echo "no line for ${pair%%:*}"; continue; }
        [ "$call" -lt "${pair#*:}" ] || echo "the call is not before ${pair%%:*}"
    done
    code "$f" | awk -v c="$call" 'NR > c && /rm -f .*\.p12/ { found = 1 } END { exit !found }' || echo "the .p12 files are not removed after the call"
}

script=$ROOT/e2e/import-user.sh
guest=$ROOT/e2e/guest.sh
[ -f "$script" ] || { bad "e2e/import-user.sh is missing"; exit 1; }

p=$(script_problems "$script"); [ -z "$p" ] || bad "import-user.sh: $p"
p=$(guest_problems "$guest"); [ -z "$p" ] || bad "guest.sh: $p"

# --- negative controls: each mutant must be refused
expect_refused() { # NAME PROBLEMS
    [ -n "$2" ] || bad "control '$1' was not refused"
}
# 1: guest.sh keeps the old line
{ cat "$guest"; echo 'su -l alice -c "python3 -I /e2e/import.py $work/$k.p12 $k e2e-password" >/dev/null'; } > "$tmp/g1"
expect_refused guest-keeps-import "$(guest_problems "$tmp/g1")"
# 2: a second call site
{ cat "$guest"; echo 'su -l alice -c "WORK=$work bash /e2e/import-user.sh"'; } > "$tmp/g2"
expect_refused guest-two-calls "$(guest_problems "$tmp/g2")"
# 3: the call moved after user.sh
grep -v 'import-user\.sh' "$guest" > "$tmp/g3"
awk '{ print } /\/e2e\/user\.sh/ { print "su -l alice -c \"WORK=$work bash /e2e/import-user.sh\"" }' "$tmp/g3" > "$tmp/g3b"
expect_refused guest-call-after-user "$(guest_problems "$tmp/g3b")"
# 4: the call only in the oldpath branch
grep -v 'import-user\.sh' "$guest" > "$tmp/g4"
awk '{ print } /mode" = oldpath/ { print "    su -l alice -c \"WORK=$work bash /e2e/import-user.sh\"" }' "$tmp/g4" > "$tmp/g4b"
expect_refused guest-call-in-oldpath-only "$(guest_problems "$tmp/g4b")"
# 5: the call without su
sed 's|su -l alice -c "WORK=$work bash /e2e/import-user.sh"|bash /e2e/import-user.sh|' "$guest" > "$tmp/g5"
expect_refused guest-call-without-su "$(guest_problems "$tmp/g5")"
# 6: imports before approve
grep -v 'echo approve > ' "$script" > "$tmp/s1"
echo 'echo approve > "$E2E_DIR/mode"' >> "$tmp/s1"
expect_refused script-imports-before-approve "$(script_problems "$tmp/s1")"
# 7: no count check
grep -v -e '-eq 2 ' "$script" > "$tmp/s2"
expect_refused script-without-count "$(script_problems "$tmp/s2")"
# 8: shared state directory
sed 's|agent-import|agent|' "$script" > "$tmp/s3"
expect_refused script-uses-agent-dir "$(script_problems "$tmp/s3")"
# 9: approve before the agent registered
awk '/echo approve > /{next} {print} /^python3 -I \/e2e\/agent\.py/{print "echo approve > \"$E2E_DIR/mode\""}' "$script" > "$tmp/s4"
expect_refused script-approves-before-registration "$(script_problems "$tmp/s4")"
# 10: no agent
grep -v 'agent\.py' "$script" > "$tmp/s5"
expect_refused script-without-agent "$(script_problems "$tmp/s5")"

exit "$fail"
