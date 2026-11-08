# shellcheck shell=bash
# shellcheck disable=SC2154,SC2016,SC2015 # sourced: tmp, R, bad, differs come from the caller; single quotes hold text for sed/python/stubs; A && B || bad is the check
# Sourced by scripts/test-e2e-vm-host.sh (F160): the sections "guest" (the real guest.sh in VM mode with logging stubs) and "vm-only" (the judges on fixtures).
# Uses tmp, R (the copy of the tree), bad, differs from the caller.
G=$tmp/g
mkdir -p "$G/bin" "$G/unitroot/etc" "$G/unitroot/run" "$G/unitroot/usr" "$G/facts" "$G/proc/4242/fd" "$G/target"
: > "$G/calls"
stubcmd() { printf '#!/bin/bash\necho "%s $*" >> "%s"\n%s\n' "$1" "$G/calls" "$2" > "$G/bin/$1"; chmod +x "$G/bin/$1"; }
stubcmd systemctl 'case "$*" in "show -p MainPID --value custodio") echo 4242 ;; "show -p User --value custodio") echo custodio ;; esac; exit 0'
stubcmd journalctl 'exit 0'
stubcmd id 'exit 1'
stubcmd useradd 'exit 0'
stubcmd su 'exit 0'
stubcmd chown 'exit 0'
stubcmd swtpm 'exit 0'
stubcmd swtpm_setup 'exit 0'
stubcmd systemd-analyze 'echo yes'
stubcmd apt-get 'exit 0'
stubcmd openssl 'while [ $# -gt 0 ]; do case $1 in -out|-keyout) : > "$2"; shift ;; esac; shift; done; exit 0'
printf '[Service]\nExecStart=/usr/lib/custodio/custodiod\n' > "$G/unit.service"
sha256sum "$G/unit.service" | cut -d' ' -f1 > "$G/facts/unit.sha256"
printf 'yes\n' > "$G/facts/has2.out"; printf 'yes\n' > "$G/facts/has2.verdict"; echo 0 > "$G/facts/has2.rc"
printf ' apt-get install -y --no-install-recommends /pkg/custodio_1.2.3_amd64.deb \n' > "$G/facts/apt-commandlines"; : > "$G/facts/recommends-installed"
: > "$G/tpmrm0"; printf 'PATH=/usr/bin\0' > "$G/proc/4242/environ"; ln -s /dev/tpmrm0 "$G/proc/4242/fd/3"
vmenv=(VM_FACTS="$G/facts" VM_UNIT="$G/unit.service" VM_UNIT_DIRS="$G/unitroot/etc $G/unitroot/run $G/unitroot/usr" VM_TPMRM="$G/tpmrm0" VM_PROC="$G/proc")
vmids=$(grep -v '^[[:space:]]*\(#\|$\)' "$R/e2e/vm/cases.list" | grep '^vm-' | tr '\n' ' ')
sha_tree() { (cd "$G/unitroot" && find . -type f | sort | xargs -r sha256sum; sha256sum "$G/unit.service"); }
guest_run() { # guest_run NAME GUEST-SCRIPT [VAR=VALUE...]: one run of the guest script in VM mode; $G/NAME.{out,trace,calls,tree}
    local n=$1 script=$2; shift 2
    : > "$G/calls"; rm -rf "$G/unitroot/run/custodio.service.d"
    sha_tree > "$G/$n.tree.before"
    env PATH="$G/bin:$PATH" E2E_DIR="$R/e2e" E2E_VM=1 E2E_TPM=swtpm E2E_SELECT_FILE="$G/select" E2E_SELECT="$vmids" E2E_PKG_DIR="$tmp/pk" E2E_PKG_NEXT_DIR="$tmp/pkn" \
        E2E_TARGET_DIR="$G/target" "${vmenv[@]}" BASH_XTRACEFD=9 "$@" bash -x "$script" vm > "$G/$n.out" 2> "$G/$n.err" 9> "$G/$n.trace" || echo "rc=$?" >> "$G/$n.out"
    sha_tree > "$G/$n.tree.after"
    cp "$G/calls" "$G/$n.calls"
}
printf '%s\n' "$vmids" > /dev/null
cp "$ROOT/e2e/vm/cases.list" "$G/target/cases.list"
mkdir -p "$G/stamp"; : > "$G/stamp/t"
mkctlg() { cp "$R/e2e/guest.sh" "$R/e2e/guest-$1.sh"; python3 - "$R/e2e/guest-$1.sh" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert old in s, old
open(p, "w").write(s.replace(old, new, 1))
PY
differs "$R/e2e/guest.sh" "$R/e2e/guest-$1.sh" "guest-$1"; }
mkctlg tpm '    vm_install_cases
' '    vm_install_cases
    source "$E2E_DIR/tpm-lib.sh"; TPM_DROPIN_DIR=$G/unitroot/run/custodio.service.d; TPM_DROPIN=$TPM_DROPIN_DIR/zz-e2e-test-tpm.conf
    tpm_swtpm_start() { swtpm socket; }; tpm_setup swtpm
'
mkctlg order '[ -z "$vm" ] || vm_live_cases "after the shared setup"' ':'
python3 - "$R/e2e/guest-order.sh" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('    vm_live_cases "after the cases"\n', ':\n', 1).replace("    vm_install_cases\n", '    vm_install_cases\n    vm_live_cases "before the setup"\n', 1)
open(p, "w").write(s)
PY
guest_run good "$R/e2e/guest.sh" &
wait
guest_run ctl-tpm "$R/e2e/guest-tpm.sh" G="$G"
guest_run ctl-order "$R/e2e/guest-order.sh"
find /tmp -maxdepth 1 -name 'e2e.*' -newer "$G/stamp/t" -user "$(id -u)" -exec rm -rf {} + 2> /dev/null || true

guest_ok() { # guest_ok NAME: prints the problems of a guest run
    local n=$1 l1 l2 ls lu
    grep -q 'all checks passed' "$G/$n.out" || echo "the run did not pass: $(tail -n 3 "$G/$n.out" "$G/$n.err" | tr '\n' '|')"
    grep -Eq '^\++ (tpm_setup|tpm_teardown)( |$)' "$G/$n.trace" && echo "tpm_setup/tpm_teardown was called"
    grep -q '^swtpm' "$G/$n.calls" && echo "swtpm was started"
    cmp -s "$G/$n.tree.before" "$G/$n.tree.after" || echo "a file under custodio.service.d (or the unit) changed"
    for c in $vmids; do grep -qx "E2E-CASE run $c" "$G/$n.out" || echo "case $c is not reported"; done
    ls=$(grep -n 'E2E-PHASE service' "$G/$n.out" | head -n 1 | cut -d: -f1); lu=$(grep -n 'E2E-PHASE upgrade' "$G/$n.out" | head -n 1 | cut -d: -f1)
    l1=$(grep -n 'live checks (after the shared setup)' "$G/$n.out" | head -n 1 | cut -d: -f1); l2=$(grep -n 'live checks (after the cases)' "$G/$n.out" | head -n 1 | cut -d: -f1)
    [ -n "$l1" ] && [ -n "$ls" ] && [ "$l1" -gt "$ls" ] || echo "the judges did not run after the shared setup"
    [ -n "$l2" ] && [ -n "$lu" ] && [ "$l2" -gt "$lu" ] || echo "the judges did not run after the cases"
}
p=$(guest_ok good); [ -z "$p" ] || bad "guest: $p"
p=$(guest_ok ctl-tpm); [ -n "$p" ] || bad "guest control (tpm_setup): the checks passed"
grep -q 'tpm_setup' <<< "$p" && grep -q 'changed' <<< "$p" || bad "guest control (tpm_setup): did not fail both the call check and the tree check: $p"
p=$(guest_ok ctl-order); grep -q 'after the shared setup' <<< "$p" || bad "guest control (judges only before the setup): the order check passed: $p"

# ---- vm-only: the judges on fixtures
V=$tmp/v
vm_fixture() { rm -rf "$V"; mkdir -p "$V/etc" "$V/run" "$V/usr"; cp -r "$G/facts" "$V/facts"; cp "$G/unit.service" "$V/unit.service"; : > "$V/tpmrm0"
    printf 'PATH=/usr/bin\0' > "$V/environ"; printf 'lrwx------ 1 root root 64 Jan 1 00:00 3 -> /dev/tpmrm0\n' > "$V/fds"; }
vm_judge_all() { # prints the problems of every VM-only judge on the fixture in $V
    (
        export VM_FACTS="$V/facts" VM_UNIT="$V/unit.service" VM_UNIT_DIRS="$V/etc $V/run $V/usr" VM_TPMRM="$V/tpmrm0"
        # shellcheck source=e2e/vm/judge.sh
        source "$R/e2e/vm/judge.sh"
        vm_judge_tpmrm0; vm_judge_has_tpm2 "$(cat "$VM_FACTS/has2.verdict")" "$(cat "$VM_FACTS/has2.rc")"; vm_judge_no_recommends; vm_judge_unit_shipped
        vm_judge_via_device "$V/environ" "$V/fds"
    ) 2>&1
}
vm_fixture; p=$(vm_judge_all); [ -z "$p" ] || bad "vm-only: the good fixture has problems: $p"
vmcase() { # vmcase NAME CAUSE-TEXT COMMAND: after the command changes the fixture, the judges name the cause
    vm_fixture; eval "$3"; local p; p=$(vm_judge_all)
    grep -qF -- "$2" <<< "$p" || bad "vm-only $1: expected '$2', got '${p:-nothing}'"
}
vmcase no-tpmrm0 'does not exist' 'rm "$V/tpmrm0"'
vmcase has2-partial "printed 'partial'" 'echo partial > "$V/facts/has2.verdict"'
vmcase has2-rc16 'exited 16' 'echo 16 > "$V/facts/has2.rc"'
vmcase has2-no "printed 'no'" 'echo no > "$V/facts/has2.verdict"'
vmcase no-flag 'without --no-install-recommends' 'echo " apt-get install -y /pkg/c.deb " > "$V/facts/apt-commandlines"'
vmcase recommends 'a recommended package is installed' 'echo libfoo > "$V/facts/recommends-installed"'
vmcase dropin 'drop-in present' 'mkdir "$V/etc/custodio.service.d"; echo "[Service]" > "$V/etc/custodio.service.d/x.conf"'
vmcase run-dropin 'drop-in present' 'mkdir "$V/run/custodio.service.d"; echo "[Service]" > "$V/run/custodio.service.d/zz.conf"'
vmcase unit-sum 'differs from the packaged one' 'echo "# edited" >> "$V/unit.service"'
vmcase tcti-unit 'CUSTODIOD_TEST_SWTPM_TCTI is set' 'echo "Environment=CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=/x" >> "$V/unit.service"; sha256sum "$V/unit.service" | cut -d" " -f1 > "$V/facts/unit.sha256"'
vmcase tcti-dropin 'CUSTODIOD_TEST_SWTPM_TCTI is set' 'mkdir "$V/usr/custodio.service.d"; echo "Environment=CUSTODIOD_TEST_SWTPM_TCTI=x" > "$V/usr/custodio.service.d/a.conf"'
vmcase tcti-env 'CUSTODIOD_TEST_SWTPM_TCTI is set' 'printf "CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=/x\0" > "$V/environ"'
vmcase socket 'holds a socket' 'printf "lrwx------ 1 root root 64 Jan 1 00:00 4 -> /run/swtpm/tpm.sock\n" > "$V/fds"'
vm_fixture; : > "$V/fds"; p=$(vm_judge_all); [ -z "$p" ] || bad "vm-only: a service that holds no descriptor open between calls is judged: $p"
