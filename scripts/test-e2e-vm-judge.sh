#!/usr/bin/env bash
# shellcheck disable=SC2016 # single quotes hold commands for eval
# F160: the VM-only judges (e2e/vm/judge.sh) on a fixture, with no VM: the good fixture has no problem, and one bad fixture per judge is named.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-vm-judge: $*" >&2; fail=1; }
V=$tmp/v
vm_fixture() {
    rm -rf "$V"; mkdir -p "$V/etc" "$V/run" "$V/usr" "$V/facts"
    printf '[Service]\nExecStart=/usr/lib/custodio/custodiod\n' > "$V/unit.service"
    sha256sum "$V/unit.service" | cut -d' ' -f1 > "$V/facts/unit.sha256"
    echo yes > "$V/facts/has2.verdict"; echo 0 > "$V/facts/has2.rc"
    printf ' apt-get install -y --no-install-recommends /pkg/custodio_1.2.3_amd64.deb \n' > "$V/facts/apt-commandlines"
    : > "$V/facts/recommends-installed"; : > "$V/tpmrm0"
    printf 'PATH=/usr/bin\0' > "$V/environ"; printf 'lrwx------ 1 root root 64 Jan 1 00:00 3 -> /dev/tpmrm0\n' > "$V/fds"
}
vm_judge_all() { # prints the problems of every VM-only judge on the fixture in $V
    (
        export VM_FACTS="$V/facts" VM_UNIT="$V/unit.service" VM_UNIT_DIRS="$V/etc $V/run $V/usr" VM_TPMRM="$V/tpmrm0"
        # shellcheck source=e2e/vm/judge.sh
        source "$ROOT/e2e/vm/judge.sh"
        vm_judge_tpmrm0; vm_judge_has_tpm2 "$(cat "$VM_FACTS/has2.verdict")" "$(cat "$VM_FACTS/has2.rc")"; vm_judge_no_recommends; vm_judge_unit_shipped
        vm_judge_via_device "$V/environ" "$V/fds"
    ) 2>&1
}
vm_fixture; p=$(vm_judge_all); [ -z "$p" ] || bad "the good fixture has problems: $p"
vmcase() { # vmcase NAME CAUSE-TEXT COMMAND: after the command changes the fixture, the judges name the cause
    vm_fixture; eval "$3"; local p; p=$(vm_judge_all)
    grep -qF -- "$2" <<< "$p" || bad "$1: expected '$2', got '${p:-nothing}'"
}
vmcase no-tpmrm0 'does not exist' 'rm "$V/tpmrm0"'
vmcase has2-no "printed 'no'" 'echo no > "$V/facts/has2.verdict"'
vmcase no-flag 'without --no-install-recommends' 'echo " apt-get install -y /pkg/c.deb " > "$V/facts/apt-commandlines"'
vmcase dropin 'drop-in present' 'mkdir "$V/etc/custodio.service.d"; echo "[Service]" > "$V/etc/custodio.service.d/x.conf"'
vmcase tcti-unit 'CUSTODIOD_TEST_SWTPM_TCTI is set' 'echo "Environment=CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=/x" >> "$V/unit.service"; sha256sum "$V/unit.service" | cut -d" " -f1 > "$V/facts/unit.sha256"'
vmcase socket 'holds a socket' 'printf "lrwx------ 1 root root 64 Jan 1 00:00 4 -> /run/swtpm/tpm.sock\n" > "$V/fds"'
[ "$fail" = 0 ] || exit 1
echo "test-e2e-vm-judge: ok"
