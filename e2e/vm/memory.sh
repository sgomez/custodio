#!/usr/bin/env bash
# Root side of the vm-memory-* cases (F214, SPEC Design 4 and acceptance 24). Needs WORK, E2E_VM=1 and E2E_TPM; the full VM mode runs them, the lacking mode reports them skipped.
#   vm-memory-swap-max  vm-memory-default-stage  vm-memory-default-crash  vm-memory-default-crash-override  vm-memory-default-control
#   vm-memory-coredump-stage  vm-memory-coredump-crash  vm-memory-coredump-crash-override  vm-memory-coredump-control
# A crash is SIGSEGV to custodiod's MainPID: custodiod is not dumpable (it sets that itself), so the kernel hands no dump to any handler and systemd's Result is `signal`, not `core-dump`; the
# handler's store gains nothing for it. Each handler has a control, a transient unit of a packaged binary (sleep) with LimitCORE=infinity crashed the same way, which must end `core-dump`
# and leave its core or report in the store, or the case fails (the check could not see a dump). The default handler of the image (apport) goes first; then systemd-coredump is installed
# from the archive if absent and made the handler. A handler that cannot be run FAILS the run; there is no skip path. The drop-in of the override cases, the controls' dumps and units are
# removed at exit and the service is left running.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/../report.sh"
mode=${E2E_TPM:-swtpm}
ids="swap-max default-stage default-crash default-crash-override default-control coredump-stage coredump-crash coredump-crash-override coredump-control"
if [ -z "${E2E_VM:-}" ] || [ "$mode" != swtpm ]; then
    for i in $ids; do case_skip "vm-memory-$i" "E2E_TPM=$mode: the memory group runs in the full VM mode (SPEC acceptance 24)"; done
    exit 0
fi
for tool in busctl systemd-run sysctl dpkg-query; do command -v "$tool" > /dev/null || fail "$tool is not installed"; done

MEM=$WORK/memory
rm -rf "${MEM:?}"
mkdir -p "$MEM"
DROPIN_DIR=/run/systemd/system/custodio.service.d
CTRL=custodio-memory-control
handler=''

# until_ok SECONDS COMMAND...: a condition, polled, bounded
until_ok() { local s=$1 end; shift; end=$((SECONDS + s)); until "$@" > /dev/null 2>&1; do [ "$SECONDS" -lt "$end" ] || return 1; sleep 0.2; done; }
unit_state() { systemctl show "${2:-custodio}" -p "$1" --value; }
is_failed() { [ "$(unit_state ActiveState "$1")" = failed ]; }
is_active() { [ "$(unit_state ActiveState custodio)" = active ]; }
ver() { dpkg-query -W -f='${Version}' "$1" 2> /dev/null || echo none; }
record() { echo "E2E-MEMORY-RECORD $1=$2"; }

# The store of the handler in use, one entry per line: what a dump of custodiod would leave there.
store() {
    case $handler in
    apport)
        grep -al '^CoreDump' /var/crash/*.crash 2> /dev/null || true
        find /var/lib/apport/coredump -mindepth 1 2> /dev/null || true ;;
    coredump) find /var/lib/systemd/coredump -mindepth 1 2> /dev/null || true ;;
    esac | sort
}
journal_entries() { coredumpctl list --no-pager --no-legend 2> /dev/null | grep -c . || true; }
why_no_dump() {
    { echo "--- apport.log"; tail -n 8 /var/log/apport.log 2>&1; echo "--- journal"; journalctl --no-pager -n 12 -o cat -t apport -t systemd-coredump 2>&1; } | cut -c1-240
}

restart_service() { # the service starts again on the next call
    systemctl reset-failed custodio 2> /dev/null || true
    busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys > /dev/null 2>&1 || fail "ListKeys did not start custodio.service again"
    until_ok 30 is_active || fail "custodio.service is not active after the next call"
}

# crash NAME: SIGSEGV to custodiod; the unit fails with Result=signal and the handler's store is as before
crash() {
    local pid before after n_before n_after
    is_active || restart_service
    pid=$(unit_state MainPID)
    [ "${pid:-0}" -gt 1 ] || fail "$1: custodio.service has no MainPID"
    before=$(store)
    n_before=$(journal_entries)
    kill -SEGV "$pid"
    until_ok 30 is_failed custodio || fail "$1: custodio.service did not fail after SIGSEGV (state $(unit_state ActiveState))"
    [ "$(unit_state Result)" = signal ] || fail "$1: Result is '$(unit_state Result)', expected 'signal' (a result of core-dump means the kernel dumped custodiod)"
    after=$(store)
    [ "$before" = "$after" ] || fail "$1: the $handler store gained: $(diff <(echo "$before") <(echo "$after") | tail -n 4)"
    if [ "$handler" = coredump ]; then
        n_after=$(journal_entries)
        [ "$n_before" = "$n_after" ] || fail "$1: coredumpctl lists $((n_after - n_before)) new entries"
    fi
    restart_service
}

# control NAME: a transient unit of a packaged binary with an unlimited core limit, crashed the same way: it must dump, or the checks above prove nothing
control() {
    local before after new f
    before=$(store)
    systemd-run --quiet --unit="$CTRL" -p LimitCORE=infinity /usr/bin/sleep 300 || fail "$1: systemd-run of the control failed"
    until_ok 20 systemctl is-active --quiet "$CTRL" || fail "$1: the control did not start"
    systemctl kill -s SEGV "$CTRL"
    until_ok 60 is_failed "$CTRL" || fail "$1: the control did not fail after SIGSEGV"
    [ "$(unit_state Result "$CTRL")" = core-dump ] || { why_no_dump >&2; fail "$1: the control's Result is '$(unit_state Result "$CTRL")', expected core-dump"; }
    new=''
    for _ in $(seq 150); do
        after=$(store)
        new=$(comm -13 <(echo "$before") <(echo "$after"))
        [ -z "$new" ] || break
        sleep 0.4
    done
    [ -n "$new" ] || { why_no_dump >&2; fail "$1: the $handler handler left nothing for the control: the group cannot see a dump"; }
    for f in $new; do rm -rf "$f"; done
    systemctl reset-failed "$CTRL" 2> /dev/null || true
}

with_override() { # NAME: LimitCORE=infinity in a drop-in; the process still has 0, then the crash; the drop-in goes
    local pid limits
    mkdir -p "$DROPIN_DIR"
    printf '[Service]\nLimitCORE=infinity\n' > "$DROPIN_DIR/50-memory-core.conf"
    systemctl daemon-reload
    systemctl restart custodio
    until_ok 30 is_active || fail "$1: custodio.service did not start with the drop-in"
    [ "$(systemctl show custodio -p LimitCORE --value)" = infinity ] || fail "$1: the drop-in did not set LimitCORE=infinity"
    pid=$(unit_state MainPID)
    limits=$(sed -n 's/^Max core file size  *\([^ ]*\) *\([^ ]*\) .*/\1 \2/p' "/proc/$pid/limits")
    [ "$limits" = "0 0" ] || fail "$1: with LimitCORE=infinity in the unit the process's core limit is '$limits', expected '0 0' (custodiod lowers it itself)"
    crash "$1"
    rm -rf "$DROPIN_DIR"
    systemctl daemon-reload
    systemctl restart custodio
    until_ok 30 is_active || fail "$1: custodio.service did not start again without the drop-in"
}

cleanup() {
    rm -rf "$DROPIN_DIR"
    systemctl daemon-reload > /dev/null 2>&1 || true
    systemctl stop "$CTRL" > /dev/null 2>&1 || true
    systemctl reset-failed "$CTRL" custodio > /dev/null 2>&1 || true
    systemctl is-active --quiet custodio || systemctl start custodio > /dev/null 2>&1 || true
}
# shellcheck disable=SC2329 # run by the EXIT trap
on_exit() { local rc=$?; trap - EXIT; cleanup; exit "$rc"; }
trap on_exit EXIT

systemctl is-active --quiet custodio || fail "custodio.service is not active"
cg=/sys/fs/cgroup$(unit_state ControlGroup)
[ "$(cat "$cg/memory.swap.max" 2> /dev/null || echo missing)" = 0 ] || fail "memory.swap.max of $cg is '$(cat "$cg/memory.swap.max" 2> /dev/null || echo missing)', expected 0"
case_run vm-memory-swap-max

# ---- the handler the image ships
pattern=$(sysctl -n kernel.core_pattern)
record default_core_pattern "$pattern"
record default_suid_dumpable "$(sysctl -n fs.suid_dumpable)"
record default_apport_version "$(ver apport)"
record default_apport_handler_version "$(ver apport-core-dump-handler)"
[ "${pattern#|}" != "$pattern" ] || fail "kernel.core_pattern '$pattern' pipes to no handler"
helper=${pattern#|}
helper=${helper%% *}
[ -x "$helper" ] || fail "kernel.core_pattern '$pattern' names $helper, which is not an executable"
case $pattern in *apport*) ;; *) fail "the image's core handler is not apport: '$pattern'" ;; esac
if grep -qs '^enabled=0' /etc/default/apport; then fail "/etc/default/apport has enabled=0: apport is the default handler but disabled"; fi
handler=apport
case_run vm-memory-default-stage
crash default
case_run vm-memory-default-crash
with_override default-override
case_run vm-memory-default-crash-override
control default
case_run vm-memory-default-control

# ---- systemd-coredump, from the signed archive if absent, made the handler
if ! dpkg-query -W -f='${Status}' systemd-coredump 2> /dev/null | grep -q 'install ok installed'; then
    apt-get install -y --no-install-recommends systemd-coredump > "$MEM/apt.log" 2>&1 || { tail -n 8 "$MEM/apt.log" >&2; fail "systemd-coredump does not install from the archive"; }
fi
systemctl stop apport.service > /dev/null 2>&1 || true
/usr/lib/systemd/systemd-sysctl /usr/lib/sysctl.d/50-coredump.conf > /dev/null 2>&1 || fail "the sysctl file of systemd-coredump could not be applied"
pattern=$(sysctl -n kernel.core_pattern)
record coredump_core_pattern "$pattern"
record coredump_suid_dumpable "$(sysctl -n fs.suid_dumpable)"
record coredump_version "$(ver systemd-coredump)"
case $pattern in *systemd-coredump*) ;; *) fail "kernel.core_pattern is '$pattern', not systemd-coredump's" ;; esac
command -v coredumpctl > /dev/null || fail "coredumpctl is not installed"
handler=coredump
case_run vm-memory-coredump-stage
crash coredump
case_run vm-memory-coredump-crash
with_override coredump-override
case_run vm-memory-coredump-crash-override
control coredump
case_run vm-memory-coredump-control
