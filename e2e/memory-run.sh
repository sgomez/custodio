#!/usr/bin/env bash
# Root side of the memory-* cases (F214, SPEC Design 4 and acceptance 24), debian13 containers: what the running custodiod and its unit say about
# core dumps and swap. The unit's two settings (systemctl show), the process's own core limit (/proc/PID/limits: custodiod sets it itself, whatever the unit says)
# and the dumpable flag (a non-dumpable process's /proc/PID entries are root's while it runs as the service's uid; a control process of another uid, dumpable,
# owns its own entries, so the check can tell the two apart), and one bus call to the running service (a service that cannot read its own /proc would fail here).
# Crashes under a core handler need a kernel of their own and are the vm-memory-* cases. Nothing is changed: the control process is killed at exit.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/report.sh
source "$here/report.sh"
CTRL_UID=65534
ctrl=''
trap '[ -z "$ctrl" ] || kill "$ctrl" 2> /dev/null || true' EXIT

systemctl is-active --quiet custodio || fail "custodio.service is not active"
shown=$(systemctl show custodio -p MemorySwapMax -p LimitCORE | sort | tr '\n' ' ')
[ "$shown" = "LimitCORE=0 MemorySwapMax=0 " ] || fail "systemctl show custodio: '$shown'"
case_run memory-unit-settings

pid=$(systemctl show custodio -p MainPID --value)
[ "${pid:-0}" -gt 1 ] || fail "custodio.service has no MainPID"
limits=$(sed -n 's/^Max core file size  *\([^ ]*\) *\([^ ]*\) .*/\1 \2/p' "/proc/$pid/limits")
[ "$limits" = "0 0" ] || fail "/proc/$pid/limits: core file size soft/hard is '$limits', expected '0 0'"
case_run memory-core-limit

uid=$(sed -n 's/^Uid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$pid/status")
[ "$uid" != 0 ] || fail "the service runs as uid 0: the dumpable check cannot tell"
owner=$(stat -c %u "/proc/$pid/status")
[ "$owner" = 0 ] || fail "/proc/$pid/status is owned by uid $owner while the process runs as $uid: the service is dumpable"
# the control: a process of another uid, started by exec after the uid change, is dumpable and its entries are its own
setpriv --reuid=$CTRL_UID --regid=$CTRL_UID --clear-groups sleep 300 &
ctrl=$!
for _ in $(seq 100); do
    [ "$(stat -c %u "/proc/$ctrl/status" 2> /dev/null || echo x)" = "$CTRL_UID" ] && break
    sleep 0.1
done
[ "$(stat -c %u "/proc/$ctrl/status")" = "$CTRL_UID" ] || fail "the control process of uid $CTRL_UID has its /proc entries owned by $(stat -c %u "/proc/$ctrl/status"): the check cannot tell dumpable from not"
case_run memory-not-dumpable

# the service still works with the flag off: one call on the bus (ListKeys answers for the caller; polkit is not asked)
busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys > /dev/null 2>&1 || fail "ListKeys on the running, non-dumpable service failed"
[ "$(systemctl show custodio -p MainPID --value)" = "$pid" ] || fail "the service restarted during the memory cases"
case_run memory-service-answers
