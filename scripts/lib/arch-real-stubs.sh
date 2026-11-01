#!/bin/sh
# Runs in the throw-away Arch container of scripts/test-arch-lifecycle-real.sh (F58): installs the stand-ins for the tools the scripts and the
# systemd and dbus hooks call. Every log line is "SEQ name args files=present|absent policy=present|absent :: parent command line"; files is whether the
# unit file exists at that moment, policy whether the bus policy does, the parent command line says which script or hook made the call.
mkdir -p /tmp/stub /usr/local/stub
cat > /usr/local/stub/lib.sh <<'LIB'
log() {
    n=$(cat /tmp/seq 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > /tmp/seq
    f=absent; [ ! -e /usr/lib/systemd/system/custodio.service ] || f=present
    p=absent; for q in /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf /etc/dbus-1/system.d/com.rfirma.Custodio1.conf; do [ ! -e "$q" ] || p=present; done
    ctx=$(tr '\0' ' ' < "/proc/$PPID/cmdline" 2>/dev/null)
    echo "$n $* files=$f policy=$p :: $ctx" >> /tmp/calls
}
effect() { n=$(cat /tmp/seq 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > /tmp/seq; echo "$n EFFECT $*" >> /tmp/calls; }
LIB
cat > /usr/bin/systemctl <<'STUB'
#!/bin/sh
. /usr/local/stub/lib.sh
log systemctl "$@"
case "$1" in
is-active) [ -e /tmp/stub/active ] || exit 3 ;;
stop) rm -f /tmp/stub/active; effect stopped ;;
start) : > /tmp/stub/active; effect started ;;
restart) : > /tmp/stub/active; effect restarted ;;
try-restart) if [ -e /tmp/stub/active ]; then effect restarted; fi ;;
esac
exit 0
STUB
cat > /usr/bin/journalctl <<'STUB'
#!/bin/sh
. /usr/local/stub/lib.sh
log journalctl "$@"
exit 0
STUB
# "booted, not a chroot": the hooks of systemd would skip otherwise (systemd-hook, systemd_live)
printf '#!/bin/sh\nexit 1\n' > /usr/bin/systemd-detect-virt
printf '#!/bin/sh\nexit 0\n' > /usr/bin/systemd-notify
mv /usr/bin/systemd-sysusers /usr/bin/systemd-sysusers.real
cat > /usr/bin/systemd-sysusers <<'STUB'
#!/bin/sh
. /usr/local/stub/lib.sh
log systemd-sysusers "$@"
if [ -e /tmp/stub/fail-sysusers ]; then echo "systemd-sysusers: stub failure" >&2; exit 1; fi
exec /usr/bin/systemd-sysusers.real "$@"
STUB
chmod +x /usr/bin/systemctl /usr/bin/journalctl /usr/bin/systemd-detect-virt /usr/bin/systemd-notify /usr/bin/systemd-sysusers
