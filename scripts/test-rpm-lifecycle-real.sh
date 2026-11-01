#!/usr/bin/env bash
# The real rpm runs the scriptlets of the .rpm (F44): install, upgrade between two builds of this tree, upgrade over an old package with
# only the F42-era %pre/%post (what the M1 rpm had), erase, and the offline variants, with `rpm --root` into a small root as root of a
# user namespace (scripts/lib/bus-fixtures.sh, bf_in_root) and the stubs of scripts/lib/lifecycle-fixtures.sh for systemctl,
# systemd-sysusers, journalctl and busctl. The rpm database is in /rpmdb of the root, outside /var, so that /var can be read-only.
#
# Two kinds of proof of the argument counts: a fixture package whose four scriptlets only log their $1 (what rpm passes), and this tree's
# own scriptlets, whose observable effects differ for each value (restart only on 2, stop only on 0), so every $1 drives one of them.
#
# Mechanisms proved here: account before unpack: the systemd-sysusers stub records whether the bus policy file was in the root when it
# ran ("absent" on a first install), and a package whose account creation is moved to %post (a mutant, run every time) says "present".
# Restart: %pre notes the running service, the new %post restarts it once after the reloads; the old package's %preun and %postun (ours
# or none at all) take no part, and a package that restarts only from %postun is a mutant that fails. The order of the call log is the
# evidence for "after the bus reload of the NEW package's %post": the rpmdb holds both versions at that point, so a version query proves nothing.
# What this cannot cover: a real systemd and bus, a real rpm-ostree, Fedora or Alma (F45 and later). rpm-ostree runs no erase scriptlet.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/package-fixtures.sh
. "$ROOT/scripts/lib/package-fixtures.sh"
# shellcheck source=scripts/lib/bus-fixtures.sh
. "$ROOT/scripts/lib/bus-fixtures.sh"
# shellcheck source=scripts/lib/lifecycle-fixtures.sh
. "$ROOT/scripts/lib/lifecycle-fixtures.sh"

fx_init
bf_init
trap 'bf_cleanup; fx_cleanup' EXIT
fail=0
mutant_mode=0
mutant_hit=0
bad() {
    if [ "$mutant_mode" = 1 ]; then mutant_hit=1; else echo "test-rpm-lifecycle-real: $*" >&2; fail=1; fi
}

SKELETON=$BF_DIR/skeleton
bf_mkroot "$SKELETON"
lc_stubs "$SKELETON"
bf_in_root "$SKELETON" true || { echo "test-rpm-lifecycle-real: cannot make a user namespace for rpm" >&2; exit 1; }

# build_rpm NAME VERSION DIR: an rpm of the real nfpm.yaml whose scriptlets are the files pre, post, preun, postun of DIR (a key whose file is
# absent is left out). The package is out/NAME/*.rpm in FX_DIR.
build_rpm() {
    local name=$1 version=$2 dir=$3 yaml=${BASE_YAML:-$ROOT/packaging/nfpm.yaml} key file n=0
    mkdir -p "$FX_DIR/pk/$name" "$FX_DIR/out/$name"
    cp "$dir"/* "$FX_DIR/pk/$name/"
    for pair in preinstall:pre postinstall:post preremove:preun postremove:postun; do
        key=${pair%%:*} file=${pair##*:}
        n=$((n + 1))
        if [ -e "$dir/$file" ]; then
            python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$yaml" "$FX_DIR/nfpm-$name-$n.yaml" script-set rpm "$key" "pk/$name/$file"
        else
            python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$yaml" "$FX_DIR/nfpm-$name-$n.yaml" script-del rpm "$key"
        fi
        yaml=$FX_DIR/nfpm-$name-$n.yaml
    done
    (cd "$FX_DIR" && NFPM_VERSION=$version NFPM_PRERELEASE='' nfpm package -f "$yaml" -p rpm -t "out/$name" > /dev/null)
    ls "$FX_DIR/out/$name"/*.rpm
}
# mutant_dir NAME SCRIPT SED-EXPRESSION: a copy of packaging/rpm with one scriptlet edited; fails the test when the edit changes nothing.
mutant_dir() {
    local dir=$FX_DIR/mut-$1
    rm -rf "$dir"
    cp -r "$ROOT/packaging/rpm" "$dir"
    sed -i "$3" "$dir/$2"
    if cmp -s "$dir/$2" "$ROOT/packaging/rpm/$2"; then echo "test-rpm-lifecycle-real: mutant $1 changes nothing" >&2; fail=1; fi
    printf '%s' "$dir"
}

# The F42-era package: the check as the only %pre and the three calls of M1 as %post; no %preun, no %postun.
OLD42=$FX_DIR/old42
mkdir -p "$OLD42"
{
    printf '#!/bin/sh\n'
    sed -n '/^# >>> custodio-bus-check$/,/^# <<< custodio-bus-check$/p' "$ROOT/packaging/bus-check.sh"
    printf 'custodio_bus_check || exit 1\n'
} > "$OLD42/pre"
cat > "$OLD42/post" <<'M1'
#!/bin/sh
# Create the static `custodio` account the D-Bus policy names, and let systemd see the new unit.
systemd-sysusers custodio.conf || true
systemctl daemon-reload || true
systemctl reload dbus || true
M1
# A package whose scriptlets only log $1.
LOGDIR=$FX_DIR/logging
mkdir -p "$LOGDIR"
# shellcheck disable=SC2016 # the scriptlet expands $1 itself
for s in pre post preun postun; do printf '#!/bin/sh\necho "%s $1" >> /recorded-args\n' "$s" > "$LOGDIR/$s"; done

PKG_OLD=$(build_rpm old 0.1.0 "$ROOT/packaging/rpm")
PKG_NEW=$(build_rpm new 0.1.1 "$ROOT/packaging/rpm")
PKG_OLD42=$(build_rpm old42 0.1.0 "$OLD42")
PKG_LOG_OLD=$(build_rpm log-old 0.1.0 "$LOGDIR")
PKG_LOG_NEW=$(build_rpm log-new 0.1.1 "$LOGDIR")
# F61: the package as the current M2 ones were (this tree's nfpm.yaml edited): the daemon at /usr/lib/custodio, the unit starting it there.
python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$ROOT/packaging/nfpm.yaml" "$FX_DIR/nfpm-oldpath-base.yaml" oldpath
PKG_OLDPATH=$(BASE_YAML=$FX_DIR/nfpm-oldpath-base.yaml build_rpm oldpath 0.1.0 "$ROOT/packaging/rpm")
oldpath_files=$(rpm --dbpath "$FX_DIR/rpmdb" -qlp "$PKG_OLDPATH")
grep -qx '/usr/lib/custodio/custodiod' <<< "$oldpath_files" || { echo "test-rpm-lifecycle-real: the old-path fixture has no daemon at /usr/lib/custodio" >&2; exit 1; }
! grep -q '^/usr/libexec' <<< "$oldpath_files" || { echo "test-rpm-lifecycle-real: the old-path fixture has a /usr/libexec path" >&2; exit 1; }

BUS='busctl --address=unix:path=/run/dbus/system_bus_socket call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionCredentials s org.freedesktop.DBus'
ACTIVE='systemctl is-active --quiet custodio.service'
RELOAD=$'systemctl daemon-reload\nsystemctl reload dbus.service'
CATALOG='journalctl --update-catalog'
MARKER=run/custodio-restart-after-upgrade
RESTART='systemctl restart custodio.service'

# new_root [none]: a fresh root with an empty rpm database in /rpmdb and a populated state directory (or none).
new_root() {
    # The previous case is done with its root; keeping every one fills /tmp (GBs per run).
    if [ -n "${root:-}" ] && [ -d "$root" ]; then chmod -R u+w "$root" 2> /dev/null || true; rm -rf "$root"; fi
    root=$(mktemp -d "$BF_DIR/root.XXXXXX")
    cp -a "$SKELETON/." "$root/"
    mkdir -p "$root/var/lib" "$root/rpmdb"
    [ "${1:-}" = none ] || lc_populate "$root"
    bf_in_root "$root" rpm --root "$root" --dbpath /rpmdb --initdb
    before=$(lc_snapshot "$root")
}
# rpm_in [offline] ARGS...: the real rpm on the root; sets rc, out, err. offline: /var and /run read-only for the whole transaction, and
# the scriptlet temporary files in /tmp (rpm writes them to /var/tmp by default).
rpm_in() {
    local ro=""
    if [ "$1" = offline ]; then ro="var run"; shift; fi
    lc_reset "$root"
    rc=0
    # shellcheck disable=SC2016 # the inner shell expands $r, $d and $@
    bf_in_root "$root" sh -c 'r=$1; ro=$2; shift 2; for d in $ro; do mount --bind "$r/$d" "$r/$d" && mount -o remount,ro,bind "$r/$d" || exit 99; done; exec "$@"' \
        sh "$root" "$ro" rpm --root "$root" --dbpath /rpmdb --define '_tmppath /tmp' --nosignature --nodigest --nodeps "$@" > "$BF_DIR/rpm.out" 2> "$BF_DIR/rpm.err" || rc=$?
    out=$(cat "$BF_DIR/rpm.out")
    err=$(cat "$BF_DIR/rpm.err")
    calls=$(lc_calls "$root")
}
# query ARGS...: rpm -q in the root.
query() { bf_in_root "$root" rpm --root "$root" --dbpath /rpmdb -q "$@" 2> /dev/null; }
want_calls() { [ "$calls" = "$2" ] || bad "$1: calls were:"$'\n'"$calls"$'\n'"expected:"$'\n'"$2"; }
want_ok() { [ "$rc" -eq 0 ] || bad "$1: rpm exit status $rc: $err"; }
state_intact() { # LABEL: all of var/lib (the rpm database is outside) is as it was
    local after
    after=$(lc_snapshot "$root")
    [ "$after" = "$before" ] || bad "$1: the state directory changed:"$'\n'"$(diff <(echo "$before") <(echo "$after") || true)"
    [ ! -e "$root/stub/violation" ] || bad "$1: a file tool was called with a path under the state directory"
}
active() { [ -e "$root/stub/active" ]; }
files_gone() { # LABEL: no packaged file remains
    local left
    left=$(find "$root/usr" -mindepth 1 -not -type d \( -iname '*custodio*' -o -name 'com.rfirma*' \) 2> /dev/null || true)
    [ -z "$left" ] || bad "$1: files remain: $left"
}
want_notice() { # LABEL
    grep -qF '/var/lib/custodio' <<< "$err" || bad "$1: the notice does not name the state directory: $err"
    grep -qF 'destroys the keys for good' <<< "$err" || bad "$1: the notice lacks the warning: $err"
    grep -qF 'account custodio was kept' <<< "$err" || bad "$1: the notice does not say the account is kept: $err"
    [ -z "$out" ] || bad "$1: output on stdout: $out"
}
no_enable() { if grep -E '(^| )(enable|start|preset|mask)( |$)' <<< "$calls" > /dev/null; then bad "$1: enable, start or preset: $calls"; fi; }

# cases NEW [OLD]: every scenario with the package NEW as the one being installed or upgraded to, and OLD (an older build of this tree) as the
# one it replaces. A mutant is built in both versions, since the %preun and %postun of an upgrade come from the old package.
cases() {
    local new=$1 old=${2:-$PKG_OLD} label

    # ---- install ----
    new_root
    rpm_in -i "$new"
    want_ok "install"
    want_calls "install" "$BUS"$'\n''systemd-sysusers -'$'\n'"$RELOAD"$'\n'"$CATALOG"
    [ "$(cat "$root/stub/policy-at-sysusers" 2> /dev/null)" = absent ] || bad "install: the account was not created before the bus policy was unpacked: $(cat "$root/stub/policy-at-sysusers" 2> /dev/null)"
    grep -q '^custodio:' "$root/etc/passwd" || bad "install: the account was not created"
    [ -e "$root/usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf" ] || bad "install: the bus policy was not installed"
    no_enable "install"
    active && bad "install: the service was started"
    state_intact "install"

    # ---- install fails when the account cannot be created: no file is installed ----
    new_root
    : > "$root/stub/fail-sysusers"
    rpm_in -i "$new"
    [ "$rc" -ne 0 ] || bad "install with a failing systemd-sysusers: rpm succeeded"
    grep -q 'systemd-sysusers' <<< "$err" || bad "install with a failing systemd-sysusers: no message names the tool: $err"
    ! query custodio > /dev/null || bad "install with a failing systemd-sysusers: the package is installed"
    files_gone "install with a failing systemd-sysusers"
    new_root
    rm "$root/usr/bin/systemd-sysusers"
    rpm_in -i "$new"
    [ "$rc" -ne 0 ] || bad "install without systemd-sysusers: rpm succeeded"
    grep -q 'systemd-sysusers is not installed' <<< "$err" || bad "install without systemd-sysusers: no message names the tool: $err"
    files_gone "install without systemd-sysusers"
    new_root
    lc_bus_without_processfd "$root"
    rpm_in -i "$new"
    [ "$rc" -ne 0 ] || bad "install on a bus without ProcessFD: rpm succeeded"
    want_calls "install on a bus without ProcessFD" "$BUS"
    grep -q '^custodio:' "$root/etc/passwd" && bad "install on a bus without ProcessFD: an account was created"
    files_gone "install on a bus without ProcessFD"

    # ---- upgrade between two builds of this tree, and over the F42-era package ----
    for from in tree f42 oldpath; do
        for running in yes no; do
            new_root
            case $from in tree) rpm_in -i "$old" ;; f42) rpm_in -i "$PKG_OLD42" ;; oldpath) rpm_in -i "$PKG_OLDPATH" ;; esac
            want_ok "first install ($from)"
            if [ "$from" = oldpath ]; then [ -e "$root/usr/lib/custodio/custodiod" ] || bad "first install ($from): the old daemon is missing"; fi
            [ "$running" = no ] || : > "$root/stub/active"
            label="upgrade from $from, running $running"
            rpm_in -U "$new"
            want_ok "$label"
            if [ "$running" = yes ]; then
                want_calls "$label" "$BUS"$'\n''systemd-sysusers -'$'\n'"$ACTIVE"$'\n'"$RELOAD"$'\n'"$CATALOG"$'\n'"$RESTART"
                active || bad "$label: the service is not running afterwards"
            else
                want_calls "$label" "$BUS"$'\n''systemd-sysusers -'$'\n'"$ACTIVE"$'\n'"$RELOAD"$'\n'"$CATALOG"
                active && bad "$label: a stopped service was started"
            fi
            [ "$(grep -c "^$RESTART" <<< "$calls")" -le 1 ] || bad "$label: more than one restart"
            [ "$(query --qf '%{VERSION}' custodio)" = 0.1.1 ] || bad "$label: the version after the upgrade is $(query --qf '%{VERSION}' custodio)"
            [ ! -e "$root/$MARKER" ] || bad "$label: the marker is still there"
            grep -c '^custodio:' "$root/etc/passwd" | grep -qx 1 || bad "$label: not exactly one account line"
            no_enable "$label"
            state_intact "$label"
            if [ "$from" = oldpath ]; then # F61: the daemon moved to /usr/libexec and the unit follows; the module stays
                [ -e "$root/usr/libexec/custodio/custodiod" ] || bad "$label: the new daemon is missing"
                [ ! -e "$root/usr/lib/custodio/custodiod" ] || bad "$label: the old daemon is still there"
                [ -e "$root/usr/lib/custodio/libcustodio_pkcs11.so" ] || bad "$label: the module is gone"
                grep -qx 'ExecStart=/usr/libexec/custodio/custodiod' "$root/usr/lib/systemd/system/custodio.service" || bad "$label: the unit does not start the new path"
            fi
        done
    done

    # ---- erase ----
    new_root
    rpm_in -i "$new"
    : > "$root/stub/active"
    : > "$root/stub/had-account"
    rpm_in -e custodio
    want_ok "erase"
    want_calls "erase" 'systemctl stop custodio.service'$'\n'"$RELOAD"$'\n'"$ACTIVE"
    want_notice "erase"
    active && bad "erase: the service runs afterwards"
    grep -q '^custodio:' "$root/etc/passwd" || bad "erase: the account is gone"
    ! query custodio > /dev/null || bad "erase: the package is still installed"
    files_gone "erase"
    no_enable "erase"
    state_intact "erase"

    # ---- the offline variants: no bus, systemctl failing, /var and /run read-only ----
    new_root none
    lc_bus_down "$root"
    : > "$root/stub/fail"
    rpm_in offline -i "$old"
    want_ok "offline install"
    grep -q 'no system bus is running' <<< "$err" || bad "offline install: the no-bus notice is missing: $err"
    grep -q '^custodio:' "$root/etc/passwd" || bad "offline install: the account was not created"
    [ -e "$root/usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf" ] || bad "offline install: nothing was installed"
    state_intact "offline install"
    rpm_in offline -U "$new"
    want_ok "offline upgrade"
    grep -q 'no system bus is running' <<< "$err" || bad "offline upgrade: the no-bus notice is missing: $err"
    state_intact "offline upgrade"
    rpm_in offline -e custodio
    want_ok "offline erase"
    want_notice "offline erase"
    files_gone "offline erase"
    state_intact "offline erase"
    # A running service whose marker cannot be written: the upgrade goes on.
    new_root none
    rpm_in -i "$old"
    : > "$root/stub/active"
    rpm_in offline -U "$new"
    want_ok "upgrade with a read-only /run"
    [ ! -e "$root/$MARKER" ] || bad "upgrade with a read-only /run: a marker"
    ! grep -q '^systemctl restart' <<< "$calls" || bad "upgrade with a read-only /run: a restart without a marker"
    # The account is still created offline and its failure still fails the install.
    new_root none
    lc_bus_down "$root"
    : > "$root/stub/fail-sysusers"
    rpm_in offline -i "$new"
    [ "$rc" -ne 0 ] || bad "offline install with a failing systemd-sysusers: rpm succeeded"
    files_gone "offline install with a failing systemd-sysusers"
}

# ---- the argument counts: a package whose scriptlets only log $1 ----
new_root
rpm_in -i "$PKG_LOG_OLD"
want_ok "logging package: install"
rpm_in -U "$PKG_LOG_NEW"
want_ok "logging package: upgrade"
rpm_in -e custodio
want_ok "logging package: erase"
[ "$(cat "$root/recorded-args" 2> /dev/null)" = "$(printf '%s\n' 'pre 1' 'post 1' 'pre 2' 'post 2' 'preun 1' 'postun 1' 'preun 0' 'postun 0')" ] \
    || bad "the arguments rpm passed were: $(tr '\n' ';' < "$root/recorded-args" 2> /dev/null)"

# ---- this tree's scriptlets ----
cases "$PKG_NEW"

# ---- mutants: a package built with one scriptlet changed must fail the cases above ----
mutant() { # NAME SCRIPT SED-EXPRESSION
    local dir pkg pkg_old
    dir=$(mutant_dir "$1" "$2" "$3")
    pkg=$(build_rpm "mut-$1" 0.1.1 "$dir")
    pkg_old=$(build_rpm "mut-old-$1" 0.1.0 "$dir")
    mutant_mode=1
    mutant_hit=0
    cases "$pkg" "$pkg_old"
    mutant_mode=0
    [ "$mutant_hit" = 1 ] || bad "mutant '$1' survived"
}
mutant sysusers-ignored-failure pre 's|custodio_create_account \|\| exit 1|custodio_create_account \|\| true|'
mutant bus-check-ignored pre 's|^custodio_bus_check \|\| exit 1|custodio_bus_check \|\| true|'
# shellcheck disable=SC2016 # sed expressions
mutant restart-always post 's|if \[ "\${1:-0}" -ge 2 \] && \[ -e /run/custodio-restart-after-upgrade \]; then|if [ "${1:-0}" -ge 1 ]; then|'
mutant restart-before-bus-reload post 's|^systemctl reload dbus.service .*|systemctl restart custodio.service\n&|'
# shellcheck disable=SC2016 # sed expressions
mutant restart-in-postun-only post '/^if \[ "\${1:-0}" -ge 2 \]/,/^fi/d'
mutant stop-on-upgrade preun 's|-eq 0 \]|-ge 0 ]|'
mutant notice-on-upgrade postun 's|-eq 0 \]|-ge 0 ]|'
mutant enable-in-post post 's|^journalctl --update-catalog .*|&\nsystemctl enable custodio.service|'
mutant no-stop-on-erase preun 's|^    systemctl stop custodio.service.*|    :|'
mutant delete-state postun 's|^    systemctl daemon-reload .*|    rm -rf /var/lib/custodio/\n&|'
# The next mutant (the whole restart removed from %post) is what a package that restarts only from the old package's %postun looks like to the
# upgrade over the F42-era package, which has no %postun: no restart at all. The account moved out of %pre is a mutant of its own, below.
mutant account-in-post pre '/^custodio_create_account || exit 1$/d'

# The account creation moved to %post: with the rule above only %pre may create it, the policy is "present" and %pre has no sysusers call.
dir=$(mutant_dir account-moved post 's|^exit 0$|systemd-sysusers - <<EOT\nu custodio - "Custodio signing service" -\nEOT\nexit 0|')
sed -i '/^custodio_create_account || exit 1$/d' "$dir/pre"
pkg=$(build_rpm mut-account-moved 0.1.1 "$dir")
new_root
rpm_in -i "$pkg"
[ "$(cat "$root/stub/policy-at-sysusers" 2> /dev/null)" = present ] || bad "the account-in-%post mutant is not seen as 'present'"

exit "$fail"
