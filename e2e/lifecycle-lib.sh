# shellcheck shell=bash
# Sourced by the lifecycle case (lifecycle.sh) and its self-test (lifecycle-selftest.sh). The checks of F49 (removal, purge, reinstall) as
# functions that print one message per problem and return non-zero when there is any, so the self-test can feed each one fixtures.
# The state comparisons (snapshot_state, compare_state, compare_listing) and the version readers are F48's, in upgrade-lib.sh.

BUS_NAME=com.rfirma.Custodio1
# shellcheck source=e2e/daemon-path.sh
source "$(dirname "${BASH_SOURCE[0]}")/daemon-path.sh"

# The shared system directories: a directory that the package lists (or whose file it lists) and that stays after the removal is not a leftover
# when it is in this list. A fixed list, no pattern, and no path named after custodio: /usr/lib/custodio, /usr/libexec/custodio, /usr/share/doc/custodio and
# /usr/share/licenses/custodio are not in it, so they must be gone. The /lib entries are the usr-merge aliases of the unit directory.
SHARED_DIRS=(
    /lib /lib/systemd /lib/systemd/system
    /usr /usr/bin /usr/lib /usr/libexec /usr/lib/systemd /usr/lib/systemd/catalog /usr/lib/systemd/system /usr/lib/sysusers.d /usr/lib/tmpfiles.d
    /usr/share /usr/share/dbus-1 /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d /usr/share/doc
    /usr/share/libalpm /usr/share/libalpm/hooks /usr/share/libalpm/scripts /usr/share/licenses
    /usr/share/man /usr/share/man/man1 /usr/share/p11-kit /usr/share/p11-kit/modules /usr/share/polkit-1 /usr/share/polkit-1/actions
)

# What every package must list: the PKCS#11 module, the unit, the D-Bus policy and the D-Bus activation file. The daemon too, at the path of
# its format (daemon_path).
REQUIRED_PATHS=(
    /usr/lib/custodio/libcustodio_pkcs11.so
    /usr/lib/systemd/system/custodio.service
    /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf
    /usr/share/dbus-1/system-services/com.rfirma.Custodio1.service
)

# --- the files of the package, read from the package file ----------------------------------------------------------------------

# entries_from_deb / entries_from_rpm / entries_from_arch: read the output of the target's tool on stdin, print "f PATH" or "d PATH".
entries_from_deb() { awk '{ p = $6; sub(/^\./, "", p); sub(/\/$/, "", p); if (p != "") print (substr($1, 1, 1) == "d" ? "d " : "f ") p }'; }
entries_from_rpm() { awk 'NF == 2 { print (substr($1, 1, 1) == "d" ? "d " : "f ") $2 }'; } # input: "PERMS PATH" (rpm -qp --qf '[%{FILEMODES:perms} %{FILENAMES}\n]')
entries_from_arch() { awk 'NF == 2 { p = $2; if (p ~ /\/$/) { sub(/\/$/, "", p); print "d " p } else print "f " p }'; } # input of pacman -Qlp: "NAME PATH"

# with_ancestors: stdin "f|d PATH" lines; prints them with every ancestor directory of every entry added (the rpm of this project lists
# files only, but the directories its files need are the package's too), sorted, without duplicates, without the root.
with_ancestors() {
    awk '{
        print
        p = $2
        while (sub(/\/[^\/]*$/, "", p) && p != "") print "d " p
    }' | LC_ALL=C sort -u
}

# packaged_entries FORMAT FILE: the entries of the package file with the target's own tool.
packaged_entries() {
    case $1 in
    deb) dpkg-deb -c "$2" | entries_from_deb | with_ancestors ;;
    rpm) rpm -qp --qf '[%{FILEMODES:perms} %{FILENAMES}\n]' "$2" 2> /dev/null | entries_from_rpm | with_ancestors ;;
    arch) pacman -Qlp "$2" | entries_from_arch | with_ancestors ;;
    *) echo "packaged_entries: unknown format '$1'" >&2; return 1 ;;
    esac
}

# entries_problems LIST [FORMAT]: the list is not empty and holds the files the package must install, the daemon at the path of its format only.
# Without FORMAT (the leftover check, which only reads a list it was given) the format is the one whose daemon path the list holds.
entries_problems() {
    local list=$1 p bad=0 daemon other fmt=${2:-}
    if [ -z "$fmt" ]; then
        if grep -qx 'f /usr/libexec/custodio/custodiod' "$list"; then fmt=deb; else fmt=arch; fi
    fi
    daemon=$(daemon_path "$fmt") || return 1
    other=$(other_daemon_path "$fmt")
    grep -qx "f $daemon" "$list" || { echo "package: the list lacks $daemon"; bad=1; }
    ! grep -qx "f $other" "$list" || { echo "package: the list has the daemon at $other, the path of another format"; bad=1; }
    if [ "$(grep -c '^f ' "$list" || true)" -eq 0 ]; then echo "package: the list holds no file"; return 1; fi
    if [ "$(grep -c '^d ' "$list" || true)" -eq 0 ]; then echo "package: the list holds no directory"; bad=1; fi
    for p in "${REQUIRED_PATHS[@]}"; do
        grep -qx "f $p" "$list" || { echo "package: the list lacks $p"; bad=1; }
    done
    [ "$bad" -eq 0 ]
}

is_shared_dir() { local d x; d=$1; for x in "${SHARED_DIRS[@]}"; do [ "$x" = "$d" ] && return 0; done; return 1; }

# owner_of FORMAT PATH: succeeds when an installed package owns PATH (asked after the removal, so it is another package).
owner_of() {
    case $1 in
    deb) dpkg -S -- "$2" > /dev/null 2>&1 ;;
    rpm) rpm -qf -- "$2" > /dev/null 2>&1 ;;
    arch) pacman -Qo -- "$2" > /dev/null 2>&1 ;;
    *) return 1 ;;
    esac
}

# leftover_problems LIST OWNER_COMMAND [ROOT]: after the removal no file of LIST exists (test -e and -L), and no directory exists that is
# not in SHARED_DIRS and that no other package owns (OWNER_COMMAND PATH succeeds when another package owns it). ROOT is a prefix for fixtures.
leftover_problems() {
    local list=$1 owner=$2 root=${3:-} kind path bad=0
    entries_problems "$list" || return 1
    while read -r kind path; do
        if [ "$kind" = f ]; then
            if [ -e "$root$path" ] || [ -L "$root$path" ]; then echo "leftover: file $path"; bad=1; fi
        else
            is_shared_dir "$path" && continue
            # shellcheck disable=SC2086 # OWNER_COMMAND is a command with its arguments, split on purpose
            $owner "$path" && continue
            if [ -e "$root$path" ] || [ -L "$root$path" ]; then echo "leftover: directory $path (owned by no other package)"; bad=1; fi
        fi
    done < "$list"
    [ "$bad" -eq 0 ]
}

# --- the service --------------------------------------------------------------------------------------------------------------

# stopped_problems ACTIVE MAINPID PROC OLD_PID: the unit's ActiveState is not active, MainPID is 0, the pid that ran before is gone.
stopped_problems() {
    local active=$1 mainpid=$2 proc=$3 old=$4 bad=0
    if [ "$active" = active ]; then echo "service: custodio.service is still active"; bad=1; fi
    if [ "$mainpid" != 0 ]; then echo "service: custodio.service still has the main pid '$mainpid'"; bad=1; fi
    if [ -e "$proc/$old" ]; then echo "service: the process $old that ran before is still there"; bad=1; fi
    [ "$bad" -eq 0 ]
}

# running_problems ACTIVE MAINPID: the unit is active with a main pid (before the removal, and after the activation of the reinstalled one).
running_problems() {
    local active=$1 mainpid=$2 bad=0
    [ "$active" = active ] || { echo "service: custodio.service is not active ($active)"; bad=1; }
    case $mainpid in '' | 0 | *[!0-9]*) echo "service: custodio.service has no main pid ('$mainpid')"; bad=1 ;; esac
    [ "$bad" -eq 0 ]
}

# not_active_problems ACTIVE: right before the first call after the reinstall the unit must not be active, so that the call is what starts it.
not_active_problems() {
    [ "$1" != active ] || { echo "service: custodio.service is active before the first call after the install; the call would prove nothing"; return 1; }
}

# --- activation ---------------------------------------------------------------------------------------------------------------

# activatable_problems LISTING: the list of activatable names (busctl --system list --activatable) holds the bus name.
activatable_problems() {
    awk -v n="$BUS_NAME" '$1 == n { found = 1 } END { exit !found }' "$1" || { echo "activation: $BUS_NAME is not in the list of activatable names"; return 1; }
}

# not_activatable_problems LISTING CALL_RC CALL_OUTPUT PROCESSES: the name is not listed, a call to it failed with the bus's own "no such
# service" error, and no custodiod process exists (PROCESSES is the output of pgrep -x custodiod: empty when there is none).
not_activatable_problems() {
    local listing=$1 rc=$2 out=$3 procs=$4 bad=0
    if grep -q "$BUS_NAME" "$listing"; then echo "activation: $BUS_NAME is still in the list of activatable names"; bad=1; fi
    if [ "$rc" -eq 0 ]; then echo "activation: a call to $BUS_NAME succeeded"; bad=1
    elif ! grep -Eq 'ServiceUnknown|not activatable|not provided by any' <<< "$out"; then echo "activation: the call failed, but not with a no-such-service error: $out"; bad=1; fi
    if [ -n "$procs" ]; then echo "activation: a custodiod process exists: $procs"; bad=1; fi
    [ "$bad" -eq 0 ]
}

# --- the state directory and the account -----------------------------------------------------------------------------------------

# state_problems LINK BEFORE_SNAPSHOT AFTER_SNAPSHOT_FILE: the directory (through the link) exists, and its snapshot equals the one taken before.
state_problems() {
    local link=$1 before=$2 after=$3
    if [ ! -e "$link" ]; then echo "state: $link is gone"; return 1; fi
    snapshot_state "$link" > "$after" || { echo "state: $link cannot be read"; return 1; }
    compare_state "$before" "$after"
}

# account_problems BEFORE AFTER: the getent passwd lines of custodio before and after: the account exists and is the same uid and gid.
account_problems() {
    local before=$1 after=$2 bad=0 ub ua
    if [ -z "$after" ]; then echo "account: the custodio account is gone"; return 1; fi
    [ -n "$before" ] || { echo "account: no entry was recorded before"; return 1; }
    ub=$(cut -d: -f3,4 <<< "$before")
    ua=$(cut -d: -f3,4 <<< "$after")
    if [ "$ub" != "$ua" ]; then echo "account: uid:gid was $ub and is $ua"; bad=1; fi
    [ "$bad" -eq 0 ]
}

# --- the notice -------------------------------------------------------------------------------------------------------------

# notice_problems OUTPUT_FILE: the captured output of the removal tool says where the keys are, that they stay, and the warning of SPEC
# section 2 (the phrase is the one in the maintainer scripts of the three formats; no regex characters, so it is matched as a fixed string).
notice_problems() {
    local f=$1 bad=0
    if [ ! -s "$f" ]; then echo "notice: the captured output of the removal is empty"; return 1; fi
    grep -qF '/var/lib/custodio' "$f" || { echo "notice: the output does not name /var/lib/custodio"; bad=1; }
    grep -qF 'still on disk' "$f" || { echo "notice: the output does not say the keys are still on disk"; bad=1; }
    grep -qF 'destroys the keys for good' "$f" || { echo "notice: the output lacks the warning that deleting the keys destroys the keys for good"; bad=1; }
    [ "$bad" -eq 0 ]
}

# --- the package database -------------------------------------------------------------------------------------------------------

# db_status FORMAT: installed, config-files (deb: removed, configuration left) or not-installed.
# shellcheck disable=SC2016 # dpkg-query's own format string
db_status() {
    local s
    case $1 in
    deb) s=$(dpkg-query -W -f='${db:Status-Status}' custodio 2> /dev/null) || s=not-installed; echo "${s:-not-installed}" ;;
    rpm) if rpm -q custodio > /dev/null 2>&1; then echo installed; else echo not-installed; fi ;;
    arch) if pacman -Q custodio > /dev/null 2>&1; then echo installed; else echo not-installed; fi ;;
    *) return 1 ;;
    esac
}

# db_leftovers FORMAT: what the database still holds of the removed package, for the log (the conffiles of a deb in config-files state).
# shellcheck disable=SC2016 # dpkg-query's own format string
db_leftovers() {
    case $1 in
    deb) echo "conffiles: [$(dpkg-query -W -f='${Conffiles}' custodio 2> /dev/null | tr '\n' ' ')]" ;;
    *) echo "nothing (no such state)" ;;
    esac
}

# removed_problems STATUS KIND: after a removal the database does not hold the package as installed (a deb may keep config-files);
# after a purge it holds nothing.
removed_problems() {
    local status=$1 kind=$2
    case $kind:$status in
    remove:not-installed | remove:config-files | purge:not-installed) return 0 ;;
    *) echo "database: after the $kind the package is '$status'"; return 1 ;;
    esac
}

# installed_problems STATUS VERSION EXPECTED: after a reinstall the package is installed at the version of N+1.
installed_problems() {
    local status=$1 version=$2 expected=$3 bad=0
    [ "$status" = installed ] || { echo "database: after the reinstall the package is '$status'"; bad=1; }
    [ "$version" = "$expected" ] || { echo "database: after the reinstall the version is '$version', not $expected"; bad=1; }
    [ "$bad" -eq 0 ]
}

# --- no import, no manual start or stop ---------------------------------------------------------------------------------------------

# The words are split so that this file does not contain what it forbids (it is one of the files that are checked).
_k='kill'
_imp='import'
_forbidden="${_imp}[.]py|pkcs11-tool[^|]*(--write-object|--${_imp})|custodio[[:space:]]+${_imp}\b|systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(restart|try-restart|reload|reload-or-restart|try-reload-or-restart|daemon-reload|daemon-reexec|start|stop|${_k}|enable|disable|mask|reset-failed)\b|\b(p${_k}|${_k}all|service[[:space:]]+custodio)\b|\b${_k}[[:space:]]"

# lifecycle_static_problems SECTION_FILE FILE...: the section of SECTION_FILE between "# BEGIN lifecycle-case" and "# END lifecycle-case"
# exists once, is not empty, and neither it nor any whole FILE (the scripts it calls) imports a key or starts, stops, reloads or kills anything
# by hand. The scripts that run the target's removal tool must not throw its output away.
lifecycle_static_problems() {
    local file=$1 section n_begin n_end bad=0 f body
    shift
    n_begin=$(grep -c '^# BEGIN lifecycle-case$' "$file" || true)
    n_end=$(grep -c '^# END lifecycle-case$' "$file" || true)
    if [ "$n_begin" -ne 1 ] || [ "$n_end" -ne 1 ]; then echo "static: $file needs exactly one BEGIN and one END marker of lifecycle-case"; return 1; fi
    section=$(sed -n '/^# BEGIN lifecycle-case$/,/^# END lifecycle-case$/p' "$file" | grep -v '^[[:space:]]*#' | sed '/^[[:space:]]*$/d')
    if [ -z "$section" ]; then echo "static: the lifecycle-case section of $file is empty"; return 1; fi
    if grep -Eq "$_forbidden" <<< "$section"; then echo "static: the lifecycle-case section of $file imports a key or starts, stops or kills something by hand"; bad=1; fi
    for f in "$@"; do
        [ -f "$f" ] || { echo "static: $f does not exist"; bad=1; continue; }
        body=$(grep -v '^[[:space:]]*#' "$f" | sed '/^[[:space:]]*$/d')
        if [ -z "$body" ]; then echo "static: $f is empty"; bad=1; continue; fi
        if grep -Eq "$_forbidden" <<< "$body"; then echo "static: $f imports a key or starts, stops or kills something by hand"; bad=1; fi
        case $(basename "$f") in
        remove.sh | purge.sh)
            if grep -q '/dev/null' <<< "$body"; then echo "static: $f throws output away; the notice of the removal must be captured"; bad=1; fi
            ;;
        esac
    done
    [ "$bad" -eq 0 ]
}
