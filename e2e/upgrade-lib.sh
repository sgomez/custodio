# shellcheck shell=bash
# Sourced by the upgrade case (upgrade.sh) and its self-test (upgrade-selftest.sh). The comparisons of F48 as functions that
# print one message per problem and return non-zero when there is any, so the self-test can feed each one fixtures.

STATE_LINK=${STATE_LINK:-/var/lib/custodio}
# shellcheck source=e2e/daemon-path.sh
source "$(dirname "${BASH_SOURCE[0]}")/daemon-path.sh"

# unit_binary UNIT_FILE: the executable the unit starts, from its last ExecStart line: the prefixes (- @ ! + :) and the arguments are
# stripped. The old-path package has its daemon at /usr/lib/custodio and the new one at its format's path (daemon_path), so the
# path is read from the unit before and after the upgrade instead of being a constant.
unit_binary() {
    local line path
    [ -f "$1" ] || { echo "unit_binary: no unit file '$1'" >&2; return 1; }
    line=$(grep -E '^[[:space:]]*ExecStart=' "$1" | tail -n 1 || true)
    [ -n "$line" ] || { echo "unit_binary: no ExecStart in '$1'" >&2; return 1; }
    line=${line#*=}
    line=${line#"${line%%[![:space:]]*}"}
    while [[ $line == [-@!+:]* ]]; do line=${line#?}; done
    path=${line%%[[:space:]]*}
    [[ $path == /* ]] || { echo "unit_binary: ExecStart of '$1' is not an absolute path ('$path')" >&2; return 1; }
    printf '%s\n' "$path"
}

# oldpath_problems BEFORE AFTER: the upgrade from the package with the daemon at the old path (F61) moved the service: before it ran the old
# path, after it runs the libexec path of the new package, and the two are different files.
oldpath_problems() {
    local before=$1 after=$2 bad=0
    if [ "$before" != "$OLD_DAEMON_PATH" ]; then echo "oldpath: the service ran $before before the upgrade, not the old path $OLD_DAEMON_PATH"; bad=1; fi
    if [ "$after" = "$before" ]; then echo "oldpath: the service runs $after after the upgrade, the same path as before"; bad=1; fi
    if [ "$after" = "$OLD_DAEMON_PATH" ]; then echo "oldpath: the unit still names the old path $OLD_DAEMON_PATH after the upgrade"; bad=1; fi
    if [ "$after" != "$(daemon_path deb)" ]; then echo "oldpath: the service runs $after after the upgrade, not $(daemon_path deb)"; bad=1; fi
    [ "$bad" -eq 0 ]
}

# unit_file: the unit file of custodio.service as systemd resolves it now.
unit_file() { systemctl show -p FragmentPath --value custodio; }

# --- package files and versions ---------------------------------------------------------------------------------------------

pkg_format() { # FILE: deb, rpm or arch, by the name
    case $1 in
    *.deb) echo deb ;;
    *.rpm) echo rpm ;;
    *.pkg.tar.zst) echo arch ;;
    *) echo "pkg_format: unknown package file '$1'" >&2; return 1 ;;
    esac
}

pkg_file_version() { # FORMAT FILE: the version of the package file, as the target's own tool reads it
    case $1 in
    deb) dpkg-deb -f "$2" Version ;;
    rpm) rpm -qp --qf '%{VERSION}-%{RELEASE}' "$2" 2> /dev/null ;;
    arch) pacman -Qp "$2" | awk '{ print $2 }' ;;
    *) return 1 ;;
    esac
}

# shellcheck disable=SC2016 # the next function holds dpkg-query's own format string
installed_version() { # FORMAT: the version the target's package database holds for custodio
    case $1 in
    deb) dpkg-query -W -f='${Version}' custodio ;;
    rpm) rpm -q --qf '%{VERSION}-%{RELEASE}' custodio ;;
    arch) pacman -Q custodio | awk '{ print $2 }' ;;
    *) return 1 ;;
    esac
}

version_tool() { # FORMAT: the name of the comparison used, for the log
    case $1 in
    deb) echo "dpkg --compare-versions" ;;
    rpm) echo "rpm.vercmp (rpm --eval)" ;;
    arch) echo "vercmp" ;;
    *) return 1 ;;
    esac
}

# version_greater FORMAT NEW OLD: succeeds only if the target's own tool says NEW is strictly greater than OLD. The rpm and Arch tools
# print 1, 0 or -1; the answer must be exactly 1 (an empty output, an error text or any other number fails).
version_greater() {
    local fmt=$1 new=$2 old=$3 r
    [[ $new =~ ^[A-Za-z0-9.+~_^-]+$ && $old =~ ^[A-Za-z0-9.+~_^-]+$ ]] || { echo "version_greater: unexpected characters in a version" >&2; return 1; }
    case $fmt in
    deb) dpkg --compare-versions "$new" gt "$old" ;;
    rpm)
        r=$(rpm --eval "%{lua: print(rpm.vercmp('$new','$old'))}") || return 1
        [ "$r" = 1 ]
        ;;
    arch)
        r=$(vercmp "$new" "$old") || return 1
        [ "$r" = 1 ]
        ;;
    *) return 1 ;;
    esac
}

# upgrade_gate FORMAT FROM_FILE TO_FILE: what must hold before anything is installed. The database holds FROM's version, the two
# versions differ, and the target's own tool says TO is strictly greater. Prints one message per problem; fails on any. The case
# calls it before the install command, so an equal or lower version never reaches the install.
upgrade_gate() {
    local fmt=$1 from=$2 to=$3 vf vt
    vf=$(pkg_file_version "$fmt" "$from") || { echo "gate: cannot read the version of $from"; return 1; }
    vt=$(pkg_file_version "$fmt" "$to") || { echo "gate: cannot read the version of $to"; return 1; }
    if [ "$(installed_version "$fmt")" != "$vf" ]; then echo "gate: before the upgrade the database holds $(installed_version "$fmt"), not $vf"; return 1; fi
    if [ "$vf" = "$vt" ]; then echo "gate: both packages have the same version ($vf)"; return 1; fi
    if ! version_greater "$fmt" "$vt" "$vf"; then echo "gate: the new version ($vt) is not greater than the old one ($vf) by $(version_tool "$fmt")"; return 1; fi
    echo "e2e: upgrade: $(version_tool "$fmt") says $vt is greater than $vf"
}

# --- the state directory --------------------------------------------------------------------------------------------------

# snapshot_state [DIR]: one line per entry of the state directory (through the link to /var/lib/private/custodio), sorted:
# "TYPE UID GID MODE HASH PATH" with the sha256 of the content (of the link text for a symlink; "-" for a directory).
snapshot_state() (
    local root p kind hash
    root=$(readlink -f "${1:-$STATE_LINK}")
    [ -d "$root" ] || { echo "snapshot_state: $root is not a directory" >&2; return 1; }
    cd "$root" || return 1
    find . -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' p; do
        if [ -L "$p" ]; then
            kind=l
            hash=$(printf '%s' "$(readlink "$p")" | sha256sum | cut -d' ' -f1)
        elif [ -d "$p" ]; then
            kind=d
            hash=-
        else
            kind=f
            hash=$(sha256sum < "$p" | cut -d' ' -f1)
        fi
        echo "$kind $(stat -c '%u %g %a' "$p") $hash $p"
    done
)

# compare_state BEFORE AFTER: files holding two snapshots. Fails on anything that differs, one message per entry.
compare_state() {
    local before=$1 after=$2 bad=0 kind uid gid mode hash path files
    local -A b a
    files=$(grep -c '^f ' "$before" || true)
    if [ "$files" -lt 2 ]; then echo "state: the snapshot before holds $files regular files (the two imported keys need at least 2)"; bad=1; fi
    while read -r kind uid gid mode hash path; do b[$path]="$kind $uid $gid $mode $hash"; done < "$before"
    while read -r kind uid gid mode hash path; do a[$path]="$kind $uid $gid $mode $hash"; done < "$after"
    for path in "${!b[@]}"; do
        if [ -z "${a[$path]+x}" ]; then echo "state: removed: $path"; bad=1; continue; fi
        [ "${a[$path]}" != "${b[$path]}" ] || continue
        read -r kind uid gid mode hash <<< "${b[$path]}"
        local k2 u2 g2 m2 h2
        read -r k2 u2 g2 m2 h2 <<< "${a[$path]}"
        [ "$kind" = "$k2" ] || { echo "state: type changed: $path"; bad=1; continue; }
        [ "$hash" = "$h2" ] || { echo "state: content changed: $path"; bad=1; }
        { [ "$uid" = "$u2" ] && [ "$gid" = "$g2" ]; } || { echo "state: owner changed: $path"; bad=1; }
        if [ "$mode" != "$m2" ]; then
            if [ "$kind" = d ]; then echo "state: directory mode changed: $path"; else echo "state: mode changed: $path"; fi
            bad=1
        fi
    done
    for path in "${!a[@]}"; do
        [ -n "${b[$path]+x}" ] || { echo "state: added: $path"; bad=1; }
    done
    [ "$bad" -eq 0 ]
}

# compare_listing BEFORE AFTER: the key listings taken through the PKCS#11 module are not empty, name both keys, and are identical.
compare_listing() {
    local before=$1 after=$2 bad=0 f key
    for f in "$before" "$after"; do
        if [ ! -s "$f" ]; then echo "listing: $f is empty"; bad=1; continue; fi
        for key in rsa1 ec1; do
            grep -q "$key" "$f" || { echo "listing: $f does not name $key"; bad=1; }
        done
    done
    # sha256sum, not cmp: diffutils is not on every target image
    [ "$(sha256sum < "$before")" = "$(sha256sum < "$after")" ] || { echo "listing: the listing after the upgrade differs from the one before"; bad=1; }
    [ "$bad" -eq 0 ]
}

# --- the service ----------------------------------------------------------------------------------------------------------

# exe_problems PROC PID INSTALLED: the process runs the file now installed at INSTALLED, by device and inode (the content of N+1 is
# the same as N's, so a hash cannot tell them apart), and its exe link is not "(deleted)".
exe_problems() {
    local proc=$1 pid=$2 installed=$3 link mine theirs bad=0
    link=$(readlink "$proc/$pid/exe" 2> /dev/null || true)
    if [ -z "$link" ]; then echo "service: pid $pid has no exe link"; return 1; fi
    case $link in *' (deleted)') echo "service: pid $pid runs a deleted binary ($link)"; bad=1 ;; esac
    mine=$(stat -L -c '%d:%i' "$proc/$pid/exe" 2> /dev/null || true)
    theirs=$(stat -L -c '%d:%i' "$installed" 2> /dev/null || true)
    if [ -z "$mine" ] || [ -z "$theirs" ] || [ "$mine" != "$theirs" ]; then
        echo "service: pid $pid does not run the installed file (device:inode ${mine:-none}, installed ${theirs:-none})"; bad=1
    fi
    [ "$bad" -eq 0 ]
}

# service_problems PROC OLD_PID NEW_PID INSTALLED: the service restarted (new pid), the new process runs the installed file, and the old
# process is gone or still runs a deleted binary.
service_problems() {
    local proc=$1 old=$2 new=$3 installed=$4 bad=0 link
    if [ "$old" = "$new" ]; then echo "service: the main pid did not change ($new), the service did not restart"; bad=1; fi
    exe_problems "$proc" "$new" "$installed" || bad=1
    if [ "$old" != "$new" ] && [ -e "$proc/$old" ]; then
        link=$(readlink "$proc/$old/exe" 2> /dev/null || true)
        case $link in *' (deleted)') ;; *) echo "service: the old pid $old still runs a binary that is not deleted ($link)"; bad=1 ;; esac
    fi
    [ "$bad" -eq 0 ]
}

# --- no manual step -------------------------------------------------------------------------------------------------------

# manual_step_problems FILE: the section of FILE between "# BEGIN upgrade-case" and "# END upgrade-case" must exist, not be empty, and
# contain no command that restarts, reloads or starts anything by hand (reading state with systemctl show/is-active is allowed).
manual_step_problems() {
    local file=$1 section n_begin n_end
    n_begin=$(grep -c '^# BEGIN upgrade-case$' "$file" || true)
    n_end=$(grep -c '^# END upgrade-case$' "$file" || true)
    if [ "$n_begin" -ne 1 ] || [ "$n_end" -ne 1 ]; then echo "manual: $file needs exactly one BEGIN and one END marker of upgrade-case"; return 1; fi
    section=$(sed -n '/^# BEGIN upgrade-case$/,/^# END upgrade-case$/p' "$file" | grep -v '^[[:space:]]*#' | sed '/^[[:space:]]*$/d')
    if [ -z "$section" ]; then echo "manual: the upgrade-case section of $file is empty"; return 1; fi
    if grep -Eq 'systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(restart|try-restart|reload|reload-or-restart|try-reload-or-restart|daemon-reload|daemon-reexec|start|stop|kill|enable|disable|mask|reset-failed)\b|\b(pkill|killall|service[[:space:]]+custodio)\b|\bkill[[:space:]]|busctl[^|]*[[:space:]]call\b|custodiod[[:space:]]*&' <<< "$section"; then
        echo "manual: the upgrade-case section of $file runs a command that restarts or starts a service by hand"
        return 1
    fi
    return 0
}
