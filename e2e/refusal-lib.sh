# shellcheck shell=bash
# Sourced by the refusal case (refusal.sh) and its self-test (refusal-selftest.sh). The checks of F50 (the package refuses to install on a bus
# without ProcessFD) as functions that print one message per problem and return non-zero when there is any, so the self-test can feed each one
# fixtures. The patterns the static check forbids live in refusal-static.sh.

BUS_NAME=com.rfirma.Custodio1
# The one reason the package's check refuses a bus that answers but lacks ProcessFD (packaging/bus-check.sh). The two other messages that name
# ProcessFD ("could not be queried", "cannot check") are failures of the check itself and must not pass as this refusal.
REFUSAL_PHRASE='does not provide ProcessFD'

REQUIRED_FILES=(
    /usr/lib/custodio/custodiod
    /usr/lib/custodio/libcustodio_pkcs11.so
    /usr/lib/systemd/system/custodio.service
    /usr/share/dbus-1/system.d/com.rfirma.Custodio1.conf
    /usr/share/dbus-1/system-services/com.rfirma.Custodio1.service
)
OWNED_DIRS=(/usr/lib/custodio /var/lib/custodio)

# package_files DEB: the non-directory entries of the package file (never of the installed system), one absolute path per line.
package_files() { dpkg-deb -c "$1" | awk 'substr($1, 1, 1) != "d" { p = $6; sub(/^\./, "", p); if (p != "") print p }'; }

# list_problems LISTFILE: the package lists files, and the ones the refusal is about.
list_problems() {
    local f=$1 p bad=0
    if [ "$(grep -c . "$f" || true)" -eq 0 ]; then echo "package: the list of packaged files is empty"; return 1; fi
    for p in "${REQUIRED_FILES[@]}"; do
        grep -qx "$p" "$f" || { echo "package: the list lacks $p"; bad=1; }
    done
    return "$bad"
}

# precondition_problems RC REPLYFILE: the reply of the running bus to the credentials of the bus itself is a success and has no ProcessFD.
precondition_problems() {
    local rc=$1 f=$2
    if [ "$rc" -ne 0 ]; then echo "bus: the credentials query failed with status $rc"; return 1; fi
    if [ ! -s "$f" ]; then echo "bus: the credentials reply is empty"; return 1; fi
    if ! grep -q '"ProcessID"' "$f"; then echo "bus: the reply is not a credentials reply"; return 1; fi
    if grep -q 'ProcessFD' "$f"; then echo "bus: the bus provides ProcessFD, so there is nothing to refuse"; return 1; fi
}

# install_problems RC OUTFILE: the apt install failed because of the package's own check.
install_problems() {
    local rc=$1 f=$2 bad=0
    if [ "$rc" -eq 0 ]; then echo "install: the install succeeded"; bad=1; fi
    if [ ! -s "$f" ]; then echo "install: the captured output is empty"; return 1; fi
    grep -q "$REFUSAL_PHRASE" "$f" || { echo "install: the output lacks '$REFUSAL_PHRASE'"; bad=1; }
    grep -q '^custodio: ' "$f" || { echo "install: the output has no line from the package script (custodio: )"; bad=1; }
    grep -q 'pre-installation script' "$f" || { echo "install: dpkg did not report the pre-installation script failing"; bad=1; }
    if grep -Eq 'Unable to locate|unmet dependencies|Unable to correct problems|could not be queried|cannot check that' "$f"; then
        echo "install: the failure is a dependency, network or check failure, not the refusal"; bad=1
    fi
    return "$bad"
}

# files_problems ROOT LISTFILE: none of the packaged files, nor the directories the package owns, exists under ROOT.
files_problems() {
    local root=$1 p bad=0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if [ -e "$root$p" ] || [ -L "$root$p" ]; then echo "files: $p exists"; bad=1; fi
    done < "$2"
    for p in "${OWNED_DIRS[@]}"; do
        if [ -e "$root$p" ] || [ -L "$root$p" ]; then echo "files: $p exists"; bad=1; fi
    done
    return "$bad"
}

# status_problems STATUS: the dpkg status is not-installed, or absent (dpkg-query found no such package).
status_problems() {
    case $1 in
    not-installed | absent) return 0 ;;
    *) echo "dpkg: the status of custodio is '$1'"; return 1 ;;
    esac
}
# audit_problems OUTFILE: dpkg --audit printed nothing.
audit_problems() { if [ -s "$1" ]; then echo "dpkg: --audit reports: $(head -n 3 "$1" | tr '\n' ' ')"; return 1; fi; }

# listing_problems NAME LISTFILE: LISTFILE (busctl list, or list --activatable) does not hold the bus name.
listing_problems() {
    if grep -Eq "(^|[[:space:]])${BUS_NAME//./\\.}([[:space:]]|\$)" "$2"; then echo "bus: $BUS_NAME is in the $1 list"; return 1; fi
}
# call_problems RC OUTFILE: a call to the name fails because nothing provides it.
call_problems() {
    if [ "$1" -eq 0 ]; then echo "bus: a call to $BUS_NAME succeeded"; return 1; fi
    grep -Eqi 'ServiceUnknown|not activatable|not provided by any' "$2" || { echo "bus: the call failed for another reason: $(head -n 2 "$2" | tr '\n' ' ')"; return 1; }
}
# process_problems PIDS: no custodiod process (the output of pgrep -x custodiod).
process_problems() { if [ -n "${1//[[:space:]]/}" ]; then echo "process: custodiod runs: $1"; return 1; fi; }
# unit_problems CATRC ACTIVE: there is no unit and it is not active.
unit_problems() {
    local bad=0
    if [ "$1" -eq 0 ]; then echo "unit: systemctl cat custodio found a unit"; bad=1; fi
    if [ "$2" = active ]; then echo "unit: custodio is active"; bad=1; fi
    return "$bad"
}
