#!/usr/bin/env bash
# Self-test of refusal-lib.sh and refusal-static.sh, run by the guest before it relies on them and by `just test-scripts`. Each rejection has its
# own control: the check must fail AND say the expected thing; the good fixture must pass. Usage: refusal-selftest.sh
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/refusal-lib.sh
source "$here/refusal-lib.sh"
# shellcheck source=e2e/refusal-static.sh
source "$here/refusal-static.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
bad() { echo "refusal-selftest: FAIL: $*" >&2; failures=$((failures + 1)); }
# rejects WHAT TEXT CMD...: the command fails and its output says TEXT
rejects() {
    local what=$1 text=$2 out
    shift 2
    if out=$("$@" 2>&1); then bad "$what: accepted"; return; fi
    grep -q -- "$text" <<< "$out" || bad "$what: rejected, but without '$text': $out"
}
accepts() { local what=$1 out; shift; out=$("$@" 2>&1) || bad "$what: rejected: $out"; }
fx() { printf '%s' "$2" > "$tmp/$1"; } # fx NAME CONTENT

# --- the files of the package come from the package file
if command -v dpkg-deb > /dev/null; then
    mkdir -p "$tmp/pkgroot/DEBIAN"
    for p in "${REQUIRED_FILES[@]}"; do mkdir -p "$tmp/pkgroot$(dirname "$p")"; echo x > "$tmp/pkgroot$p"; done
    printf 'Package: custodio\nVersion: 1\nArchitecture: all\nMaintainer: t <t@example.org>\nDescription: t\n' > "$tmp/pkgroot/DEBIAN/control"
    dpkg-deb --build "$tmp/pkgroot" "$tmp/fx.deb" > /dev/null 2>&1 || bad "could not build the fixture package"
    package_files "$tmp/fx.deb" > "$tmp/files"
    accepts "list of a real package" list_problems "$tmp/files"
    [ "$(wc -l < "$tmp/files")" -eq "${#REQUIRED_FILES[@]}" ] || bad "package_files lists directories or misses files: $(tr '\n' ' ' < "$tmp/files")"
else
    printf '%s\n' "${REQUIRED_FILES[@]}" > "$tmp/files"
fi
: > "$tmp/empty"
rejects "empty list" 'empty' list_problems "$tmp/empty"
grep -v custodiod "$tmp/files" > "$tmp/nodaemon"
rejects "list without the daemon" 'lacks /usr/lib/custodio/custodiod' list_problems "$tmp/nodaemon"

# --- the precondition: a bus that answers and lacks ProcessFD
fx ok '(a{sv}) 3 "UnixUserID" u 0 "ProcessID" u 311 "UnixGroupIDs" au 1 0
'
accepts "reply without ProcessFD" precondition_problems 0 "$tmp/ok"
fx fd '(a{sv}) 3 "UnixUserID" u 0 "ProcessID" u 311 "ProcessFD" h 5
'
rejects "reply with ProcessFD" 'provides ProcessFD' precondition_problems 0 "$tmp/fd"
fx err 'Failed to connect to bus: No such file or directory
'
rejects "error reply" 'failed with status 1' precondition_problems 1 "$tmp/err"
rejects "empty reply" 'empty' precondition_problems 0 "$tmp/empty"
rejects "success with a text that is no reply" 'not a credentials reply' precondition_problems 0 "$tmp/err"

# --- the install: the package's own check refused
fx good 'Preparing to unpack custodio.deb ...
custodio: the system bus does not provide ProcessFD, which custodiod needs to identify its callers.
dpkg: error processing archive custodio.deb (--install):
 new custodio package pre-installation script subprocess returned error exit status 1
E: Sub-process /usr/bin/dpkg returned an error code (1)
'
accepts "the refusal" install_problems 100 "$tmp/good"
rejects "install that exits 0" 'install succeeded' install_problems 0 "$tmp/good"
rejects "empty output" 'empty' install_problems 100 "$tmp/empty"
fx other 'E: Sub-process /usr/bin/dpkg returned an error code (1)
'
rejects "failure that does not name ProcessFD" "lacks 'does not provide ProcessFD'" install_problems 100 "$tmp/other"
fx query 'custodio: the system bus could not be queried for ProcessFD (busctl exited with status 1).
dpkg: error processing archive x (--install):
 new custodio package pre-installation script subprocess returned error exit status 1
'
rejects "check that could not query the bus" 'lacks .does not provide ProcessFD' install_problems 100 "$tmp/query"
{ cat "$tmp/good"; cat "$tmp/query"; } > "$tmp/mixed"
rejects "refusal text next to a check failure" 'not the refusal' install_problems 100 "$tmp/mixed"
fx nodep 'E: Unable to locate package custodio
custodio: the system bus does not provide ProcessFD
 new custodio package pre-installation script
'
rejects "dependency failure" 'not the refusal' install_problems 100 "$tmp/nodep"
fx noprefix 'the system bus does not provide ProcessFD
 new custodio package pre-installation script subprocess returned error exit status 1
'
rejects "output without the script prefix" 'custodio: ' install_problems 100 "$tmp/noprefix"
fx nopre 'custodio: the system bus does not provide ProcessFD
'
rejects "output without dpkg's report" 'pre-installation script' install_problems 100 "$tmp/nopre"

# --- no file is left
mkdir -p "$tmp/root"
accepts "empty root" files_problems "$tmp/root" "$tmp/files"
mkdir -p "$tmp/root/usr/lib/custodio"
rejects "only /usr/lib/custodio left" '/usr/lib/custodio exists' files_problems "$tmp/root" "$tmp/files"
touch "$tmp/root/usr/lib/custodio/custodiod"
rejects "a packaged file left" '/usr/lib/custodio/custodiod exists' files_problems "$tmp/root" "$tmp/files"
rm -rf "$tmp/root"
mkdir -p "$tmp/root/var/lib/custodio"
rejects "only /var/lib/custodio left" '/var/lib/custodio exists' files_problems "$tmp/root" "$tmp/files"
rm -rf "$tmp/root"
mkdir -p "$tmp/root/usr/lib/systemd/system"
ln -s /nowhere "$tmp/root/usr/lib/systemd/system/custodio.service"
rejects "a dangling link left" 'custodio.service exists' files_problems "$tmp/root" "$tmp/files"

# --- dpkg
accepts "not-installed" status_problems not-installed
accepts "no such package" status_problems absent
for s in installed half-configured unpacked half-installed config-files ''; do rejects "status '$s'" "status of custodio is '$s'" status_problems "$s"; done
accepts "clean audit" audit_problems "$tmp/empty"
fx aud 'The following packages are only half configured: custodio
'
rejects "audit output" 'audit reports' audit_problems "$tmp/aud"

# --- the bus
fx names 'NAME                 PID PROCESS         USER
org.freedesktop.DBus   1 dbus-daemon     messagebus
:1.0                 300 systemd-logind  root
'
accepts "listing without the name" listing_problems owned "$tmp/names"
fx owned 'com.rfirma.Custodio1   500 custodiod root
'
rejects "name owned" 'in the owned list' listing_problems owned "$tmp/owned"
fx act 'org.freedesktop.DBus
com.rfirma.Custodio1
'
rejects "name activatable" 'in the activatable list' listing_problems activatable "$tmp/act"
fx unk 'Call failed: The name is not activatable
'
accepts "call fails: not activatable" call_problems 1 "$tmp/unk"
fx unk2 'Call failed: The name com.rfirma.Custodio1 was not provided by any .service files
'
accepts "call fails: no service file" call_problems 1 "$tmp/unk2"
rejects "call that succeeds" 'succeeded' call_problems 0 "$tmp/unk"
rejects "call that fails for another reason" 'another reason' call_problems 1 "$tmp/err"
accepts "no process" process_problems ''
rejects "live custodiod" 'custodiod runs: 412' process_problems '412'
accepts "no unit" unit_problems 1 inactive
rejects "a unit exists" 'found a unit' unit_problems 0 inactive
rejects "an active unit" 'is active' unit_problems 1 active

# --- the static check: the real files pass, each forbidden thing fails
accepts "the real refusal files" static_problems "$here/refusal.sh" "$here/refusal-lib.sh" "$here/targets/ubuntu2404/install.sh"
# sec CODE...: a fixture refusal.sh with CODE inside its markers
sec() { { echo '#!/usr/bin/env bash'; echo "$SECTION_BEGIN"; printf '%s\n' "$@"; echo "$SECTION_END"; } > "$tmp/refusal.sh"; }
sec 'echo a' 'echo b' 'echo c'
accepts "a harmless section" static_problems "$tmp/refusal.sh"
for code in 'systemctl stop custodio' 'systemctl restart custodio' 'systemctl start custodio' 'systemctl daemon-reload' 'pkill custodiod' 'kill 12' \
    'rm -rf /usr/lib/custodio' 'dpkg --purge custodio' 'apt-get remove -y custodio' 'apt-get install -y dbus-broker' \
    'echo x > /etc/dbus-1/system.d/x.conf' 'cp x /usr/share/dbus-1/y'; do
    sec 'echo a' 'echo b' "$code"
    rejects "section with '$code'" 'forbidden pattern' static_problems "$tmp/refusal.sh"
done
sec '# systemctl stop custodio' 'echo a' 'echo b' 'echo c'
accepts "a comment naming a forbidden command" static_problems "$tmp/refusal.sh"
printf '#!/usr/bin/env bash\necho a\necho b\npkill custodiod\n' > "$tmp/install.sh"
rejects "a called file with pkill" 'forbidden pattern' static_problems "$tmp/install.sh"
printf '#!/usr/bin/env bash\nsystemctl stop custodio\necho a\necho b\n' > "$tmp/refusal.sh"
rejects "no markers" 'lacks its section markers' static_problems "$tmp/refusal.sh"
sec
rejects "empty section" 'empty' static_problems "$tmp/refusal.sh"
rejects "missing file" 'does not exist' static_problems "$tmp/none.sh"

[ "$failures" -eq 0 ] || { echo "refusal-selftest: $failures failure(s)" >&2; exit 1; }
echo "refusal-selftest: all controls behave"
