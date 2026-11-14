#!/usr/bin/env bash
# The per-user refresh units (F184, acceptance 12, trigger part): the checks of scripts/check_user_units.py on the source tree, each
# negative control on a fixture copy with one fault, and one run of the service's command line against the debug CLI.
# `systemd-analyze verify` runs on copies with the binary path replaced by a stub (the container has no /usr/bin/custodio).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHECK=$ROOT/scripts/check_user_units.py
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
fail=0
bad() { echo "test-user-refresh-units: $*" >&2; fail=1; }
for tool in systemd-analyze python3 cargo; do
    command -v "$tool" > /dev/null || { echo "test-user-refresh-units: required tool '$tool' is not installed" >&2; exit 1; }
done

# The CLI the run below needs; a cold tree builds the crate here (test-scripts gives no ordering).
timeout 1500 cargo build -p custodio-cli --locked --quiet --manifest-path "$ROOT/Cargo.toml" || { echo "test-user-refresh-units: cannot build custodio-cli" >&2; exit 1; }
CLI=$ROOT/target/debug/custodio-cli

check() { python3 -I -B "$CHECK" "$1" > "$tmp/out" 2>&1; }
USER_SRC=data/systemd-user
# fixture NAME: a copy of the files the check reads, in $tmp/NAME.
fixture() {
    local d=$tmp/$1
    mkdir -p "$d/packaging" "$d/$USER_SRC" "$d/crates/custodio-cli/src"
    cp "$ROOT/packaging/nfpm.yaml" "$d/packaging/"
    cp "$ROOT/$USER_SRC"/* "$d/$USER_SRC/"
    cp "$ROOT/crates/custodio-cli/src/register_native.rs" "$d/crates/custodio-cli/src/"
}
# control NAME WORD... -- : the fixture NAME (edited by the caller) must fail, naming every WORD.
control() {
    local name=$1 words=() word
    shift
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do words+=("$1"); shift; done
    if check "$tmp/$name"; then bad "$name: the check passed"; return; fi
    for word in "${words[@]}"; do
        grep -qF -- "$word" "$tmp/out" || bad "$name: output lacks '$word': $(cat "$tmp/out")"
    done
}

check "$ROOT" || bad "the source tree fails: $(cat "$tmp/out")"

# --- negative controls ---
fixture bogus
sed -i 's/^NoNewPrivileges=yes/&\nBogus=1/' "$tmp/bogus/$USER_SRC/custodio-refresh.service"
# The shipped text is the one with Bogus=1, so the copy matches it and only the output rule can catch the fault.
control bogus "exited 0 but printed output" "Bogus"
grep -q "differs from the shipped" "$tmp/out" && bad "bogus: the copy check fired; the control does not test the output rule"

fixture nowrite
sed -i 's/^NoNewPrivileges=yes/&\nProtectSystem=strict\nReadWritePaths=%h\/snap\/firefox\/common/' "$tmp/nowrite/$USER_SRC/custodio-refresh.service"
check "$tmp/nowrite" || bad "nowrite: the hardened unit with its writable path fails: $(cat "$tmp/out")"
sed -i '/^ReadWritePaths=/d' "$tmp/nowrite/$USER_SRC/custodio-refresh.service"
control nowrite "hardening" "ProtectSystem" "%h/snap/firefox/common"
fixture nowrite-tmpfs
sed -i 's/^NoNewPrivileges=yes/&\nTemporaryFileSystem=\/home/' "$tmp/nowrite-tmpfs/$USER_SRC/custodio-refresh.service"
control nowrite-tmpfs "hardening" "TemporaryFileSystem"

fixture nologin
sed -i 's/^WantedBy=default.target/WantedBy=graphical-session.target/' "$tmp/nologin/$USER_SRC/custodio-refresh.service"
control nologin "login trigger"

fixture nochange
sed -i 's/^PathChanged=.*/PathChanged=\/usr\/lib\/custodio\/other.so/' "$tmp/nochange/$USER_SRC/custodio-refresh.path"
control nochange "change trigger" "/usr/lib/custodio/libcustodio_pkcs11.so"

fixture nobinary
sed -i 's|^ExecStart=/usr/bin/custodio|ExecStart=/usr/local/bin/custodio|' "$tmp/nobinary/$USER_SRC/custodio-refresh.service"
control nobinary "ExecStart" "/usr/bin/custodio"

# Not enabled: a link is gone, a link points nowhere, a unit has no [Install] section, the link is limited to one format.
fixture nolink
python3 -I - "$tmp/nolink/packaging/nfpm.yaml" default.target.wants << 'PY'
import sys, yaml
p, key = sys.argv[1:]
cfg = yaml.safe_load(open(p))
cfg["contents"] = [c for c in cfg["contents"] if key not in c["dst"]]
yaml.safe_dump(cfg, open(p, "w"))
PY
control nolink "not enabled for every user" "default.target.wants/custodio-refresh.service"
fixture deadlink
sed -i 's|src: ../custodio-refresh.path|src: ../custodio-gone.path|' "$tmp/deadlink/packaging/nfpm.yaml"
control deadlink "which the package does not ship" "custodio-gone.path"
fixture noinstall
sed -i '/^\[Install\]/,$d' "$tmp/noinstall/$USER_SRC/custodio-refresh.path"
control noinstall "no [Install] section"
fixture onefmt
sed -i 's|^\(  - src: ../custodio-refresh.path\)|\1\n    packager: deb|' "$tmp/onefmt/packaging/nfpm.yaml"
control onefmt "limited to packager deb"

# A service that does not run the refresh mode is caught by the run below; the control edits the argument list of a copy.
fixture noargs
sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/custodio register|' "$tmp/noargs/$USER_SRC/custodio-refresh.service"

# --- the run: the service's command line against the debug CLI ---
exec_line=$(python3 -I -B "$CHECK" "$ROOT" --exec-line)
# run_line LINE HOME: runs the ExecStart line with the binary swapped for the debug CLI and the module for a fixture.
run_line() {
    local line=$1 home=$2 words
    read -ra words <<< "$line"
    [ "${words[0]}" = /usr/bin/custodio ] || { echo "the ExecStart binary is ${words[0]}" >&2; return 1; }
    [ "${words[*]:1}" = "register --refresh-only" ] || { echo "the ExecStart arguments are '${words[*]:1}', not 'register --refresh-only'" >&2; return 1; }
    HOME=$home "$CLI" "${words[@]:1}" --module "$tmp/module.so" > "$tmp/run.out" 2> "$tmp/cli.err"
}
printf 'the new module' > "$tmp/module.so"
home=$tmp/home
mkdir -p "$home/snap/firefox/common/old"
copy=$home/snap/firefox/common/libcustodio_pkcs11.so
printf 'a stale copy' > "$copy"
run_line "$exec_line" "$home" 2> "$tmp/run.err" || bad "the service's command failed: $(cat "$tmp/run.err")"
cmp -s "$copy" "$tmp/module.so" || bad "the stale copy was not replaced by the module"
grep -q "refreshed" "$tmp/run.out" || bad "the outcome line does not say the copy was refreshed: $(cat "$tmp/run.out")"
# /run/systemd/journal/socket does not exist in the container, so the journal outcome is read from stderr.
if [ -S /run/systemd/journal/socket ]; then :; else
    grep -q "cannot write to the journal at /run/systemd/journal/socket" "$tmp/cli.err" || bad "stderr lacks the journal message: $(cat "$tmp/cli.err")"
fi
# The control: a service without --refresh-only fails the argument check.
noargs_line=$(python3 -I -B "$CHECK" "$tmp/noargs" --exec-line)
if run_line "$noargs_line" "$home" 2> "$tmp/noargs.err"; then bad "noargs: a service that does not run the refresh mode passed"; fi
grep -qF "not 'register --refresh-only'" "$tmp/noargs.err" || bad "noargs: the message does not name the arguments: $(cat "$tmp/noargs.err")"
exit "$fail"
