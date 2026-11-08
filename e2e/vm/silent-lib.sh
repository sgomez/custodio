# shellcheck shell=bash
# Sourced by e2e/vm/silent.sh (the vm-silent-* cases, F161, acceptance 11 of SPEC.md) and by scripts/test-e2e-vm-silent.sh, which runs it with stubs and on fixtures.
# How the library is hidden: systemd loads libtss2-rc (dlopen) for TPM work: `systemd-analyze has-tpm2` is "partial" without it and `systemd-creds` cannot seal. The package stays installed; each
# file of libtss2-rc0* that is a library (libtss2-rc.so.0*) is moved aside with `dpkg-divert --local --rename`, which dpkg knows and can undo exactly. What loads it is then restarted:
# `systemctl daemon-reexec` (PID 1 drops what it loaded) and the service (its credential calls start fresh `systemd-creds` processes). Restoring is the reverse.
# Overridable for the self-test: VS_LIBS (the library paths, one word each), VS_E2E (where tpmfail.py and vm/ are).
VS_E2E=${VS_E2E:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}

# vs_libs: the library files (real files and links) of the libtss2-rc package, one per line
vs_libs() {
    # shellcheck disable=SC2086 # one path per word
    if [ -n "${VS_LIBS:-}" ]; then printf "%s\n" ${VS_LIBS}; return; fi
    local pkg f
    pkg=$(dpkg-query -W -f='${Package}\n' 'libtss2-rc0*' 2> /dev/null | head -n 1)
    [ -n "$pkg" ] || return 1
    dpkg -L "$pkg" | while IFS= read -r f; do
        case $f in */libtss2-rc.so.*) if [ -e "$f" ] || [ -L "$f" ]; then echo "$f"; fi ;; esac
    done
}

# vs_wait_ready OLDPID: the service has a new MainPID, is active and answers Ping
vs_wait_ready() {
    local old=$1 p=''
    for _ in $(seq 150); do
        p=$(systemctl show -p MainPID --value custodio)
        if [ "$p" != 0 ] && [ "$p" != "$old" ] && [ "$(systemctl show -p ActiveState --value custodio)" = active ] \
            && busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    echo "vm-silent: the service did not come back (old pid $old, now $p)" >&2
    return 1
}

# vs_restart: what loads the library starts over
vs_restart() {
    local old
    old=$(systemctl show -p MainPID --value custodio)
    ldconfig || return 1
    systemctl daemon-reexec || return 1
    systemctl restart custodio || return 1
    vs_wait_ready "$old"
}

vs_hide() {
    local f libs
    libs=$(vs_libs) && [ -n "$libs" ] || { echo "vm-silent: no libtss2-rc library found to hide" >&2; return 1; }
    while IFS= read -r f; do
        dpkg-divert --local --rename --divert "$f.hidden-by-e2e" --add "$f" > /dev/null || return 1
    done <<< "$libs"
    vs_restart
}

# vs_libs_all: our diversions that are in place (the package's paths are not found once diverted, so ask dpkg for the diversions)
vs_libs_all() {
    dpkg-divert --list '*libtss2-rc.so.*' 2> /dev/null | sed -n 's/^local diversion of \(.*\) to .*\.hidden-by-e2e$/\1/p'
}

vs_restore() {
    local f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        dpkg-divert --local --rename --remove "$f" > /dev/null || return 1
    done < <(vs_libs_all)
    vs_restart
}

# vs_restore_ok: prints the problems with the restore (empty: the libraries are back, no diversion is left, has-tpm2 says yes)
vs_restore_ok() {
    local f out rc=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then echo "the library $f is not back"; fi
    done < <(vs_libs)
    f=$(vs_libs_all | tr '\n' ' ')
    [ -z "${f// /}" ] || echo "a diversion is left: $f"
    out=$(systemd-analyze has-tpm2 2> /dev/null) || rc=$?
    if [ "$out" != yes ] || [ "$rc" != 0 ]; then echo "systemd-analyze has-tpm2 says '$out' (exit $rc) after the restore"; fi
}

# vs_install_trap: whatever way the shell ends (success, a failed judge, a signal), the library is put back and its users restarted; a restore that fails fails the run
vs_install_trap() {
    trap 'vs_on_exit' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
}
vs_on_exit() {
    local rc=$? p
    trap - EXIT
    if [ -n "$(vs_libs_all)" ] || [ "${VS_ALWAYS_RESTORE:-}" = 1 ]; then
        vs_restore || { echo "vm-silent: FAIL: the library could not be put back" >&2; [ "$rc" -ne 0 ] || rc=1; }
    fi
    p=$(vs_restore_ok)
    [ -z "$p" ] || { echo "vm-silent: FAIL: after the restore: $p" >&2; [ "$rc" -ne 0 ] || rc=1; }
    exit "$rc"
}

# vs_problems CASE DIR ID: the problems of one case. DIR/hidden holds the evidence of the import while the library was hidden (has2.out, has2.rc, import.out, import.rc, state-before,
# state-after, list.out, cli-list.out, journal.json); DIR/restored the one after the restore (has2.out, has2.rc, import.out, list.out, reader.out, reader.rc, restore.problems).
vs_problems() {
    local c=$1 id=$3 h=$2/hidden r=$2/restored
    # a judge that cannot run (a missing evidence file) is a problem, not an empty answer
    tf() { local o; o=$(python3 -I "$VS_E2E/tpmfail.py" "$@" 2>&1) || o="the judge tpmfail.py $1 failed: $o"; printf '%s\n' "$o"; }
    sl() { local o; o=$(python3 -I "$VS_E2E/vm/silent.py" "$@" 2>&1) || o="the judge silent.py $1 failed: $o"; printf '%s\n' "$o"; }
    case $c in
    vm-silent-import-fails)
        sl hiding "$h/has2.out" "$h/has2.rc"
        tf failed "$h/import.out" "$h/import.rc" CredentialsUnavailable
        ;;
    vm-silent-journal-cause) tf journal "$h/journal.json" "$id" binding_mismatch e2e-password ;;
    vm-silent-nothing-stored) tf nothing "$h/state-before" "$h/state-after" "$h/list.out" "$id" ;;
    vm-silent-no-key)
        sl absent "$h/list.out" "$h/cli-list.out" "$id"
        tf noweaker "$h/import.out" "$h/list.out" "$h/journal.json" "$id"
        ;;
    vm-silent-restored-imports)
        sl restored "$r/has2.out" "$r/has2.rc"
        tf kind "$r/import.out" "$r/list.out" "$id" encrypted-tpm
        sl reader "$r/reader.out" "$r/reader.rc"
        cat "$r/restore.problems" 2> /dev/null || echo "$r/restore.problems is missing"
        ;;
    *) echo "vs_problems: unknown case $c" ;;
    esac | sed '/^$/d'
}
