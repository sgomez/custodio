#!/usr/bin/env bash
# F61: the relabeling of the key files that a service in init_t wrote as init_var_lib_t. The mechanism is the tmpfiles.d line of data/tmpfiles.d/custodio.conf
# (systemd-tmpfiles restores the SELinux label of the state directory at every boot, so also on rpm-ostree, where no scriptlet touches /var at deploy time).
# Checked here: the line is exactly one `Z` line on the state directory with `-` for mode, owner and group (a static check, with a control for each
# way to make it wider); the real systemd-tmpfiles on a fixture root changes no owner, mode, content or time, and does not create an absent directory
# or touch a path outside; no maintainer script or hook runs restorecon, chcon or systemd-tmpfiles (the install cannot fail on it, and nothing runs
# outside the state directory). NOT checked here: the label itself; there is no SELinux in the dev container (SPEC "Limits"), see docs/manual-acceptance.md.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-relabel: $*" >&2; fail=1; }
CONF=$ROOT/data/tmpfiles.d/custodio.conf
STATE=/var/lib/private/custodio

# conf_problems FILE: prints one message per problem
# shellcheck disable=SC2317 # called through accepts and rejects
conf_problems() {
    local f=$1 lines n
    lines=$(grep -v '^[[:space:]]*\(#\|$\)' "$f" || true)
    n=$(grep -c . <<< "$lines" || true)
    [ "$n" -eq 1 ] || { echo "the file has $n active lines, expected exactly one"; return 1; }
    [ "$lines" = "Z $STATE - - -" ] || { echo "the line is '$lines', expected 'Z $STATE - - -'"; return 1; }
}
accepts() { local what=$1 out; shift; out=$("$@" 2>&1) || bad "$what: rejected: $out"; }
rejects() { # WHAT WORD CMD...
    local what=$1 word=$2 out
    shift 2
    if out=$("$@" 2>&1); then bad "$what: accepted"; return; fi
    grep -q -- "$word" <<< "$out" || bad "$what: rejected without '$word': $out"
}
accepts "the shipped file" conf_problems "$CONF"
variant() { # NAME LINE...
    local name=$1
    shift
    printf '%s\n' "$@" > "$tmp/$name.conf"
}
variant mode "Z $STATE 0755 - -"; rejects "a mode" 'expected' conf_problems "$tmp/mode.conf"
variant owner "Z $STATE - root -"; rejects "an owner" 'expected' conf_problems "$tmp/owner.conf"
variant group "Z $STATE - - root"; rejects "a group" 'expected' conf_problems "$tmp/group.conf"
variant create "d $STATE - - -"; rejects "a line that creates the directory" 'expected' conf_problems "$tmp/create.conf"
variant remove "R $STATE - - -"; rejects "a line that removes it" 'expected' conf_problems "$tmp/remove.conf"
variant wide "Z /var/lib - - -"; rejects "a wider path" 'expected' conf_problems "$tmp/wide.conf"
variant link "Z /var/lib/custodio - - -"; rejects "the symlink path" 'expected' conf_problems "$tmp/link.conf"
variant age "Z $STATE - - - 1d"; rejects "an age" 'expected' conf_problems "$tmp/age.conf"
variant two "Z $STATE - - -" "Z /etc - - -"; rejects "a second line" 'active lines' conf_problems "$tmp/two.conf"
variant none "# nothing"; rejects "no line" 'active lines' conf_problems "$tmp/none.conf"

# The real tool on a fixture root.
if command -v systemd-tmpfiles > /dev/null; then
    root=$tmp/root
    mkdir -p "$root$STATE" "$root/var/lib/other" "$root/etc"
    printf 'secret key bytes\n' > "$root$STATE/key1.p12"
    printf 'other\n' > "$root/var/lib/other/file"
    chmod 0700 "$root$STATE"
    chmod 0640 "$root$STATE/key1.p12"
    touch -d '2020-01-01 00:00:00' "$root$STATE/key1.p12" "$root/var/lib/other/file"
    snap() { (cd "$root" && find . -mindepth 1 -printf '%p %y %m %U:%G %T@ %s\n' | LC_ALL=C sort; find . -type f -exec sha256sum {} + | LC_ALL=C sort); }
    before=$(snap)
    systemd-tmpfiles --create --root="$root" "$CONF" > "$tmp/run.out" 2>&1 || bad "systemd-tmpfiles failed: $(cat "$tmp/run.out")"
    [ "$(snap)" = "$before" ] || bad "systemd-tmpfiles changed owner, mode, content, size, time or the tree:"$'\n'"$(diff <(echo "$before") <(snap) || true)"
    if grep -q 'secret\|key1' "$tmp/run.out"; then bad "the run printed a key file name or content"; fi
    # the directory is absent: nothing is created
    rm -rf "$root$STATE"
    before=$(snap)
    systemd-tmpfiles --create --root="$root" "$CONF" > "$tmp/run.out" 2>&1 || bad "systemd-tmpfiles failed on an absent directory: $(cat "$tmp/run.out")"
    [ "$(snap)" = "$before" ] || bad "an absent state directory was created or something else changed"
    [ ! -e "$root$STATE" ] || bad "the state directory was created"
    # control: a line with a mode does change the mode, so the comparison above can see a change
    mkdir -p "$root$STATE"
    chmod 0700 "$root$STATE"
    variant wide2 "Z $STATE 0755 - -"
    before=$(snap)
    systemd-tmpfiles --create --root="$root" "$tmp/wide2.conf" > /dev/null 2>&1 || true
    [ "$(snap)" != "$before" ] || bad "control: a line with a mode changed nothing, so the comparison cannot see a change"
else
    echo "test-relabel: systemd-tmpfiles is not installed; the run on a fixture root is skipped" >&2
fi

# No maintainer script, scriptlet or hook runs a labelling tool: the install cannot fail on it and nothing is relabelled outside the state directory.
# shellcheck disable=SC2317 # called through accepts and rejects
scripts_problems() { # FILE...: lines that call restorecon, chcon, semanage or systemd-tmpfiles
    local f hits=0
    for f in "$@"; do
        if grep -nE '(^|[^[:alnum:]_-])(restorecon|chcon|semanage|setfiles|systemd-tmpfiles)([^[:alnum:]_-]|$)' "$f" | grep -v '^[0-9]*:[[:space:]]*#' ; then hits=1; fi
    done
    [ "$hits" -eq 0 ] || { echo "a script labels files"; return 1; }
}
files=$(find "$ROOT/packaging/deb" "$ROOT/packaging/rpm" "$ROOT/packaging/arch" -type f)
# shellcheck disable=SC2086 # the file names have no spaces
accepts "the packaging scripts" scripts_problems $files
printf '#!/bin/sh\nrestorecon -R /var/lib\n' > "$tmp/bad1"
rejects "a script with restorecon" 'labels files' scripts_problems "$tmp/bad1"
printf '#!/bin/sh\nsystemd-tmpfiles --create || true\n' > "$tmp/bad2"
rejects "a script with systemd-tmpfiles" 'labels files' scripts_problems "$tmp/bad2"
exit "$fail"
