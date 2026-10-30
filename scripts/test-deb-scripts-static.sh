#!/usr/bin/env bash
# Static gates on the four maintainer scripts of the .deb (F43), read as text: no script names the state directory outside the notice, none
# changes the bus policy, the polkit action or the unit, none removes the account or deletes recursively, and all four are plain
# executable sh with set -e. The runs are in scripts/test-deb-lifecycle.sh; the stubs there fail the test on any call with a state path.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC=$ROOT/packaging/deb
BF_DIR=$(mktemp -d)
trap 'rm -rf "$BF_DIR"' EXIT
fail=0
bad() { echo "test-deb-scripts-static: $*" >&2; fail=1; }

# ---- the gates ----
code() { grep -Ev '^[[:space:]]*(#|$)' "$ROOT/packaging/deb/$1"; }
SCRIPTS=(preinst postinst prerm postrm)

# Every line that names the state directory is on this list, with the file, the exact text and the reason (a pattern would hide a new use).
ALLOW_STATE=(
    'postrm|        echo "custodio: the signing keys are still on disk in /var/lib/custodio (the real directory is /var/lib/private/custodio)."|the notice names where the keys are; it prints a path and never opens it'
)
for f in "${SCRIPTS[@]}"; do
    while IFS= read -r line; do
        found=0
        for entry in "${ALLOW_STATE[@]}"; do
            IFS='|' read -r a_file a_text a_why <<< "$entry"
            if [ "$a_file" = "$f" ] && [ "$a_text" = "$line" ] && [ -n "$a_why" ]; then found=1; fi
        done
        [ "$found" = 1 ] || bad "$f names the state directory in a line that is not on the allowlist: $line"
    done < <(grep -E '/var/lib|StateDirectory|STATE_DIRECTORY' "$ROOT/packaging/deb/$f" | grep -Ev '^[[:space:]]*#' || true)
done
for entry in "${ALLOW_STATE[@]}"; do
    IFS='|' read -r a_file a_text _ <<< "$entry"
    grep -qxF "$a_text" "$ROOT/packaging/deb/$a_file" || bad "the allowlist entry for $a_file matches no line: $a_text"
done
# Nothing in the scripts changes the bus policy, the polkit action or the unit, and no script removes the account or deletes recursively.
for f in "${SCRIPTS[@]}"; do
    if code "$f" | grep -E 'dbus-1|polkit-1|/lib/systemd|/etc/|custodio\.service\.d|systemctl +(edit|set-property|mask|enable|preset|start)|deb-systemd-helper|userdel|deluser|groupdel|rm +-[a-zA-Z]*r|chown|chmod|chgrp|sed +-i|\btee\b|\bcp\b|\bmv\b|\binstall +-' | grep -v 'bus-check' > "$BF_DIR/hits"; then
        # The embedded F42 check is the same text in all three formats; it holds none of these, so any hit is new.
        bad "$f has a forbidden command or path: $(cat "$BF_DIR/hits")"
    fi
done
# The marker path is the same in the three scripts that use it.
for f in preinst postinst postrm; do
    grep -q '/run/custodio-restart-after-upgrade' "$ROOT/packaging/deb/$f" || bad "$f does not use the marker path"
done
# The notice is the only output of postrm; preinst and postinst print only on error.
[ "$(grep -c 'echo\|printf' "$SRC/postrm")" -eq 3 ] || bad "postrm prints other than the three lines of the notice"
for f in "${SCRIPTS[@]}"; do
    head -n 1 "$SRC/$f" | grep -qx '#!/bin/sh' || bad "$f does not start with #!/bin/sh"
    [ -x "$SRC/$f" ] || bad "$f is not executable"
    grep -q '^set -e$' "$SRC/$f" || bad "$f lacks set -e"
done


exit "$fail"
