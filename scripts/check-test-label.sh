#!/usr/bin/env bash
# The gate of F175 (acceptance 15): the test-only source of peer credentials (the `test-seam` feature of custodiod, which lets a test
# supply the label, uid and pidfd of a connection instead of the kernel's) is never enabled in what ships. Enabling means:
#   - the feature's name anywhere in a file of data/ or packaging/ (unit files, nfpm.yaml, packaging scripts, Environment=, --features);
#   - in a Cargo.toml of the workspace, outside [dev-dependencies] and the feature's own definition `test-seam = []`: a normal or build
#     dependency with features = [...] naming it, another feature that turns it on, or a `default = [...]` list that has it.
# Prints nothing on success and one line per enabling occurrence on failure. Argument: the root of the tree to check (default: this repository),
# so the test can check altered copies.
set -euo pipefail

ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
FEATURE=test-seam
fail=0
bad() { echo "check-test-label: $*" >&2; fail=1; }

[ -d "$ROOT/data" ] && [ -d "$ROOT/packaging" ] || { bad "$ROOT has no data/ or packaging/"; exit 1; }

# ---- shipped files
shipped=$(grep -rIl -e "$FEATURE" "$ROOT/data" "$ROOT/packaging" 2> /dev/null || true)
for f in $shipped; do bad "$f names the test-only source ($FEATURE): it must not ship"; done

# ---- Cargo manifests
manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/.git/*')
for f in $manifests; do
    # The fuzz crate of custodiod is built only by cargo-fuzz (debug assertions on, so the release `compile_error!` holds), and ships
    # nothing; it may name the feature on its one dependency line.
    allow=
    case "$f" in */crates/custodiod/fuzz/Cargo.toml) allow='custodiod = { path = "..", features = ["test-seam"] }' ;; esac
    # Lines naming the feature that are not comments, not the definition, and not in a dev-dependencies section.
    hits=$(awk -v feat="$FEATURE" -v allow="$allow" '
        /^[[:space:]]*\[/ { sec = $0; gsub(/[[:space:]]/, "", sec) }
        /^[[:space:]]*#/ { next }
        allow != "" && $0 == allow { next }
        index($0, "\"" feat "\"") || index($0, feat) {
            line = $0; gsub(/[[:space:]]/, "", line)
            if (line == feat "=[]" && sec == "[features]") next
            if (sec == "[dev-dependencies]" || sec ~ /^\[target\..*\.dev-dependencies\]$/ || sec ~ /^\[dev-dependencies\./) next
            print FNR ": " $0
        }' "$f")
    if [ -n "$hits" ]; then
        bad "$f enables $FEATURE outside [dev-dependencies] (a normal or build dependency, another feature, or the default features): $hits"
    fi
done
exit "$fail"
