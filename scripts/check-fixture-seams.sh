#!/usr/bin/env bash
# The gate of F197: the fixture seam of custodio-cli (the `fixture-root` cargo feature, which points `custodio fingerprint` at a fixture
# root and lets a test override the uid and inject a failure) never ships. Argument: a binary, or the root of a tree (default: this repository).
#   - a binary fails if it holds the name of any variable the seam reads (CUSTODIO_FIXTURE_ROOT, CUSTODIO_FIXTURE_EUID, CUSTODIO_FIXTURE_FAIL);
#   - a tree fails if a file of data/ or packaging/ names the feature or one of the variables, if a Cargo.toml of the workspace turns the
#     feature on outside [dev-dependencies] and its own definition `fixture-root = []` (a normal or build dependency with features = [...],
#     another feature that enables it, a `default = [...]` list that has it).
# Prints one line per fault on standard error. Exit 0 when clean.
set -euo pipefail

TARGET=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
FEATURE=fixture-root
VARS=(CUSTODIO_FIXTURE_ROOT CUSTODIO_FIXTURE_EUID CUSTODIO_FIXTURE_FAIL)
fail=0
bad() { echo "check-fixture-seams: $*" >&2; fail=1; }

if [ -f "$TARGET" ]; then
    for v in "${VARS[@]}"; do
        if grep -aqF -- "$v" "$TARGET"; then bad "$TARGET holds $v: the fixture seam is in the binary"; fi
    done
    exit "$fail"
fi
[ -d "$TARGET/data" ] && [ -d "$TARGET/packaging" ] || { bad "$TARGET is not a binary and has no data/ or packaging/"; exit 1; }

pattern=$(printf -- '-e %s ' "$FEATURE" "${VARS[@]}")
# shellcheck disable=SC2086 # the words of $pattern are separate grep options
shipped=$(grep -rIl $pattern "$TARGET/data" "$TARGET/packaging" 2> /dev/null || true)
for f in $shipped; do bad "$f names the fixture seam: it must not ship"; done

manifests=$(find "$TARGET" -name Cargo.toml -not -path '*/target/*' -not -path '*/.git/*')
for f in $manifests; do
    hits=$(awk -v feat="$FEATURE" '
        /^[[:space:]]*\[/ { sec = $0; gsub(/[[:space:]]/, "", sec) }
        /^[[:space:]]*#/ { next }
        index($0, feat) {
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
