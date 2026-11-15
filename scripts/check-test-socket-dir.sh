#!/usr/bin/env bash
# The gate of `just test-socket-dir` (F178): the Cargo feature `test-socket-dir` of custodio-pkcs11, which lets a test replace `/run` as the base of
# the snap socket directory, cannot reach a shipped build. Static, no cargo call. It is not proven by a release build of the cdylib (see
# contracts/F178.md). Every manifest of the workspace (the root one and crates/*/Cargo.toml) is scanned.
#   - the feature is defined in custodio-pkcs11 and is not in its `default` list;
#   - the feature name appears in a manifest only on that definition, and in custodio-it under a `[dev-dependencies]` section (in any other
#     section, `features = [...]` on a dependency entry included, or in another crate's `[features]`, it fails);
#   - no justfile, workflow, packaging file or script names the feature or uses `--all-features`;
#   - the override variable CUSTODIO_TEST_SOCKET_BASE_DIR is in no .rs file besides the module and the tests of custodio-it;
#   - the module is declared, and used, only behind `#[cfg(feature = "test-socket-dir")]` (or `#![cfg(...)]` inside the file).
# Argument: the root of the tree to check (default: this repository), so the test can check altered copies.
set -euo pipefail

ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
FEATURE=test-socket-dir
VAR=CUSTODIO_TEST_SOCKET_BASE_DIR
PKCS11=$ROOT/crates/custodio-pkcs11
MODULE=$PKCS11/src/backend/test_dir.rs
fail=0
bad() { echo "check-test-socket-dir: $*" >&2; fail=1; }

[ -f "$PKCS11/Cargo.toml" ] || { bad "$PKCS11/Cargo.toml does not exist"; exit 1; }
[ -f "$MODULE" ] || { bad "$MODULE does not exist"; exit 1; }

# ---- the definition, and not in default
grep -Eq "^${FEATURE}[[:space:]]*=[[:space:]]*\[\]" "$PKCS11/Cargo.toml" || bad "custodio-pkcs11 does not define the feature $FEATURE as an empty list"
if grep -E '^default[[:space:]]*=' "$PKCS11/Cargo.toml" | grep -q "$FEATURE"; then bad "the feature $FEATURE is in default"; fi

# ---- every manifest: the section of each line that names the feature
for manifest in "$ROOT/Cargo.toml" "$ROOT"/crates/*/Cargo.toml; do
    [ -f "$manifest" ] || continue
    crate=$(basename "$(dirname "$manifest")")
    hits=$(awk -v f="$FEATURE" '
        /^[[:space:]]*\[/ { section = $0; gsub(/[[:space:]]/, "", section); next }
        /^[[:space:]]*#/ { next }
        index($0, f) { line = $0; sub(/^[[:space:]]+/, "", line); print section "\t" line }
    ' "$manifest")
    [ -n "$hits" ] || continue
    while IFS=$'\t' read -r section line; do
        case "$crate|$section" in
            custodio-pkcs11\|\[features\]) [[ "$line" == "$FEATURE"* ]] || bad "$manifest: $FEATURE named in [features] other than on its definition: $line" ;;
            custodio-it\|\[dev-dependencies\]|custodio-it\|\[dev-dependencies.*) ;;
            *) bad "$manifest: $FEATURE named under $section (only custodio-it's [dev-dependencies] may): $line" ;;
        esac
    done <<< "$hits"
done

# ---- recipes, workflows, packaging, scripts
# The gate's own file names contain the feature name; a line that only names them is fine.
others=$(grep -rIn --exclude-dir=.git --exclude-dir=target --exclude-dir=node_modules --exclude-dir=crates \
    --exclude='check-test-socket-dir.sh' --exclude='test-check-test-socket-dir.sh' -e "$FEATURE" -e '--all-features' \
    "$ROOT/justfile" "$ROOT/.github" "$ROOT/packaging" "$ROOT/scripts" "$ROOT/e2e" "$ROOT/data" 2>/dev/null \
    | grep -v -e 'check-test-socket-dir\.sh' || true)
[ -z "$others" ] || bad "a recipe, workflow, packaging file or script names $FEATURE or --all-features: $others"

# ---- the variable, and the cfg on the module
users=$(grep -rl --include='*.rs' "$VAR" "$ROOT/crates" 2>/dev/null | grep -v -e "^$MODULE\$" -e "^$ROOT/crates/custodio-it/tests/" -e '/target/' || true)
[ -z "$users" ] || bad "$VAR is read outside the gated module: $users"
grep -q "\"$FEATURE\"" "$MODULE" 2>/dev/null && first=$(grep -m1 -v -e '^//' -e '^$' "$MODULE") || first=
gated_inside=0
[[ "$first" == '#![cfg(feature = "'$FEATURE'")]' ]] && gated_inside=1
if [ "$gated_inside" != 1 ]; then
    uses=$(grep -rn --include='*.rs' -E '\btest_dir\b' "$PKCS11/src" | grep -v "^$MODULE:" || true)
    [ -n "$uses" ] || bad "nothing declares the module test_dir"
    while IFS=: read -r file lineno _; do
        [ -n "$file" ] || continue
        prev=$(sed -n "$((lineno - 1))p" "$file")
        grep -Fq "#[cfg(feature = \"$FEATURE\")]" <<< "$prev" || bad "$file:$lineno: test_dir is not directly behind #[cfg(feature = \"$FEATURE\")]"
    done <<< "$uses"
fi
exit "$fail"
