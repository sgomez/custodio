#!/usr/bin/env bash
# Fails on any tracked file over MAX_TOKENS (bytes / 4) and on any Rust file with an inline
# `#[cfg(test)] mod … { … }`: tests live in their own file, so they never count against the code.
set -euo pipefail

MAX_TOKENS=5000

# Not code: lockfiles, the license, vendored skills and docs.
EXCLUDE_PATTERNS=(
  "Cargo.lock"
  "*/Cargo.lock"
  "package-lock.json"
  "skills-lock.json"
  "LICENSE"
  ".agents/skills/*"
  ".claude/skills/*"
  "docs/*"
  "*.md"
)

excluded() {
  local pattern
  for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    # shellcheck disable=SC2254
    case "$1" in $pattern) return 0 ;; esac
  done
  return 1
}

# The line of the first `#[cfg(test)]` followed by an inline module, or nothing.
inline_tests() {
  awk '
    /^[[:space:]]*#\[cfg\(test\)\]/ { pending = NR; next }
    pending && /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+[A-Za-z_0-9]+[[:space:]]*\{/ { print pending; exit }
    pending && !/^[[:space:]]*(#\[|\/\/|$)/ { pending = 0 }
  ' "$1"
}

over=()
inline=()
while IFS= read -r file; do
  if [ ! -f "$file" ] || [ -L "$file" ] || excluded "$file"; then continue; fi
  if file --mime-encoding "$file" | grep -q binary; then continue; fi
  tokens=$(($(wc -c <"$file") / 4))
  if [ "$tokens" -gt "$MAX_TOKENS" ]; then over+=("  $file (~$tokens tokens)"); fi
  if [[ "$file" == *.rs ]] && line=$(inline_tests "$file") && [ -n "$line" ]; then
    inline+=("  $file:$line")
  fi
done < <(git ls-files)

status=0
if [ ${#over[@]} -gt 0 ]; then
  status=1
  cat >&2 <<EOF
These files exceed ${MAX_TOKENS} tokens (bytes / 4):

$(printf '%s\n' "${over[@]}")

Split each into smaller modules by responsibility, re-exporting with pub use so callers
do not change.
EOF
fi
if [ ${#inline[@]} -gt 0 ]; then
  status=1
  cat >&2 <<EOF
These files have inline test modules:

$(printf '%s\n' "${inline[@]}")

Move them to src/foo/tests.rs behind "#[cfg(test)] mod tests;".
EOF
fi
exit "$status"
