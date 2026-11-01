#!/usr/bin/env bash
# Lists the tracked shell scripts for shellcheck: every `*.sh` file and every file whose first line is a
# sh, bash or dash shebang, so maintainer scripts are covered whatever their names.
set -euo pipefail
shebang='^#![[:space:]]*(/usr)?/bin/(env[[:space:]]+)?(-S[[:space:]]+)?(ba|da)?sh([[:space:]]|$)'
git ls-files -z | while IFS= read -r -d '' f; do
    if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi
    case $f in
    *.sh) printf '%s\n' "$f" ;;
    *)
        if head -n1 -- "$f" | LC_ALL=C grep -qaE "$shebang"; then printf '%s\n' "$f"; fi
        ;;
    esac
done
