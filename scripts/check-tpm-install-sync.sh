#!/usr/bin/env bash
# Fails unless harness/Containerfile and every job of ci.yml and mutants.yml that builds or tests the workspace install the TPM
# packages (F104), each install preceded by a comment that mentions the TPM. Usage: check-tpm-install-sync.sh [ROOT]
# ROOT holds harness/Containerfile and .github/workflows/ (default: this repository).
set -euo pipefail
ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
# libtss2-dev is what tss-esapi builds against; the others give the software TPM and its tools.
PACKAGES=(swtpm swtpm-tools tpm2-tools libtss2-dev)
# Jobs that never compile, by workflow file: job id. Every other job must install the packages.
EXEMPT=(
    "ci.yml:commits"  # commitlint only (node)
    "ci.yml:ci"       # aggregator of the other jobs' results
    "mutants.yml:report" # files a GitHub issue from the artifacts
)
fail=0
bad() { echo "check-tpm-install-sync: $*" >&2; fail=1; }

# block_ok TEXT: prints what is wrong with the TPM install in TEXT, one item per line (nothing when it is right). The TPM install is
# every apt install statement (backslash continuations joined) that names one of the packages; together they must name all of them,
# and the first must follow a comment block that mentions the TPM.
block_ok() {
    local text=$1 p out
    out=$(awk '
        function flush() {
            if (stmt ~ /apt(-get)? .*install/ && stmt ~ /(swtpm|tpm2-tools|libtss2-dev)/) { all = all " " stmt; if (!n++) ok = above }
            stmt = ""
        }
        /^[[:space:]]*#/ { if (!pc) blk = 0; if (tolower($0) ~ /tpm/) blk = 1; pc = 1; next }
        { if (stmt == "") above = pc ? blk : 0; pc = 0 }
        { line = $0; cont = (line ~ /\\[[:space:]]*$/); sub(/\\[[:space:]]*$/, "", line); stmt = stmt " " line; if (!cont) flush() }
        END { flush(); print (n ? "FOUND" : "NOINSTALL"); print (ok ? "COMMENT" : "NOCOMMENT"); print all }
    ' <<< "$text")
    local found comment all
    found=$(sed -n 1p <<< "$out") comment=$(sed -n 2p <<< "$out") all=$(sed -n '3,$p' <<< "$out")
    if [ "$found" = NOINSTALL ]; then echo NOINSTALL; return; fi
    for p in "${PACKAGES[@]}"; do
        grep -Eq "(^|[[:space:]])$p([[:space:]]|$)" <<< "$all" || echo "$p"
    done
    [ "$comment" = COMMENT ] || echo NOCOMMENT
}

report() { # LABEL RESULT
    local r
    while IFS= read -r r; do
        [ -n "$r" ] || continue
        case $r in
        NOINSTALL) bad "$1: no apt install of the TPM packages" ;;
        NOCOMMENT) bad "$1: the install has no comment above it that mentions the TPM" ;;
        *) bad "$1: package $r is not installed" ;;
        esac
    done <<< "$2"
}

cf=$ROOT/harness/Containerfile
[ -f "$cf" ] || bad "missing $cf"
if [ -f "$cf" ]; then
    block=$(cat "$cf")
    report "harness/Containerfile" "$(block_ok "$block")"
fi

declare -A seen=()
for wf in ci.yml mutants.yml; do
    f=$ROOT/.github/workflows/$wf
    [ -f "$f" ] || { bad "missing $f"; continue; }
    ids=$(awk '/^jobs:/ { j = 1; next } j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$f")
    for id in $ids; do
        seen["$wf:$id"]=1
        exempt=0
        for e in "${EXEMPT[@]}"; do [ "${e%%[[:space:]]*}" = "$wf:$id" ] && exempt=1; done
        [ "$exempt" = 0 ] || continue
        body=$(awk -v id="$id" '/^jobs:/ { j = 1; next } j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { cur = $1; sub(/:$/, "", cur); next } j && cur == id { print }' "$f")
        report "$wf job $id" "$(block_ok "$body")"
    done
done
for e in "${EXEMPT[@]}"; do
    key=${e%%[[:space:]]*}
    [ -n "${seen[$key]:-}" ] || bad "exempt job $key does not exist: update EXEMPT"
done
exit "$fail"
