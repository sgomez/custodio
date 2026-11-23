# shellcheck shell=bash
# Sourced by check-tpm-install-sync.sh and check-shell-install-sync.sh. Fails unless harness/Containerfile and every job of WORKFLOWS
# install PACKAGES, each install preceded by a comment that mentions KEYWORD, except the jobs in EXEMPT.
# The caller sets: NAME (for messages), ROOT, KEYWORD (lower-case, matched in the comment above the install), PACKAGES (array),
# WORKFLOWS (array of file names), EXEMPT (array of "file:job reason"). A job that is neither checked nor exempt fails the check.
fail=0
bad() { echo "$NAME: $*" >&2; fail=1; }

# block_ok TEXT: prints what is wrong with the install in TEXT, one item per line (nothing when it is right). The install is every apt
# install statement (backslash continuations joined) that names one of the packages; together they must name all of them, and the
# first must follow a comment block that mentions KEYWORD.
block_ok() {
    local text=$1 p out pattern
    pattern=$(IFS='|'; echo "${PACKAGES[*]}")
    out=$(awk -v pat="(^|[^A-Za-z0-9_.+-])($pattern)([^A-Za-z0-9_.+-]|\$)" -v kw="$KEYWORD" '
        function flush() {
            if (stmt ~ /apt(-get)? .*install/ && stmt ~ pat) { all = all " " stmt; if (!n++) ok = above }
            stmt = ""
        }
        /^[[:space:]]*#/ { if (!pc) blk = 0; if (index(tolower($0), kw)) blk = 1; pc = 1; next }
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
        NOINSTALL) bad "$1: no apt install of the $KEYWORD packages" ;;
        NOCOMMENT) bad "$1: the install has no comment above it that mentions $KEYWORD" ;;
        *) bad "$1: package $r is not installed" ;;
        esac
    done <<< "$2"
}

run_install_sync() {
    local cf=$ROOT/harness/Containerfile wf f ids id e key body block
    [ -f "$cf" ] || bad "missing $cf"
    if [ -f "$cf" ]; then
        block=$(cat "$cf")
        report "harness/Containerfile" "$(block_ok "$block")"
    fi
    declare -A seen=()
    for wf in "${WORKFLOWS[@]}"; do
        f=$ROOT/.github/workflows/$wf
        [ -f "$f" ] || { bad "missing $f"; continue; }
        ids=$(awk '/^jobs:/ { j = 1; next } j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { sub(/^  /, ""); sub(/:.*/, ""); print }' "$f")
        for id in $ids; do
            seen["$wf:$id"]=1
            local skip=0
            for e in "${EXEMPT[@]}"; do [ "${e%%[[:space:]]*}" = "$wf:$id" ] && skip=1; done
            [ "$skip" = 0 ] || continue
            body=$(awk -v id="$id" '/^jobs:/ { j = 1; next } j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { cur = $1; sub(/:$/, "", cur); next } j && cur == id { print }' "$f")
            report "$wf job $id" "$(block_ok "$body")"
        done
    done
    for e in "${EXEMPT[@]}"; do
        key=${e%%[[:space:]]*}
        [ -n "${seen[$key]:-}" ] || bad "exempt job $key does not exist: update EXEMPT"
    done
    return "$fail"
}
