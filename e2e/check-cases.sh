#!/usr/bin/env bash
# The case accounting of one e2e run.
#   check-cases.sh lint SKIP_LIST             the skip list is well formed
#   check-cases.sh check CASES SKIP_LIST OUT  OUT (the guest's output) reports every case of CASES exactly once, and every skipped
#                                             case is on SKIP_LIST
# Skip list format: one `case: reason` per line, the case being [A-Za-z0-9._-]+ and the reason not empty; `#` starts a comment
# line; blank lines are ignored; a case appears once. Unused entries are reported on stderr and do not fail.
set -euo pipefail
die() { echo "check-cases: $*" >&2; exit 1; }

lint() { # prints the cases of the list, one per line
    local file=$1 line n=0 case seen=" "
    [ -f "$file" ] || die "$file: no such file"
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        case $line in '' | '#'*) continue ;; esac
        [[ $line =~ ^([A-Za-z0-9._-]+):[[:space:]]*(.*[^[:space:]])[[:space:]]*$ ]] \
            || die "$file:$n: expected 'case: reason' with a case and a reason, got '$line'"
        case=${BASH_REMATCH[1]}
        case $seen in *" $case "*) die "$file:$n: case '$case' is listed twice" ;; esac
        seen="$seen$case "
        printf '%s\n' "$case"
    done < "$file"
}

reported() { # kind: the cases the output reports as run or skipped, in order
    sed -n 's/^E2E-CASE \(run\|skipped\) \([^ ]*\)$/\1 \2/p' "$1"
}

check() {
    local cases=$1 skips=$2 out=$3 listed known kind id seen=" " bad=0 line
    [ -f "$cases" ] || die "$cases: no such file"
    [ -f "$out" ] || die "$out: no such file"
    listed=" $(lint "$skips" | tr '\n' ' ')"
    known=" $(grep -v '^[[:space:]]*\(#\|$\)' "$cases" | tr '\n' ' ')"
    local skipped=" "
    while read -r kind id; do
        case $known in *" $id "*) ;; *) echo "check-cases: unknown case '$id'" >&2; bad=1; continue ;; esac
        case $seen in *" $id "*) echo "check-cases: case '$id' reported twice" >&2; bad=1; continue ;; esac
        seen="$seen$id "
        if [ "$kind" = skipped ]; then
            skipped="$skipped$id "
            case $listed in *" $id "*) echo "check-cases: skipped (on the skip list): $id" ;;
                *) echo "check-cases: case '$id' was skipped and is not on the skip list" >&2; bad=1 ;; esac
        fi
    done < <(reported "$out")
    for id in $known; do
        case $seen in *" $id "*) ;; *) echo "check-cases: case '$id' was not reported (neither run nor skipped)" >&2; bad=1 ;; esac
    done
    for id in $listed; do
        case $skipped in *" $id "*) ;; *) echo "check-cases: skip list entry '$id' matches no skipped case; remove it" >&2 ;; esac
    done
    line=$(reported "$out" | wc -l)
    [ "$bad" -eq 0 ] || exit 1
    echo "check-cases: $line cases accounted for"
}

case ${1:-} in
lint) [ $# -eq 2 ] || die "usage: lint SKIP_LIST"; lint "$2" > /dev/null ;;
check) [ $# -eq 4 ] || die "usage: check CASES SKIP_LIST OUT"; check "$2" "$3" "$4" ;;
*) die "usage: lint SKIP_LIST | check CASES SKIP_LIST OUT" ;;
esac
