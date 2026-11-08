#!/usr/bin/env bash
# The case accounting of one e2e run.
#   check-cases.sh lint SKIP_LIST             the skip list is well formed
#   check-cases.sh check CASES SKIP_LIST OUT [SELECTED]
#                                             OUT (the guest's output) reports every case of CASES exactly once, and every skipped
#                                             case is on SKIP_LIST. With SELECTED (a file of case ids, a subset of CASES: `just
#                                             e2e-cases`) it reports exactly those cases once each and no other case of CASES
# CHECK_TPM_MODE (F133): the TPM mode of the run (swtpm, none, lacking; run.sh sets it). In swtpm a case that needs that mode (the tpm-kind-* cases) must be run: reported
# skipped it fails the accounting even when a skip list names it. Unset, or another mode: no such rule.
# F134: a sign-* case runs in every TPM mode; reported skipped it fails the accounting in any mode, even when a skip list names it.
# F135: the same for the noplain-* cases.
# F144: the same for the journal-kind-* cases (every injection they use exists in every mode: skipped fails the accounting in any mode).
# F136: a tpm-dup-* case needs a key of kind tpm: skipped it fails the accounting in swtpm and lacking (only mode none may skip it).
# F137: the same for the pcr-* cases (they need a TPM: only mode none may skip them).
# F138: a fallback-tpmbound-* case is skipped in every mode (SPEC_DEVIATIONS.md, F134) and refused reported run; a fallback-host-* case must run in mode none.
# F140: the same for the tpm-clear-* cases (a TPM to clear: only mode none may skip them).
# F143: the same for the tpm-slots-* cases (slots to use up: only mode none may skip them).
# F139: a tpmfail-* case needs mode swtpm: skipped it fails the accounting in swtpm, and reported run it fails in none and lacking (they replace the TPM of the run themselves).
# F141: the upgrade-kinds-before, -kept and -signs cases run in every TPM mode: skipped fails the accounting in any mode; upgrade-kinds-tpmbound is skipped in every mode (SPEC_DEVIATIONS.md, F134) and refused reported run.
# F160: CHECK_VM=1 says the run is a VM run (e2e/vm/run.sh). The VM always has a TPM, so a VM run is accounted as swtpm unless CHECK_TPM_MODE says lacking (the pcr-*, tpm-clear-*
# cases never skipped), and fallback-tpmbound-* and upgrade-kinds-tpmbound are accepted reported run and refused reported skipped, even when a skip list names them. Unset: nothing changes.
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
    local cases=$1 skips=$2 out=$3 sel=${4:-} listed known kind id seen=" " bad=0 line owed
    [ -f "$cases" ] || die "$cases: no such file"
    [ -f "$out" ] || die "$out: no such file"
    if [ -n "${CHECK_VM:-}" ]; then case ${CHECK_TPM_MODE:-} in swtpm | lacking) ;; *) CHECK_TPM_MODE=swtpm ;; esac; fi
    listed=" $(lint "$skips" | tr '\n' ' ')"
    known=" $(grep -v '^[[:space:]]*\(#\|$\)' "$cases" | tr '\n' ' ')"
    owed=$known
    if [ -n "$sel" ]; then
        [ -f "$sel" ] || die "$sel: no such file"
        owed=" $(grep -v '^[[:space:]]*\(#\|$\)' "$sel" | tr '\n' ' ')"
        [ "$owed" != " " ] || die "$sel: no case is selected"
        for id in $owed; do case $known in *" $id "*) ;; *) die "selected case '$id' is not a case of $cases" ;; esac; done
    fi
    local skipped=" "
    while read -r kind id; do
        case $known in *" $id "*) ;; *) echo "check-cases: unknown case '$id'" >&2; bad=1; continue ;; esac
        case $seen in *" $id "*) echo "check-cases: case '$id' reported twice" >&2; bad=1; continue ;; esac
        seen="$seen$id "
        case $owed in *" $id "*) ;; *) echo "check-cases: case '$id' was reported and is not selected" >&2; bad=1; continue ;; esac
        if [ "$kind" = skipped ] && [ -n "${CHECK_VM:-}" ]; then
            case $id in upgrade-kinds-tpmbound | fallback-tpmbound-*) echo "check-cases: case '$id' must run in a VM run and was skipped" >&2; bad=1 ;; esac
        fi
        if [ "$kind" = skipped ]; then
            case $id in upgrade-kinds-tpmbound) ;; upgrade-kinds-*) echo "check-cases: case '$id' applies to every TPM mode and was skipped" >&2; bad=1 ;; esac
            case $id in sign-* | noplain-* | journal-kind-*) echo "check-cases: case '$id' applies to every TPM mode and was skipped" >&2; bad=1 ;; esac
        fi
        if [ "$kind" = run ]; then
            case $id in tpmfail-*) case ${CHECK_TPM_MODE:-} in none | lacking) echo "check-cases: case '$id' runs only in swtpm and was reported run in mode ${CHECK_TPM_MODE}" >&2; bad=1 ;; esac ;; esac
            if [ -z "${CHECK_VM:-}" ]; then
                case $id in upgrade-kinds-tpmbound) echo "check-cases: case '$id' cannot be run (deviation F134) and was reported run" >&2; bad=1 ;; esac
                case $id in fallback-tpmbound-*) echo "check-cases: case '$id' cannot be run (deviation F134) and was reported run" >&2; bad=1 ;; esac
            fi
        fi
        if [ "$kind" = skipped ] && [ "${CHECK_TPM_MODE:-}" = swtpm ]; then
            case $id in tpm-kind-*) echo "check-cases: case '$id' needs the swtpm mode and was skipped in it" >&2; bad=1 ;; esac
        fi
        if [ "$kind" = skipped ]; then
            case $id in tpm-dup-* | pcr-* | tpm-clear-* | tpm-slots-*) case ${CHECK_TPM_MODE:-} in swtpm | lacking) echo "check-cases: case '$id' needs a TPM key and was skipped in mode ${CHECK_TPM_MODE}" >&2; bad=1 ;; esac ;; esac
            case $id in tpmfail-*) [ "${CHECK_TPM_MODE:-}" != swtpm ] || { echo "check-cases: case '$id' needs mode swtpm and was skipped in it" >&2; bad=1; } ;; esac
            case $id in fallback-host-*) [ "${CHECK_TPM_MODE:-}" != none ] || { echo "check-cases: case '$id' needs mode none and was skipped in it" >&2; bad=1; } ;; esac
            skipped="$skipped$id "
            case $listed in *" $id "*) echo "check-cases: skipped (on the skip list): $id" ;;
                *) echo "check-cases: case '$id' was skipped and is not on the skip list" >&2; bad=1 ;; esac
        fi
    done < <(reported "$out")
    for id in $owed; do
        case $seen in *" $id "*) ;; *) echo "check-cases: case '$id' was not reported (neither run nor skipped)" >&2; bad=1 ;; esac
    done
    for id in $listed; do
        [ -z "$sel" ] || case $owed in *" $id "*) ;; *) continue ;; esac
        # tpm-kind-* are listed for the modes without swtpm; under swtpm they run, so the entry is expected to match nothing
        case $id in tpm-kind-*) [ "${CHECK_TPM_MODE:-}" != swtpm ] || continue ;; esac
        case $id in tpm-dup-* | pcr-* | tpm-clear-* | tpm-slots-*) case ${CHECK_TPM_MODE:-} in swtpm | lacking) continue ;; esac ;; esac
        case $id in fallback-host-*) [ "${CHECK_TPM_MODE:-}" != none ] || continue ;; esac
        case $id in tpmfail-*) [ "${CHECK_TPM_MODE:-}" != swtpm ] || continue ;; esac
        case $skipped in *" $id "*) ;; *) echo "check-cases: skip list entry '$id' matches no skipped case; remove it" >&2 ;; esac
    done
    line=$(reported "$out" | wc -l)
    [ "$bad" -eq 0 ] || exit 1
    echo "check-cases: $line cases accounted for"
}

case ${1:-} in
lint) [ $# -eq 2 ] || die "usage: lint SKIP_LIST"; lint "$2" > /dev/null ;;
check) [ $# -eq 4 ] || [ $# -eq 5 ] || die "usage: check CASES SKIP_LIST OUT [SELECTED]"; check "$2" "$3" "$4" "${5:-}" ;;
*) die "usage: lint SKIP_LIST | check CASES SKIP_LIST OUT [SELECTED]" ;;
esac
