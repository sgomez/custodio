#!/usr/bin/env bash
# Host side of `just e2e [TARGET]` (default: all). For each target directory under e2e/targets/ (or E2E_TARGETS): builds its
# Containerfile, boots it as a privileged systemd container with the package mounted read-only, runs the shared guest.sh, then
# checks the case accounting (check-cases.sh) and saves the record of the run (bus daemon, polkit version) under target/e2e/.
# The packages (N, N+1 for the upgrade case and the old-path fixture) are built by the `e2e` recipe, not here.
# A target with a refusal-only marker (F50, ubuntu2404) runs only its own cases (e2e/refusal.sh): it needs no package N+1 and no old-path package.
# A failed target does not stop the others. The guest's E2E-PHASE lines (phase, seconds) go to target/e2e/phases.tsv.
# F131: E2E_TPM (swtpm, the default, also when unset; none; lacking) says what TPM the service sees. Any other value, an empty one included, is refused before anything starts.
#       `all` with E2E_TPM unset runs every target with swtpm, and with none too on a target with a tpm-none marker (debian13; never lacking): no suite reads
#       the mode, which changes only the kind a key gets on import. With E2E_TPM set, every target runs in that one mode. The mode is passed to the guest
#       (-e E2E_TPM), is part of the names of the record and the log (target/e2e/<target>.<mode>.record, .log) and is the record's tpm= line, which the guest must report as asked.
# Needs podman or docker able to run a privileged container (systemd needs cgroups and /run).
# Usage: run.sh [TARGET]            all the cases of the target (or of every target)
#        run.sh TARGET --cases NAME...   F63 (`just e2e-cases`): one target and only the cases whose ids equal a NAME or match it as a shell glob
#                                   (the words after --cases may also come as one word, split on spaces). Every NAME must match a case the target owes (e2e/cases.list
#                                   plus its own cases.list; a refusal-only target: its own only), else nothing is started. The guest gets the selection in
#                                   E2E_SELECT, check-cases.sh requires exactly those cases, and a guest run whose cases are not selected (oldpath) is not made.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
targets_dir=${E2E_TARGETS:-e2e/targets}
packages=${E2E_PACKAGES:-target/packages}
packages_next=${E2E_PACKAGES_NEXT:-target/packages-next} # package N+1 of the upgrade case (scripts/package-next.sh), never in $packages
packages_oldpath=${E2E_PACKAGES_OLDPATH:-target/packages-oldpath} # the old-path fixture of F61 (scripts/package-oldpath.sh); not for a target with a no-oldpath marker
packages_m3=${E2E_PACKAGES_M3:-target/packages-m3} # the M3 build of the tag v0.5.0 (F142, scripts/package-m3.sh): the upgrade-m3-* cases install it first
out_dir=${E2E_OUT:-target/e2e}
want=${1:-all}
# F131: the TPM modes of the run; checked before anything else is looked at or started
tpm_modes='' none_by_marker=''
if [ -z "${E2E_TPM+set}" ]; then
    if [ "$want" = all ] && [ "${2:-}" != --cases ]; then tpm_modes='swtpm none' none_by_marker=1; else tpm_modes=swtpm; fi
else
    case $E2E_TPM in
    swtpm | none | lacking) tpm_modes=$E2E_TPM ;;
    *) echo "e2e: E2E_TPM='$E2E_TPM' is not a TPM mode; the allowed values are: swtpm, none, lacking (default swtpm)" >&2; exit 1 ;;
    esac
fi
# lacking (F131) needs the filter program, built by `just e2e-tpm-filter`; refused before anything starts
tpm_filter=${E2E_TPM_FILTER:-target/release/examples/tpm-filter}
case " $tpm_modes " in
*" lacking "*) [ -x "$tpm_filter" ] || { echo "e2e: E2E_TPM=lacking needs the filter program $tpm_filter (just e2e-tpm-filter builds it)" >&2; exit 1; }
    tpm_filter=$(realpath "$tpm_filter") ;;
esac
subset=''  # set by --cases
names=()
if [ "${2:-}" = --cases ]; then
    subset=1
    shift 2
    set -f # an argument is a glob for the case ids, never for files
    for n in "$@"; do for w in $n; do names+=("$w"); done; done
    set +f
    [ "${#names[@]}" -gt 0 ] || { echo "e2e: --cases needs at least one case name or glob" >&2; exit 1; }
    [ "$want" != all ] || { echo "e2e: a subset of cases runs on one target; 'all' is not one" >&2; exit 1; }
elif [ $# -gt 1 ]; then
    echo "e2e: unexpected argument '$2' (usage: run.sh [TARGET [--cases NAME...]])" >&2
    exit 1
fi

available=$(find "$targets_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | tr '\n' ' ')
if [ "$want" = all ]; then
    list=$available
elif [ -d "$targets_dir/$want" ] && [[ $want =~ ^[A-Za-z0-9._-]+$ ]]; then
    list=$want
else
    echo "e2e: no target '$want'; available targets: ${available:-none}" >&2
    exit 1
fi
[ -n "$list" ] || { echo "e2e: no target directory under $targets_dir" >&2; exit 1; }
pairs=() # "TARGET MODE", in the order of the modes and targets
for m in $tpm_modes; do
    for t in $list; do
        [ "$m" != none ] || [ -z "$none_by_marker" ] || [ -f "$targets_dir/$t/tpm-none" ] || continue
        pairs+=("$t $m")
    done
done

# F63: the selected cases, in the order of the lists, before anything is started
select_cases() { # select_cases TARGET: sets selection (ids, one per line); refuses a name or glob that matches no case the target owes
    local dir="$targets_dir/$1" universe n id hit
    universe=$({ [ -f "$dir/refusal-only" ] || cat e2e/cases.list; [ ! -f "$dir/cases.list" ] || cat "$dir/cases.list"; } | grep -v '^[[:space:]]*\(#\|$\)' || true)
    for n in "${names[@]}"; do
        [[ $n =~ ^[][A-Za-z0-9._*?-]+$ ]] || { echo "e2e: '$n' is not a case name or a glob of case names" >&2; return 1; }
        hit=''
        while IFS= read -r id; do
            # shellcheck disable=SC2053 # the glob is the point
            [[ $id == $n ]] && { hit=1; break; }
        done <<< "$universe"
        [ -n "$hit" ] || { echo "e2e[$1]: no case matches '$n' (cases of e2e/cases.list and of $dir/cases.list)" >&2; return 1; }
    done
    selection=$(while IFS= read -r id; do
        for n in "${names[@]}"; do
            # shellcheck disable=SC2053
            if [[ $id == $n ]]; then echo "$id"; break; fi
        done
    done <<< "$universe")
}
selection=''
if [ -n "$subset" ]; then select_cases "$want" || exit 1; fi

engine=${E2E_ENGINE:-$(command -v podman || command -v docker || true)} # E2E_ENGINE: the container engine to use (CI: docker)
if [ -z "$engine" ] || ! command -v "$engine" > /dev/null; then
    echo "e2e: neither podman nor docker is installed (or E2E_ENGINE='${E2E_ENGINE:-}' is not a program); a systemd container is required" >&2
    exit 1
fi
mkdir -p "$out_dir"

# boot_container NAME TARGET MOUNT...: builds nothing, starts the privileged container and waits for systemd; MOUNTs are read-only -v values.
boot_container() {
    local name=$1 t=$2 dir="$targets_dir/$2" state='' m
    shift 2
    local mounts=()
    for m in "$@"; do mounts+=(-v "$m:ro"); done
    "$engine" run -d --name "$name" --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        "${mounts[@]}" \
        -v "$PWD/e2e:/e2e:ro" \
        -v "$PWD/docs/audit.md:/e2e-docs/audit.md:ro" \
        -v "$PWD/scripts/check-no-plaintext.sh:/e2e-noplain/scripts/check-no-plaintext.sh:ro" \
        -v "$PWD/scripts/check_no_plaintext.py:/e2e-noplain/scripts/check_no_plaintext.py:ro" \
        -v "$PWD/crates/custodiod/src/app_id_source.rs:/e2e-src/app_id_source.rs:ro" \
        -v "$PWD/$dir:/e2e-target:ro" \
        "custodio-e2e-$t" > /dev/null || return 1
    for _ in $(seq 60); do
        state=$("$engine" exec "$name" systemctl is-system-running 2> /dev/null || true)
        case "$state" in running | degraded) return 0 ;; esac
        sleep 1
    done
    echo "e2e[$t]: systemd did not boot (state: $state)" >&2
    return 1
}

run_target() { # run_target TARGET MODE
    local t=$1 tpm=$2 dir="$targets_dir/$1" name="custodio-e2e-$1-$2-$$" pattern found found_next='' found_oldpath='' found_m3='' state log rc=0 line key value cases
    for f in Containerfile skip.list package.pattern install.sh probe.sh; do
        [ -f "$dir/$f" ] || { echo "e2e[$t]: $dir/$f is missing" >&2; return 1; }
    done
    [ -f "$dir/refusal-only" ] || [ -f "$dir/files.sh" ] || { echo "e2e[$t]: $dir/files.sh is missing (the package's file list, for the check that the unit has no test drop-in)" >&2; return 1; }
    bash e2e/check-cases.sh lint "$dir/skip.list" || return 1
    pattern=$(head -n 1 "$dir/package.pattern")
    found=$(find "$packages" -name "$pattern" | sort | tail -n 1)
    [ -n "$found" ] || { echo "e2e[$t]: no package '$pattern' in $packages (the e2e recipe builds it first)" >&2; return 1; }
    if [ -f "$dir/refusal-only" ]; then
        # F50: the package never installs here, so there is no N+1 and no old-path package; only the marker lifts the demand
        [ -f "$dir/cases.list" ] || { echo "e2e[$t]: a refusal-only target needs its own cases.list" >&2; return 1; }
    else
    found_next=$(find "$packages_next" -name "$pattern" 2> /dev/null | sort | tail -n 1)
    [ -n "$found_next" ] || { echo "e2e[$t]: no package N+1 '$pattern' in $packages_next (the e2e recipe builds it)" >&2; return 1; }
    [ "$(realpath "$found")" != "$(realpath "$found_next")" ] || { echo "e2e[$t]: N and N+1 are the same file" >&2; return 1; }
    bash e2e/check-next.sh "$found" "$found_next" || return 1
    if [ ! -f "$dir/no-oldpath" ]; then
        # F61: the upgrade from the package with the daemon at the old path; a no-oldpath marker says why not (Arch has none; one target per format runs it)
        found_oldpath=$(find "$packages_oldpath" -name "$pattern" 2> /dev/null | sort | tail -n 1)
        [ -n "$found_oldpath" ] || { echo "e2e[$t]: no old-path package '$pattern' in $packages_oldpath (the e2e recipe builds it with scripts/package-oldpath.sh)" >&2; return 1; }
        for f in "$found" "$found_next"; do
            [ "$(realpath "$found_oldpath")" != "$(realpath "$f")" ] || { echo "e2e[$t]: the old-path package is the same file as N or N+1" >&2; return 1; }
        done
        ! cmp -s "$found" "$found_oldpath" || { echo "e2e[$t]: the old-path package has the same content as N" >&2; return 1; }
    fi
    # F142: the M3 build, for the upgrade-m3-* cases (every target that installs a package; they are in e2e/cases.list)
    found_m3=$(find "$packages_m3" -name "$pattern" 2> /dev/null | sort | tail -n 1)
    [ -n "$found_m3" ] || { echo "e2e[$t]: no M3 package '$pattern' in $packages_m3 (the e2e recipe builds it with scripts/package-m3.sh)" >&2; return 1; }
    for f in "$found" "$found_next"; do
        [ "$(realpath "$found_m3")" != "$(realpath "$f")" ] || { echo "e2e[$t]: the M3 package is the same file as N or N+1" >&2; return 1; }
    done
    ! cmp -s "$found" "$found_m3" || { echo "e2e[$t]: the M3 package has the same content as N" >&2; return 1; }
    fi
    # F63: whether a subset needs the extra guest runs (it always does without one)
    run_oldpath=1 run_m3=1
    if [ -n "$subset" ]; then
        grep -q '^upgrade-oldpath-' <<< "$selection" || run_oldpath=''
        grep -q '^upgrade-m3-' <<< "$selection" || run_m3=''
    fi
    # the cases of every target, and the ones of this target only
    cases=$(mktemp)
    if [ -f "$dir/refusal-only" ]; then : > "$cases"; else cat e2e/cases.list > "$cases"; fi
    [ ! -f "$dir/cases.list" ] || cat "$dir/cases.list" >> "$cases"
    echo "e2e[$t]: building the image from $dir/Containerfile"
    # the two modes of a target share the image: one build at a time per target
    flock "$work/$t.build.lock" "$engine" build -q -t "custodio-e2e-$t" -f "$dir/Containerfile" "$dir" > /dev/null || return 1
    local mounts=("$PWD/$found:/pkg/$(basename "$found")")
    [ -z "$found_next" ] || mounts+=("$PWD/$found_next:/pkg-next/$(basename "$found_next")")
    [ -z "$found_oldpath" ] || mounts+=("$PWD/$found_oldpath:/pkg-oldpath/$(basename "$found_oldpath")")
    [ -z "$found_m3" ] || mounts+=("$PWD/$found_m3:/pkg-m3/$(basename "$found_m3")")
    [ "$tpm" != lacking ] || mounts+=("$tpm_filter:/e2e-bin/tpm-filter")
    boot_container "$name" "$t" "${mounts[@]}" || return 1
    log="$out_dir/$t.$tpm.log"
    local envsel=(-e "E2E_TPM=$tpm") sel
    if [ -n "$subset" ]; then
        sel=$(tr '\n' ' ' <<< "$selection")
        envsel+=(-e "E2E_SELECT=${sel% }")
        printf '%s\n' "$selection" > "$cases.sel"
    fi
    "$engine" exec "${envsel[@]}" "$name" bash /e2e/guest.sh "$t" 2>&1 | tee "$log" || rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] || { echo "e2e[$t]: the guest exited with status $rc" >&2; return 1; }
    if [ -n "$found_oldpath" ] && [ -n "$run_oldpath" ]; then
        # F61: the same, from the package with the old daemon path, on a fresh container
        "$engine" rm -f "$name" > /dev/null 2>&1 || true
        boot_container "$name" "$t" "${mounts[@]}" || return 1
        "$engine" exec "${envsel[@]}" "$name" bash /e2e/guest.sh "$t" oldpath 2>&1 | tee -a "$log" || rc=${PIPESTATUS[0]}
        [ "$rc" -eq 0 ] || { echo "e2e[$t]: the guest exited with status $rc (upgrade from the old-path package)" >&2; return 1; }
    fi
    if [ -n "$found_m3" ] && [ -n "$run_m3" ]; then
        # F142: the same, from the M3 build, on a fresh container
        "$engine" rm -f "$name" > /dev/null 2>&1 || true
        boot_container "$name" "$t" "${mounts[@]}" || return 1
        "$engine" exec "${envsel[@]}" "$name" bash /e2e/guest.sh "$t" m3 2>&1 | tee -a "$log" || rc=${PIPESTATUS[0]}
        [ "$rc" -eq 0 ] || { echo "e2e[$t]: the guest exited with status $rc (upgrade from the M3 build)" >&2; return 1; }
    fi
    if [ -n "$subset" ]; then
        CHECK_TPM_MODE=$tpm bash e2e/check-cases.sh check "$cases" "$dir/skip.list" "$log" "$cases.sel" || return 1
    else
        CHECK_TPM_MODE=$tpm bash e2e/check-cases.sh check "$cases" "$dir/skip.list" "$log" || return 1
    fi
    rm -f "$cases" "$cases.sel"
    {
        echo "target=$t"
        sed -n 's/^E2E-RECORD //p' "$log"
    } > "$out_dir/$t.$tpm.record"
    for key in bus-daemon polkit-version tpm; do
        value=$(sed -n "s/^$key=//p" "$out_dir/$t.$tpm.record" | head -n 1)
        [ -n "$value" ] || { echo "e2e[$t]: the guest's probe reported no $key" >&2; return 1; }
    done
    sed -n "s/^E2E-PHASE \([^ ]*\) \([0-9]*\)\$/$t\t$tpm\t\1\t\2/p" "$log" > "$work/$t.$tpm.phases"
    value=$(sed -n 's/^tpm=//p' "$out_dir/$t.$tpm.record" | head -n 1)
    [ "$value" = "$tpm" ] || { echo "e2e[$t]: the guest reported tpm=$value, expected $tpm" >&2; return 1; }
    while IFS= read -r line; do echo "e2e[$t]: record: $line"; done < "$out_dir/$t.$tpm.record"
}

# E2E_JOBS: how many target-mode runs at once (default: half the CPUs). Each run has its own container, log and record; the
# output of each is printed whole, in the order of the modes and targets, once all have ended; until then it is in
# $out_dir/runs/<target>.<mode>.out, kept after a run that was cut.
half=$(( $(nproc) / 2 ))
jobs=${E2E_JOBS-$(( half > 0 ? half : 1 ))}
[[ $jobs =~ ^[1-9][0-9]*$ ]] || { echo "e2e: E2E_JOBS='$jobs' is not a positive number" >&2; exit 1; }
(( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )) || { echo "e2e: needs bash 5.1 or later (wait -p)" >&2; exit 1; }
work=$out_dir/runs
rm -rf "$work" && mkdir -p "$work"
containers() { local p; for p in "${pairs[@]}"; do echo "custodio-e2e-${p% *}-${p#* }-$$"; done; }
cleanup() {
    local c pids
    mapfile -t pids < <(jobs -p)
    [ "${#pids[@]}" -eq 0 ] || kill "${pids[@]}" 2> /dev/null || true
    wait
    for c in $(containers); do "$engine" rm -f "$c" > /dev/null 2>&1 || true; done
}
trap cleanup EXIT
run_pair() { # run_pair TARGET MODE: one run, its output and result under $work
    local t=$1 m=$2 start=$SECONDS rc=0
    if run_target "$t" "$m" > "$work/$t.$m.out" 2>&1; then rc=0; else rc=1; fi
    "$engine" rm -f "custodio-e2e-$t-$m-$$" > /dev/null 2>&1 || true
    printf '%s\t%s\t%s\t%s\n' "$t" "$m" "$((SECONDS - start))" "$([ "$rc" = 0 ] && echo passed || echo failed)" > "$work/$t.$m.time"
    return "$rc"
}
declare -A pair_of=() file_of=()
running=0 wall=$SECONDS
reap() {
    local pid
    wait -n -p pid || true
    running=$((running - 1))
    local secs result
    IFS=$'\t' read -r _ _ secs result < "$work/${file_of[$pid]}.time"
    echo "e2e: ended ${pair_of[$pid]} in ${secs}s: $result"
}
for p in "${pairs[@]}"; do # a failing run does not stop the others
    t=${p% *} m=${p#* }
    (( running < jobs )) || reap
    run_pair "$t" "$m" &
    pair_of[$!]="$t ($m)" file_of[$!]="$t.$m"
    running=$((running + 1))
done
while (( running > 0 )); do reap; done
failed=''
printf 'target\tmode\tseconds\tresult\n' > "$out_dir/timings.tsv"
printf 'target\tmode\tphase\tseconds\n' > "$out_dir/phases.tsv"
for p in "${pairs[@]}"; do
    t=${p% *} m=${p#* }
    cat "$work/$t.$m.out"
    cat "$work/$t.$m.time" >> "$out_dir/timings.tsv"
    [ ! -f "$work/$t.$m.phases" ] || cat "$work/$t.$m.phases" >> "$out_dir/phases.tsv"
    grep -q 'passed$' "$work/$t.$m.time" || failed="$failed $t ($m)"
done
echo "e2e: wall time $((SECONDS - wall))s for $(($(wc -l < "$out_dir/timings.tsv") - 1)) runs, $jobs at once (times in $out_dir/timings.tsv)"
if [ -n "$failed" ]; then
    echo "e2e: failed targets:$failed" >&2
    exit 1
fi
passed=''
for p in "${pairs[@]}"; do passed+=" ${p% *} (${p#* })"; done
echo "e2e: passed:$passed"
