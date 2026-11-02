#!/usr/bin/env bash
# Host side of `just e2e [TARGET]` (default: all). For each target directory under e2e/targets/ (or E2E_TARGETS): builds its
# Containerfile, boots it as a privileged systemd container with the package mounted read-only, runs the shared guest.sh, then
# checks the case accounting (check-cases.sh) and saves the record of the run (bus daemon, polkit version) under target/e2e/.
# The packages (N, N+1 for the upgrade case and the old-path fixture) are built by the `e2e` recipe, not here.
# A target with a refusal-only marker (F50, ubuntu2404) runs only its own cases (e2e/refusal.sh): it needs no package N+1 and no old-path package.
# A failed target does not stop the others.
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
out_dir=${E2E_OUT:-target/e2e}
want=${1:-all}
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

engine=$(command -v podman || command -v docker || true)
if [ -z "$engine" ]; then
    echo "e2e: neither podman nor docker is installed; a systemd container is required" >&2
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

run_target() {
    local t=$1 dir="$targets_dir/$1" name="custodio-e2e-$1-$$" pattern found found_next='' found_oldpath='' state log rc=0 line key value cases
    for f in Containerfile skip.list package.pattern install.sh probe.sh; do
        [ -f "$dir/$f" ] || { echo "e2e[$t]: $dir/$f is missing" >&2; return 1; }
    done
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
        # F61: the upgrade from the package with the daemon at the old path, on every target that has one (a no-oldpath marker says why not: Arch)
        found_oldpath=$(find "$packages_oldpath" -name "$pattern" 2> /dev/null | sort | tail -n 1)
        [ -n "$found_oldpath" ] || { echo "e2e[$t]: no old-path package '$pattern' in $packages_oldpath (the e2e recipe builds it with scripts/package-oldpath.sh)" >&2; return 1; }
        for f in "$found" "$found_next"; do
            [ "$(realpath "$found_oldpath")" != "$(realpath "$f")" ] || { echo "e2e[$t]: the old-path package is the same file as N or N+1" >&2; return 1; }
        done
        ! cmp -s "$found" "$found_oldpath" || { echo "e2e[$t]: the old-path package has the same content as N" >&2; return 1; }
    fi
    fi
    # F63: whether a subset needs the extra guest run (it always does without one)
    run_oldpath=1
    if [ -n "$subset" ]; then
        grep -q '^upgrade-oldpath-' <<< "$selection" || run_oldpath=''
    fi
    # the cases of every target, and the ones of this target only
    cases=$(mktemp)
    if [ -f "$dir/refusal-only" ]; then : > "$cases"; else cat e2e/cases.list > "$cases"; fi
    [ ! -f "$dir/cases.list" ] || cat "$dir/cases.list" >> "$cases"
    echo "e2e[$t]: building the image from $dir/Containerfile"
    "$engine" build -q -t "custodio-e2e-$t" -f "$dir/Containerfile" "$dir" > /dev/null || return 1
    local mounts=("$PWD/$found:/pkg/$(basename "$found")")
    [ -z "$found_next" ] || mounts+=("$PWD/$found_next:/pkg-next/$(basename "$found_next")")
    [ -z "$found_oldpath" ] || mounts+=("$PWD/$found_oldpath:/pkg-oldpath/$(basename "$found_oldpath")")
    boot_container "$name" "$t" "${mounts[@]}" || return 1
    log="$out_dir/$t.log"
    local envsel=() sel
    if [ -n "$subset" ]; then
        sel=$(tr '\n' ' ' <<< "$selection")
        envsel=(-e "E2E_SELECT=${sel% }")
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
    if [ -n "$subset" ]; then
        bash e2e/check-cases.sh check "$cases" "$dir/skip.list" "$log" "$cases.sel" || return 1
    else
        bash e2e/check-cases.sh check "$cases" "$dir/skip.list" "$log" || return 1
    fi
    rm -f "$cases" "$cases.sel"
    {
        echo "target=$t"
        sed -n 's/^E2E-RECORD //p' "$log"
    } > "$out_dir/$t.record"
    for key in bus-daemon polkit-version; do
        value=$(sed -n "s/^$key=//p" "$out_dir/$t.record" | head -n 1)
        [ -n "$value" ] || { echo "e2e[$t]: the guest's probe reported no $key" >&2; return 1; }
    done
    while IFS= read -r line; do echo "e2e[$t]: record: $line"; done < "$out_dir/$t.record"
}

failed=''
trap 'for t in $list; do "$engine" rm -f "custodio-e2e-$t-$$" >/dev/null 2>&1 || true; done' EXIT
for t in $list; do
    if ! run_target "$t"; then failed="$failed $t"; fi
    "$engine" rm -f "custodio-e2e-$t-$$" > /dev/null 2>&1 || true
done
if [ -n "$failed" ]; then
    echo "e2e: failed targets:$failed" >&2
    exit 1
fi
echo "e2e: passed: $list"
