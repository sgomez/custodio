#!/usr/bin/env bash
# Host side of `just e2e [TARGET]` (default: all). For each target directory under e2e/targets/ (or E2E_TARGETS): builds its
# Containerfile, boots it as a privileged systemd container with the package mounted read-only, runs the shared guest.sh, then
# checks the case accounting (check-cases.sh) and saves the record of the run (bus daemon, polkit version) under target/e2e/.
# The packages (N, N+1 for the upgrade case, and for a target with an old.pattern the old package of M1) are built by the `e2e`
# recipe, not here. A target with an old.pattern (debian13) gets a second guest run on a fresh container, from the old package. A failed target does not stop the others.
# Needs podman or docker able to run a privileged container (systemd needs cgroups and /run).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
targets_dir=${E2E_TARGETS:-e2e/targets}
packages=${E2E_PACKAGES:-target/packages}
packages_next=${E2E_PACKAGES_NEXT:-target/packages-next} # package N+1 of the upgrade case (scripts/package-next.sh), never in $packages
packages_old=${E2E_PACKAGES_OLD:-target/packages-old} # the old package of M1 (scripts/package-old.sh); only for targets with an old.pattern
out_dir=${E2E_OUT:-target/e2e}
want=${1:-all}

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
    local t=$1 dir="$targets_dir/$1" name="custodio-e2e-$1-$$" pattern found found_next found_old='' state log rc=0 line key value cases
    for f in Containerfile skip.list package.pattern install.sh probe.sh; do
        [ -f "$dir/$f" ] || { echo "e2e[$t]: $dir/$f is missing" >&2; return 1; }
    done
    bash e2e/check-cases.sh lint "$dir/skip.list" || return 1
    pattern=$(head -n 1 "$dir/package.pattern")
    found=$(find "$packages" -name "$pattern" | sort | tail -n 1)
    [ -n "$found" ] || { echo "e2e[$t]: no package '$pattern' in $packages (the e2e recipe builds it first)" >&2; return 1; }
    found_next=$(find "$packages_next" -name "$pattern" 2> /dev/null | sort | tail -n 1)
    [ -n "$found_next" ] || { echo "e2e[$t]: no package N+1 '$pattern' in $packages_next (the e2e recipe builds it)" >&2; return 1; }
    [ "$(realpath "$found")" != "$(realpath "$found_next")" ] || { echo "e2e[$t]: N and N+1 are the same file" >&2; return 1; }
    bash e2e/check-next.sh "$found" "$found_next" || return 1
    if [ -f "$dir/old.pattern" ]; then
        found_old=$(find "$packages_old" -name "$(head -n 1 "$dir/old.pattern")" 2> /dev/null | sort | tail -n 1)
        [ -n "$found_old" ] || { echo "e2e[$t]: no old package '$(head -n 1 "$dir/old.pattern")' in $packages_old (the e2e recipe builds it with scripts/package-old.sh)" >&2; return 1; }
        for f in "$found" "$found_next"; do
            [ "$(realpath "$found_old")" != "$(realpath "$f")" ] || { echo "e2e[$t]: the old package is the same file as N or N+1" >&2; return 1; }
        done
    fi
    # the cases of every target, and the ones of this target only
    cases=$(mktemp)
    cat e2e/cases.list > "$cases"
    [ ! -f "$dir/cases.list" ] || cat "$dir/cases.list" >> "$cases"
    echo "e2e[$t]: building the image from $dir/Containerfile"
    "$engine" build -q -t "custodio-e2e-$t" -f "$dir/Containerfile" "$dir" > /dev/null || return 1
    local mounts=("$PWD/$found:/pkg/$(basename "$found")" "$PWD/$found_next:/pkg-next/$(basename "$found_next")")
    [ -z "$found_old" ] || mounts+=("$PWD/$found_old:/pkg-old/$(basename "$found_old")")
    boot_container "$name" "$t" "${mounts[@]}" || return 1
    log="$out_dir/$t.log"
    "$engine" exec "$name" bash /e2e/guest.sh "$t" 2>&1 | tee "$log" || rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] || { echo "e2e[$t]: the guest exited with status $rc" >&2; return 1; }
    if [ -n "$found_old" ]; then
        # the upgrade from the old package runs on a fresh container: the run above left N+1 installed
        "$engine" rm -f "$name" > /dev/null 2>&1 || true
        boot_container "$name" "$t" "${mounts[@]}" || return 1
        "$engine" exec "$name" bash /e2e/guest.sh "$t" old 2>&1 | tee -a "$log" || rc=${PIPESTATUS[0]}
        [ "$rc" -eq 0 ] || { echo "e2e[$t]: the guest exited with status $rc (upgrade from the old package)" >&2; return 1; }
    fi
    bash e2e/check-cases.sh check "$cases" "$dir/skip.list" "$log" || return 1
    rm -f "$cases"
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
