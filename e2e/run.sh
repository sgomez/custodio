#!/usr/bin/env bash
# Host side of `just e2e [TARGET]` (default: all). For each target directory under e2e/targets/ (or E2E_TARGETS): builds its
# Containerfile, boots it as a privileged systemd container with the package mounted read-only, runs the shared guest.sh, then
# checks the case accounting (check-cases.sh) and saves the record of the run (bus daemon, polkit version) under target/e2e/.
# The packages are built by the `package` dependency of the recipe, not here. A failed target does not stop the others.
# Needs podman or docker able to run a privileged container (systemd needs cgroups and /run).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
targets_dir=${E2E_TARGETS:-e2e/targets}
packages=${E2E_PACKAGES:-target/packages}
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

run_target() {
    local t=$1 dir="$targets_dir/$1" name="custodio-e2e-$1-$$" pattern found state log rc=0 line key value
    for f in Containerfile skip.list package.pattern install.sh probe.sh; do
        [ -f "$dir/$f" ] || { echo "e2e[$t]: $dir/$f is missing" >&2; return 1; }
    done
    bash e2e/check-cases.sh lint "$dir/skip.list" || return 1
    pattern=$(head -n 1 "$dir/package.pattern")
    found=$(find "$packages" -name "$pattern" | sort | tail -n 1)
    [ -n "$found" ] || { echo "e2e[$t]: no package '$pattern' in $packages (the e2e recipe builds it first)" >&2; return 1; }
    echo "e2e[$t]: building the image from $dir/Containerfile"
    "$engine" build -q -t "custodio-e2e-$t" -f "$dir/Containerfile" "$dir" > /dev/null || return 1
    "$engine" run -d --name "$name" --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        -v "$PWD/$found:/pkg/$(basename "$found"):ro" \
        -v "$PWD/e2e:/e2e:ro" \
        -v "$PWD/$dir:/e2e-target:ro" \
        "custodio-e2e-$t" > /dev/null || return 1
    state=''
    for _ in $(seq 60); do
        state=$("$engine" exec "$name" systemctl is-system-running 2> /dev/null || true)
        case "$state" in running | degraded) break ;; esac
        sleep 1
    done
    case "$state" in running | degraded) ;; *) echo "e2e[$t]: systemd did not boot (state: $state)" >&2; return 1 ;; esac
    log="$out_dir/$t.log"
    "$engine" exec "$name" bash /e2e/guest.sh "$t" 2>&1 | tee "$log" || rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] || { echo "e2e[$t]: the guest exited with status $rc" >&2; return 1; }
    bash e2e/check-cases.sh check e2e/cases.list "$dir/skip.list" "$log" || return 1
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
