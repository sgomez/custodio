#!/usr/bin/env bash
# Host side of `just e2e`: boots a systemd container, installs the .deb in it and runs guest.sh.
# Needs podman or docker able to run a privileged container (systemd needs cgroups and /run).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
engine=$(command -v podman || command -v docker || true)
if [ -z "$engine" ]; then
    echo "e2e: neither podman nor docker is installed; a systemd container is required" >&2
    exit 1
fi
deb=$(find target/debian -name 'custodio_*.deb' | sort | tail -n 1)
[ -n "$deb" ] || { echo "e2e: no .deb in target/debian (run just package)" >&2; exit 1; }
"$engine" build -q -t custodio-e2e -f e2e/Containerfile e2e >/dev/null
name="custodio-e2e-$$"
cleanup() { "$engine" rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
"$engine" run -d --name "$name" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    -v "$PWD/$deb":/pkg/custodio.deb:ro \
    -v "$PWD/e2e":/e2e:ro \
    custodio-e2e >/dev/null
for _ in $(seq 60); do
    state=$("$engine" exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running | degraded) break ;; esac
    sleep 1
done
case "$state" in running | degraded) ;; *) echo "e2e: systemd did not boot (state: $state)" >&2; exit 1 ;; esac
"$engine" exec "$name" bash /e2e/guest.sh
