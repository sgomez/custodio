#!/usr/bin/env bash
# Installs the package given as the argument the way the VM install does (e2e/vm/run.sh): apt, from the local file, without recommends.
# Used by upgrade.sh in a VM (E2E_INSTALL); runs as root in the guest.
set -euo pipefail
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$1" > /dev/null
