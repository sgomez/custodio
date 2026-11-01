#!/usr/bin/env bash
# Installs the package given as the argument with the tool of this distribution; runs as root in the container.
set -euo pipefail
dpkg -i "$1" > /dev/null
