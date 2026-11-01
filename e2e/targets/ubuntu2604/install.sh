#!/usr/bin/env bash
# Installs the package given as the argument with apt, like a user would; runs as root in the container. apt resolves the
# package's dependencies (the sandbox user is root because the mounted file may not be readable by _apt in a rootless engine).
set -euo pipefail
DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root install -y --no-install-recommends "$1" > /dev/null
