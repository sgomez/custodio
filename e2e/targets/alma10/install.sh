#!/usr/bin/env bash
# Installs the package given as the argument with dnf, like a user would; runs as root in the container. dnf resolves the
# package's dependencies from the distribution's repositories.
set -euo pipefail
dnf install -y --setopt=install_weak_deps=False "$1" > /dev/null
