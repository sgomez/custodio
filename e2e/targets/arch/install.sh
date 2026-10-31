#!/usr/bin/env bash
# Installs the package given as the argument with pacman -U, like a user would; runs as root in the container. pacman
# resolves the package's dependencies from the sync databases the image refreshed with a full upgrade.
set -euo pipefail
pacman -U --noconfirm --needed "$1" > /dev/null
