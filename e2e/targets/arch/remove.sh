#!/usr/bin/env bash
# Removes the package with pacman -R, like a user would; runs as root in the container. The output (stdout and stderr, scriptlets included)
# goes to the caller, which captures it: the removal notice is checked there.
set -euo pipefail
pacman -R --noconfirm custodio
