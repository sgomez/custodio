#!/usr/bin/env bash
# Removes the package with apt, like a user would; runs as root in the container. The output (stdout and stderr, scriptlets included) goes to
# the caller, which captures it: the removal notice is checked there.
set -euo pipefail
DEBIAN_FRONTEND=noninteractive apt-get remove -y custodio
