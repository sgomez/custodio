#!/usr/bin/env bash
# Purges the package with apt (remove and delete its configuration), like a user would; runs as root in the container. The output goes to the
# caller, which captures it.
set -euo pipefail
DEBIAN_FRONTEND=noninteractive apt-get purge -y custodio
