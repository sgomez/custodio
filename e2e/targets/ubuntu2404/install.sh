#!/usr/bin/env bash
# Installs the package given as the argument with apt, like a user would; runs as root in the container. Unlike the other targets nothing is
# discarded: the refusal case needs the exit status and the whole output (stdout and stderr), and expects the install to fail.
set -euo pipefail
DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root install -y --no-install-recommends "$1"
