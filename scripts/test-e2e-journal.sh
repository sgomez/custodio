#!/usr/bin/env bash
# The self-test of e2e/journal.py on the host: it needs only bash and python3, so it does not run in each e2e container.
set -euo pipefail
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/e2e/journal-selftest.sh"
