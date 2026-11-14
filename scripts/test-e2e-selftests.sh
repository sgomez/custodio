#!/usr/bin/env bash
# The self-tests of the e2e judgements that need only bash and python3, run on the host: each feeds its judgement good and bad evidence.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
for t in journal owner ops rd jo appid cli tpmkind; do
    bash "$ROOT/e2e/$t-selftest.sh" > /dev/null || { echo "test-e2e-selftests: $t-selftest.sh fails" >&2; fail=1; }
done
exit "$fail"
