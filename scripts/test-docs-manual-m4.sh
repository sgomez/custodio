#!/usr/bin/env bash
# Test of the M4 part of docs/manual-acceptance.md (F145): sections 20 to 23 hold the items of M4 acceptance 13, 14 and 15; the
# notice, the kind lines and the scripts they name equal the code (crates/custodio-cli, scripts/check-no-plaintext.sh,
# scripts/tpm-record-check.sh); the state directory is the one of docs/install.md; any busctl command, polkit action id, error
# name or journal query the part holds equals docs/api.md and docs/audit.md. The commands of acceptance 13 are RUN, not only
# read: under scripts/with-swtpm.sh the helper line of the page runs on records of keys made on the swtpm (a key without policy
# passes; a duplicable key, an altered record and a wrong command line fail), and the page's tpm2_pcrextend line changes PCR 7.
# Every kind of check has a negative control: a fixture copy with the claim broken must differ from the real file and must fail.
# The M1 to M3 sections are never searched for an M4 item. Cost: ~6.5 s wall (controls run in parallel subshells, the swtpm part at once). A missing swtpm is a failure, never a skip.
# Usage: scripts/test-docs-manual-m4.sh   (CHECK_ONLY=1 only checks the real files, no controls and no swtpm)
# SC2016: the regexes hold literal backticks and dollars. SC2013: the words looped over contain no spaces.
# shellcheck disable=SC2016,SC2013
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

# shellcheck source=scripts/lib/docs-manual-m4-check.sh
source scripts/lib/docs-manual-m4-check.sh

check || { echo "test-docs-manual-m4: the page fails its checks" >&2; exit 1; }
echo "test-docs-manual-m4: text checks ok ($CHECK_COUNTS)"
[ -z "${CHECK_ONLY:-}" ] || exit 0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=scripts/lib/docs-manual-m4-swtpm.sh
source scripts/lib/docs-manual-m4-swtpm.sh
if [ "${M4_SWTPM_PART:-}" = 1 ]; then
    swtpm_part
    exit
fi
scripts/with-swtpm.sh env M4_SWTPM_PART=1 bash "$0" > "$tmp/swtpm.out" 2>&1 &
swtpm_job=$!

# shellcheck source=scripts/lib/docs-manual-m4-controls.sh
source scripts/lib/docs-manual-m4-controls.sh
