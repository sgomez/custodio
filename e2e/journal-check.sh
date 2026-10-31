#!/usr/bin/env bash
# Runs as root after the signatures (acceptance 7, 8 and 10). Needs WORK, START (epoch seconds before the package
# was installed) and TOTAL (the agent's request count before the unavailable signature).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/report.sh"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
uid=$(id -u custodio)
journalctl --sync

# Acceptance 7: the documented query of docs/audit.md, since the start of the run.
journalctl _SYSTEMD_UNIT=custodio.service "_UID=$uid" MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 \
    --since "@$START" -o json --no-pager > "$WORK/audit.json"
# One entry per signature of the run: the agent was asked TOTAL times, plus the unavailable signature.
python3 -I "$here/journal.py" entries --json "$WORK/audit.json" --ledger "$WORK/journal.cases" --uid "$uid" \
    --expect-total $((TOTAL + 1)) --forbid-pidless || fail "the audit entries do not match the signatures"

# Acceptance 8: nothing that was signed, and no password, anywhere in the journal of the service.
journalctl -u custodio.service --since "@$START" -o export --no-pager > "$WORK/service.export"
extra=()
for f in "$WORK/data.bin" "$WORK/deny.bin" "$WORK/big.bin" "$WORK/sig.bin" "$WORK/issued.der"; do extra+=(--file "$f"); done
python3 -I "$here/journal.py" sweep --export "$WORK/service.export" --evidence "$WORK/evidence" "${extra[@]}" \
    --password e2e-password || fail "a secret reached the journal of custodio.service"
case_run "journal-entries"

# The journal catalog: a fresh entry of this run, shown with `journalctl -x`, carries the explanation of data/custodio.catalog. This
# never runs `journalctl --update-catalog`: the package's own scripts (or the distribution's hooks) must have registered it.
journalctl -x -u custodio.service MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401 --since "@$START" -n 1 --no-pager > "$WORK/catalog.txt"
python3 -I "$here/journal.py" catalog --text "$WORK/catalog.txt" --expect "$here/catalog-text.txt" \
    || fail "the entry is not shown with the explanation of the journal catalog"
case_run "journal-catalog"
