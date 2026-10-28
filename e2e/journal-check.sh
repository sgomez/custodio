#!/usr/bin/env bash
# Runs as root after the signatures (acceptance 7 and 8). Needs WORK, START (epoch seconds before the package
# was installed) and TOTAL (the agent's request count before the unavailable signature).
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
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
echo "ok: journal entries and no secrets in the journal"
