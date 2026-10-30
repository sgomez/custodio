#!/usr/bin/env bash
# Fails when the sysusers text embedded in the deb preinst (the heredoc CUSTODIO_SYSUSERS) is not the same as the lines of
# data/sysusers.d/custodio.conf: a pre-install script cannot read the packaged file, so it carries a copy (F43).
# usage: check-sysusers-sync.sh [ROOT]
set -euo pipefail
ROOT=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
conf=$ROOT/data/sysusers.d/custodio.conf
script=$ROOT/packaging/deb/preinst
want=$(grep -Ev '^[[:space:]]*(#|$)' "$conf" || true)
got=$(sed -n "/<<'CUSTODIO_SYSUSERS'\$/,/^CUSTODIO_SYSUSERS\$/{//!p}" "$script")
[ -n "$want" ] || { echo "check-sysusers-sync: $conf has no entry" >&2; exit 1; }
if [ "$want" != "$got" ]; then
    echo "check-sysusers-sync: the sysusers text in packaging/deb/preinst differs from data/sysusers.d/custodio.conf" >&2
    exit 1
fi
