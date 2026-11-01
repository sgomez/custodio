#!/usr/bin/env bash
# Derives the unit of each package format from the one unit source (F61). The daemon is at /usr/libexec/custodio/custodiod in the .deb and
# the .rpm and at /usr/lib/custodio/custodiod in the Arch package, so the ExecStart line is the only thing that differs. The source
# (data/custodio.service) holds the Arch path; the other formats get the libexec path.
# usage: derive-units.sh [SRC_UNIT [OUT_DIR]]   (defaults: data/custodio.service, target/units)
# Writes OUT_DIR/{deb,rpm,archlinux}/custodio.service. Fails when the source has not exactly one ExecStart line with the source path, names
# the daemon path anywhere else (the derivation would leave it behind), or when another unit file with an ExecStart sits beside it.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC=${1:-$ROOT/data/custodio.service}
OUT=${2:-$ROOT/target/units}
SRC_PATH=/usr/lib/custodio/custodiod
LIBEXEC_PATH=/usr/libexec/custodio/custodiod
die() { echo "derive-units: $*" >&2; exit 1; }

[ -f "$SRC" ] || die "the unit source '$SRC' does not exist"
[ "$(grep -c '^ExecStart=' "$SRC" || true)" -eq 1 ] || die "$SRC must have exactly one ExecStart line"
grep -qx "ExecStart=$SRC_PATH" "$SRC" || die "the ExecStart of $SRC is not $SRC_PATH"
[ "$(grep -c -F "$SRC_PATH" "$SRC" || true)" -eq 1 ] || die "$SRC names $SRC_PATH outside the ExecStart line, which the derivation would not rewrite"
grep -q 'libexec' "$SRC" && die "$SRC names a libexec path itself; the source holds the Arch path only"
for other in "$(dirname "$SRC")"/*.service; do
    [ "$other" != "$SRC" ] || continue
    ! grep -q '^ExecStart=' "$other" || die "$other is a second unit file; there is one unit source"
done

for fmt in deb rpm archlinux; do
    mkdir -p "$OUT/$fmt"
    case $fmt in
    archlinux) cp "$SRC" "$OUT/$fmt/custodio.service" ;;
    *) sed "s#^ExecStart=$SRC_PATH\$#ExecStart=$LIBEXEC_PATH#" "$SRC" > "$OUT/$fmt/custodio.service" ;;
    esac
done
