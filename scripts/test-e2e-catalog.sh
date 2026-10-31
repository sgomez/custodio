#!/usr/bin/env bash
# F59: the journal catalog check of the e2e suite (`journal.py catalog`, the function the guest case calls), on captured `journalctl -x`
# text, with no container engine. Also: e2e/catalog-text.txt (the explanation the guest matches, since only /e2e is mounted there) is the
# body of BOTH entries of data/custodio.catalog (the unmarked one that C/POSIX locales show, and the one marked `en`).
# NOT checked here: that a booted system registers the catalog and shows it; that is the real run of `just e2e <target>`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-e2e-catalog: $*" >&2; fail=1; }
EXPECT=$ROOT/e2e/catalog-text.txt
check() { python3 -I "$ROOT/e2e/journal.py" catalog --text "$1" --expect "${2:-$EXPECT}"; }

# --- the text matched is the body of every entry of the catalog
python3 -I - "$ROOT/data/custodio.catalog" "$EXPECT" "$tmp" <<'PY' || bad "cannot split the catalog"
import os, sys
catalog, expect, out = sys.argv[1:4]
bodies, cur, header = [], None, False
for line in open(catalog, encoding="utf-8").read().splitlines():
    if line.startswith("#") and cur is None:
        continue
    if line.startswith("-- "):
        cur = []
        bodies.append(cur)
        header = True
        continue
    if cur is None:
        continue
    if header and line.strip() == "":
        header = False
        continue
    if not header:
        cur.append(line)
want = [l for l in open(expect, encoding="utf-8").read().splitlines() if l.strip()]
if len(bodies) < 1:
    sys.exit("no entry in the catalog")
for i, body in enumerate(bodies):
    got = [l for l in body if l.strip()]
    if got != want:
        sys.exit(f"entry {i + 1} of the catalog differs from e2e/catalog-text.txt")
open(os.path.join(out, "bodies"), "w").write(str(len(bodies)))
PY
[ "$(cat "$tmp/bodies" 2> /dev/null)" = 2 ] || bad "expected two entries (unmarked and en) in data/custodio.catalog"
# control: a change to only one entry is caught
sed '0,/^identifies this kind of entry\./s//identifies this kind of entry (changed)./' "$ROOT/data/custodio.catalog" > "$tmp/changed.catalog"
if cmp -s "$tmp/changed.catalog" "$ROOT/data/custodio.catalog"; then bad "control: the catalog copy was not changed"; fi

# --- fixtures of journalctl -x
entry='Oct 31 10:00:00 host custodiod[321]: signature made: uid 1000 pid 99 key rsa1'
{
    echo "$entry"
    echo "░░ Subject: Custodio signing request handled"
    echo "░░ Defined-By: custodio"
    echo "░░"
    while IFS= read -r l; do echo "░░ $l"; done < "$EXPECT"
} > "$tmp/with-catalog.utf8"
sed -e 's/^░░ \?/-- /' -e 's/^-- $/--/' "$tmp/with-catalog.utf8" | sed '1s/^-- //' > "$tmp/with-catalog.c"
printf '%s\n' "$entry" > "$tmp/no-catalog"
{ echo "$entry"; echo "░░ Subject: Custodio signing request handled"; head -n 1 "$EXPECT" | sed 's/^/░░ /'; } > "$tmp/partial"
printf '%s\n' '-- No entries --' > "$tmp/no-entry"
# the text mentions custodiod, but is not an entry
{ echo "Oct 31 10:00:00 host systemd[1]: Started something."; while IFS= read -r l; do echo "░░ $l"; done < "$EXPECT"; } > "$tmp/text-without-entry"
: > "$tmp/empty"

check "$tmp/with-catalog.utf8" > /dev/null 2>&1 || bad "the explanation (UTF-8 markers) was rejected"
check "$tmp/with-catalog.c" > /dev/null 2>&1 || bad "the explanation (C locale markers) was rejected"
if out=$(check "$tmp/no-catalog" 2>&1); then bad "an entry without the explanation was accepted"; else grep -qi 'catalog' <<< "$out" || bad "the rejection does not name the catalog: $out"; fi
check "$tmp/partial" > /dev/null 2>&1 && bad "an entry with one line of the explanation was accepted"
if out=$(check "$tmp/no-entry" 2>&1); then bad "no entry was accepted"; else grep -qi 'no custodiod entry' <<< "$out" || bad "the rejection does not say there is no entry: $out"; fi
check "$tmp/text-without-entry" > /dev/null 2>&1 && bad "explanation text without an entry was accepted"
check "$tmp/empty" > /dev/null 2>&1 && bad "empty output was accepted"
: > "$tmp/noexpect"
check "$tmp/with-catalog.utf8" "$tmp/noexpect" > /dev/null 2>&1 && bad "an empty expected text was accepted"

# --- wiring: the guest case calls the same subcommand; the case is listed
grep -q 'journal.py" catalog' "$ROOT/e2e/journal-check.sh" || bad "journal-check.sh does not call journal.py catalog"
grep -q 'journalctl -x' "$ROOT/e2e/journal-check.sh" || bad "journal-check.sh does not run journalctl -x"
grep -q 'case_run "journal-catalog"' "$ROOT/e2e/journal-check.sh" || bad "journal-check.sh does not report journal-catalog"
grep -qx 'journal-catalog' "$ROOT/e2e/cases.list" || bad "journal-catalog is not in e2e/cases.list"
if grep -rn 'update-catalog' "$ROOT/e2e" | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' | grep -q .; then bad "the e2e suite registers the catalog itself"; fi

exit "$fail"
