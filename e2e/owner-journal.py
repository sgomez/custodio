#!/usr/bin/python3 -I
"""The journal side of the owner-* cases (F91). Reads the output of `journalctl -o json` (one object per line, oldest first).
  owner-journal.py seen --json FILE TAG...                 exit 0 when every TAG is the MESSAGE of some entry
  owner-journal.py count --json FILE --before TAG --after TAG --unit UNIT
                                                           prints how many entries of UNIT lie between the entry with MESSAGE TAG
                                                           (before) and the one with MESSAGE TAG (after), in the order of the file
A marker that is missing, or found twice, or an "after" that comes before the "before", is an error (exit 2), never a count of 0."""
import argparse
import json
import sys


def entries(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def position(rows, tag):
    found = [i for i, e in enumerate(rows) if e.get("MESSAGE") == tag]
    if len(found) != 1:
        sys.exit(f"owner-journal: the marker {tag!r} is in the journal {len(found)} times, expected once")
    return found[0]


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    seen = sub.add_parser("seen")
    seen.add_argument("--json", required=True)
    seen.add_argument("tags", nargs="+")
    count = sub.add_parser("count")
    count.add_argument("--json", required=True)
    count.add_argument("--before", required=True)
    count.add_argument("--after", required=True)
    count.add_argument("--unit", required=True)
    args = parser.parse_args()
    rows = entries(args.json)
    if args.cmd == "seen":
        have = {e.get("MESSAGE") for e in rows if isinstance(e.get("MESSAGE"), str)}
        missing = [t for t in args.tags if t not in have]
        if missing:
            print("owner-journal: not (yet) in the journal: " + " ".join(missing), file=sys.stderr)
            return 1
        return 0
    start, end = position(rows, args.before), position(rows, args.after)
    if end < start:
        sys.exit("owner-journal: the 'after' marker comes before the 'before' marker")
    print(sum(1 for e in rows[start + 1:end] if e.get("_SYSTEMD_UNIT") == args.unit))
    return 0


sys.exit(main())
