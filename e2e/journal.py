#!/usr/bin/python3 -I
"""Journal checks of `just e2e` (SPEC acceptance 7 and 8). A pure function of its inputs, so that
journal-selftest.sh can feed it synthetic streams.

  journal.py entries --json F --ledger F --uid N [--unit U] [--expect-total N] [--forbid-pidless]
      F is `journalctl -o json` of the documented query; the ledger has one line per signature,
      "<outcome> <key id> <pid> <uid>". Exactly one entry per ledger line, matching it.
  journal.py sweep --export F --evidence DIR [--file P]... --password S
      F is `journalctl -u custodio.service -o export`. Fails when any secret appears in it, in any form.

A failure names the kind of needle and the form, never the bytes."""
import argparse
import base64
import hashlib
import json
import os
import sys

MESSAGE_ID = "29c3d30e6c4242406c6db3f120d36401"
OUTCOMES = {  # outcome -> (priority, start of MESSAGE)
    "signed": ("6", "signature made"),
    "denied": ("5", "signature denied"),
    "authorization_unavailable": ("4", "authorization unavailable, no signature"),
}
# DigestInfo prefixes of RFC 8017 section 9.2, by digest name.
DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
BIG = 4096  # larger files are searched by their first and last KIB bytes
KIB = 1024


def field(entry, name):
    value = entry.get(name)
    return value if isinstance(value, str) else None


def audit_entries(lines, unit, uid):
    """Entries of the unit, written by its user, with the audit MESSAGE_ID. The trusted fields are
    checked here as well, whatever query produced the stream."""
    found = []
    for line in lines:
        if not line.strip():
            continue
        entry = json.loads(line)
        if (field(entry, "_SYSTEMD_UNIT") == unit and field(entry, "_UID") == str(uid)
                and field(entry, "MESSAGE_ID") == MESSAGE_ID):
            found.append(entry)
    return found


def check_entries(entries, ledger, total=None, forbid_pidless=False):
    errors = []
    for number, line in enumerate(ledger, 1):
        outcome, key, pid, uid = line.split()
        label = f"ledger line {number} ({outcome} {key} pid {pid})"
        mine = [e for e in entries if field(e, "CUSTODIO_PID") == pid]
        if len(mine) != 1:
            errors.append(f"{label}: {len(mine)} journal entries, expected exactly 1")
            continue
        entry = mine[0]
        priority, text = OUTCOMES[outcome]
        want = {
            "CUSTODIO_KEY_ID": key,
            "CUSTODIO_UID": uid,
            "CUSTODIO_OUTCOME": outcome,
            "PRIORITY": priority,
            "MESSAGE": f"{text}: uid {uid} pid {pid} key {key}",
        }
        for name, expected in want.items():
            if field(entry, name) != expected:
                errors.append(f"{label}: {name} is {entry.get(name)!r}, expected {expected!r}")
    if total is not None and len(entries) != total:
        errors.append(f"{len(entries)} audit entries since the start, expected {total}")
    if forbid_pidless:
        pidless = [e for e in entries if field(e, "CUSTODIO_PID") is None]
        if pidless:
            errors.append(f"{len(pidless)} audit entries without CUSTODIO_PID")
    return errors


def der_ecdsa(data):
    """r and s of a DER ECDSA-Sig-Value, or None when data is not one."""
    try:
        if data[0] != 0x30:
            return None
        pos = 2
        if data[1] & 0x80:
            pos += data[1] & 0x7F
        ints = []
        for _ in range(2):
            if data[pos] != 0x02:
                return None
            size = data[pos + 1]
            if size & 0x80:
                return None
            ints.append(data[pos + 2:pos + 2 + size])
            pos += 2 + size
        return ints if pos == len(data) and all(ints) else None
    except IndexError:
        return None


def der_int(value):
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + bytes([len(value)]) + value


def signature_needles(data):
    """The other encoding of an ECDSA signature: r||s from DER, DER from r||s."""
    out = []
    parts = der_ecdsa(data)
    if parts:
        width = next(w for w in (32, 48, 66) if all(len(p.lstrip(b"\0")) <= w for p in parts))
        out.append(b"".join(p.lstrip(b"\0").rjust(width, b"\0") for p in parts))
    if len(data) in (64, 96, 132):
        half = len(data) // 2
        body = der_int(data[:half]) + der_int(data[half:])
        lead = bytes([len(body)]) if len(body) < 0x80 else b"\x81" + bytes([len(body)])
        out.append(b"\x30" + lead + body)
    return out


def needles(files, password):
    """(kind, bytes) for each secret: contents, digests, DigestInfo, other signature encodings."""
    out = [("import password", password.encode())]
    for path in files:
        with open(path, "rb") as f:
            data = f.read()
        name = os.path.basename(path)
        if len(data) > BIG:
            out += [(f"{name} head", data[:KIB]), (f"{name} tail", data[-KIB:])]
        elif data:
            out.append((name, data))
            out += [(f"{name} other signature encoding", s) for s in signature_needles(data)]
        for algo in DIGEST_INFO:
            digest = hashlib.new(algo, data).digest()
            out += [(f"{name} {algo} digest", digest), (f"{name} {algo} DigestInfo", DIGEST_INFO[algo] + digest)]
    return out


def b64_substrings(data):
    """Base64 text that is stable wherever data sits in a longer blob: the groups fully inside it
    at each of the three alignments."""
    out = {}
    for shift in (0, 2, 1):
        part = data[shift:]
        part = part[:len(part) - len(part) % 3]
        if len(part) >= 6:
            out[f"base64 inside, alignment {shift}"] = base64.b64encode(part)
            out[f"urlsafe base64 inside, alignment {shift}"] = base64.urlsafe_b64encode(part)
    return out


def forms(data):
    hexed = data.hex().encode()
    std = base64.b64encode(data)
    url = base64.urlsafe_b64encode(data)
    out = {
        "raw": data,
        "hex": hexed,
        "HEX": hexed.upper(),
        "colon hex": b":".join(hexed[i:i + 2] for i in range(0, len(hexed), 2)),
        "space hex": b" ".join(hexed[i:i + 2] for i in range(0, len(hexed), 2)),
        "base64": std,
        "base64 unpadded": std.rstrip(b"="),
        "urlsafe base64": url,
        "urlsafe base64 unpadded": url.rstrip(b"="),
        "byte list": b"[" + b", ".join(str(b).encode() for b in data) + b"]",
    }
    if len(data) >= 9:
        out.update(b64_substrings(data))
    return out


def sweep(stream, secrets):
    hits = []
    for kind, data in secrets:
        for form, text in forms(data).items():
            if text in stream:
                hits.append(f"{kind}: found as {form}")
    return hits


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    e = sub.add_parser("entries")
    e.add_argument("--json", required=True)
    e.add_argument("--ledger", required=True)
    e.add_argument("--uid", required=True)
    e.add_argument("--unit", default="custodio.service")
    e.add_argument("--expect-total", type=int)
    e.add_argument("--forbid-pidless", action="store_true")
    s = sub.add_parser("sweep")
    s.add_argument("--export", required=True)
    s.add_argument("--evidence", required=True)
    s.add_argument("--file", action="append", default=[])
    s.add_argument("--password", required=True)
    args = parser.parse_args()
    if args.command == "entries":
        with open(args.json, encoding="utf-8", errors="replace") as f:
            entries = audit_entries(f.read().splitlines(), args.unit, args.uid)
        with open(args.ledger, encoding="utf-8") as f:
            ledger = [line for line in f.read().splitlines() if line.strip()]
        problems = check_entries(entries, ledger, args.expect_total, args.forbid_pidless)
        what = "journal entries"
    else:
        files = [os.path.join(args.evidence, n) for n in sorted(os.listdir(args.evidence))]
        files += [p for p in args.file if os.path.isfile(p)]
        with open(args.export, "rb") as f:
            stream = f.read()
        problems = sweep(stream, needles(files, args.password))
        what = "secret leaks"
    for problem in problems:
        print(f"journal: {problem}", file=sys.stderr)
    if problems:
        sys.exit(1)
    print(f"journal: {what} ok")


if __name__ == "__main__":
    main()
