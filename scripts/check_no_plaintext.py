"""Searches every regular file under a directory for secret byte strings and their text encodings (run by check-no-plaintext.sh).

usage: check_no_plaintext.py STATE_DIR SECRETS_DIR
Every file in SECRETS_DIR is one secret. Prints the path of each state file that contains one (never the secret). Exit 0:
none; 1: a match; 2: unusable input or an unreadable file.
"""
import base64
import os
import sys

MIN_LEN = 16
WHITESPACE = b" \t\r\n"


def patterns(secret):
    """(raw patterns, text patterns) for one secret."""
    raw = [secret]
    text = []
    for hexed in (secret.hex(), secret.hex().upper()):
        text.append(hexed.encode())
        text.append(":".join(hexed[i : i + 2] for i in range(0, len(hexed), 2)).encode())
    for alt in (None, b"-_"):
        for pad, skip in ((0, 0), (1, 2), (2, 3)):
            enc = base64.b64encode(b"\0" * pad + secret)
            if alt:
                enc = enc.translate(bytes.maketrans(b"+/", alt))
            # The first characters hold the prefix bytes, the last group may depend on bytes after the secret.
            text.append(enc[skip:-4].rstrip(b"="))
    return raw, text


def main():
    state, secrets_dir = sys.argv[1:3]
    raw, text = [], []
    for name in sorted(os.listdir(secrets_dir)):
        with open(os.path.join(secrets_dir, name), "rb") as f:
            secret = f.read()
        if len(secret) < MIN_LEN:
            print(f"check-no-plaintext: derived value {name} is too short to search", file=sys.stderr)
            return 2
        r, t = patterns(secret)
        raw += r
        text += t
    drop_ws = bytes.maketrans(b"", b"")
    found = []
    for root, dirs, files in os.walk(state, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
            views = [data, data.translate(drop_ws, WHITESPACE), data.translate(drop_ws, WHITESPACE + b":")]
            if any(p in data for p in raw) or any(p in v for p in text for v in views):
                found.append(path)
    for path in found:
        print(path)
    return 1 if found else 0


try:
    sys.exit(main())
except OSError as err:
    print(f"check-no-plaintext: {err}", file=sys.stderr)
    sys.exit(2)
