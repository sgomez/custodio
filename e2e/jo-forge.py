#!/usr/bin/python3 -I
"""Write one journal entry with the given fields through journald's native socket (F94): root can set any field, so this is what "any process can write an entry
with the same MESSAGE_ID and CUSTODIO_* fields" (docs/audit.md, "Not guaranteed") looks like. Usage: jo-forge.py FIELD=VALUE... (values on one line)."""
import socket
import sys

if len(sys.argv) < 2 or any("=" not in a or "\n" in a for a in sys.argv[1:]):
    sys.exit("usage: jo-forge.py FIELD=VALUE...")
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
    s.connect("/run/systemd/journal/socket")
    s.send("".join(f"{a}\n" for a in sys.argv[1:]).encode())
