#!/usr/bin/python3 -I
"""Run `custodio delete ID` on a pseudo-terminal and type "yes" at the confirmation (the CLI asks only on a terminal). Usage: delete.py ID"""
import os
import pty
import sys

key_id = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("custodio", ["custodio", "delete", "--", key_id])
buf = b""
while b":" not in buf:
    buf += os.read(fd, 1024)
os.write(fd, b"yes\n")
while True:
    try:
        chunk = os.read(fd, 1024)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
_, status = os.waitpid(pid, 0)
sys.stdout.write(buf.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
