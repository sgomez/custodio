#!/usr/bin/python3 -I
"""Run `custodio import FILE` on a pseudo-terminal and type the password at the prompt (the CLI
reads it only from /dev/tty). Usage: import.py FILE ID PASSWORD"""
import os
import pty
import sys

file, key_id, password = sys.argv[1:4]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("custodio", ["custodio", "import", "--id", key_id, file])
buf = b""
while b":" not in buf:
    buf += os.read(fd, 1024)
os.write(fd, password.encode() + b"\n")
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
