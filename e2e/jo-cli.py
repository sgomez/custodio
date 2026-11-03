#!/usr/bin/python3 -I
"""Run the CLI on a pseudo-terminal for the journal-ops-* cases (F94), like import.py and delete.py, and write the pid of the CLI process to PIDFILE first:
the pid the bus reports as the caller is that of the process that made the call, which is this child (exec keeps the pid).
Usage: jo-cli.py PIDFILE import FILE ID PASSWORD | jo-cli.py PIDFILE delete ID. Prints the terminal output; exits with the status of the CLI."""
import os
import pty
import sys

pidfile, what, *rest = sys.argv[1:]
if what == "import" and len(rest) == 3:
    argv, answer = ["custodio", "import", "--id", rest[1], rest[0]], rest[2]
elif what == "delete" and len(rest) == 1:
    argv, answer = ["custodio", "delete", "--", rest[0]], "yes"
else:
    sys.exit("usage: jo-cli.py PIDFILE import FILE ID PASSWORD | delete ID")
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
with open(pidfile, "w", encoding="ascii") as f:
    f.write(f"{pid}\n")
buf = b""
while b":" not in buf:
    buf += os.read(fd, 1024)
os.write(fd, answer.encode() + b"\n")
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
