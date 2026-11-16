#!/usr/bin/python3 -I
"""Drives one authentication on a pseudo-terminal and writes its events (F200). Usage: fingerprint-pty.py EVENTS PLAN KILL_AFTER MONITOR -- CMD...
EVENTS: the file of `SECONDS NAME [DETAIL]` lines the judge (fingerprint.py) reads; the line `0 start` is written first. PLAN: JSON {"prompt-finger": [ACTION...],
"prompt-password": [ACTION...]}; the Nth prompt of a kind takes the Nth ACTION: "touch:ID" (a scan on the virtual sensor), "type:TEXT" (typed-wrong when it starts with
`wrong`, else typed-right), "none". KILL_AFTER: seconds after which the process is killed (event `killed`); 0 = no limit besides 120. MONITOR: a file written by
`busctl monitor` of fprintd; its `verify-match` / `verify-no-match` become `matched` / `nomatch`. The output of the process is copied to EVENTS.out (no secret: the
typed text is never echoed into it). Exit status: the process's, 255 when killed."""
import json
import os
import pty
import re
import select
import signal
import socket
import sys
import time

SOCK = "/run/fpvirt/sock"


def main():
    events_path, plan, kill_after, monitor = sys.argv[1], json.loads(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
    cmd = sys.argv[6:]
    t0 = time.monotonic()
    ev = open(events_path, "w", buffering=1)
    out = open(events_path + ".out", "w", buffering=1)

    def emit(name, detail=""):
        ev.write(f"{time.monotonic() - t0:.1f} {name}{(' ' + detail) if detail else ''}\n")

    emit("start")
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    buf, used, seen_mon = "", 0, 0
    counts = {"prompt-finger": 0, "prompt-password": 0}
    deadline = t0 + (kill_after if kill_after else 120)
    status = None
    while True:
        # fprintd's verdicts
        try:
            m = open(monitor, errors="replace").read()
        except OSError:
            m = ""
        for mm in re.finditer(r"verify-(no-match|match)", m[seen_mon:]):
            emit("nomatch" if mm[1] == "no-match" else "matched")
        seen_mon = len(m)
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                data = os.read(fd, 4096).decode(errors="replace")
            except OSError:
                data = ""
            if data:
                out.write(data)
                buf += data
        pend = buf[used:]
        for pat, name in ((r"(?i)(place|swipe|scan)[^\n]*finger|finger[^\n]*(reader|sensor)", "prompt-finger"),
                          (r"(?i)password[^\n]*: ?$|password: ?", "prompt-password")):
            mm = re.search(pat, pend)
            if mm and name == "prompt-password" and re.search(r"(?i)finger", pend[: mm.start()] + mm[0]) and False:
                continue
            if mm:
                used += mm.end()
                emit(name)
                acts = plan.get(name, [])
                act = acts[counts[name]] if counts[name] < len(acts) else "none"
                counts[name] += 1
                if act.startswith("touch:"):
                    s = socket.socket(socket.AF_UNIX)
                    s.connect(SOCK)
                    s.sendall(f"SCAN {act[6:]}\n".encode())
                    s.shutdown(socket.SHUT_WR)
                    s.close()
                    emit("scan", act[6:])
                elif act.startswith("type:"):
                    emit("typed-wrong" if act[5:].startswith("wrong") else "typed-right")
                    os.write(fd, (act[5:] + "\n").encode())
                break
        if re.search(r"(?i)sorry, try again|authentication failure|incorrect password", buf[used:]):
            used = len(buf)
            emit("refused")
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            emit("killed")
            return 255
    rc = os.waitstatus_to_exitcode(status)
    if rc == 0:
        emit("approved")
    return rc


sys.exit(main())
