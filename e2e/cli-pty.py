#!/usr/bin/python3 -I
"""Run a command on a pseudo-terminal and answer its prompts (F97). Usage:
cli-pty.py TRANSCRIPT EVENTS COUNT-FILE [--repeat REGEX=TEXT] STEP... -- CMD ARG...
STEP is `expect=REGEX` (wait until the output since the last step matches) or `send=TEXT` (TEXT with \\n for a newline). After the steps, `--repeat`
answers every further match of REGEX with TEXT until the command ends. The output goes to TRANSCRIPT; EVENTS gets one line per expect,
"expect<TAB>REGEX<TAB>requests=N", N being the lines of COUNT-FILE when the match was seen (the polkit requests the test agent logged so far; "requests=-" with
no such file). The exit status of this script is that of the command (124 if a prompt did not come within 60 s)."""
import os
import pty
import re
import select
import sys
import time


def main():
    transcript, events, count_file = sys.argv[1:4]
    rest = sys.argv[4:]
    sep = rest.index("--")
    steps, cmd = rest[:sep], rest[sep + 1:]
    repeat = None
    if steps[:1] == ["--repeat"]:
        pat, _, text = steps[1].partition("=")
        repeat = (re.compile(pat.encode()), text.encode().decode("unicode_escape").encode())
        steps = steps[2:]

    def count():
        try:
            with open(count_file) as f:
                return f"requests={len(f.readlines())}"
        except OSError:
            return "requests=-"

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    out = bytearray()
    mark = 0
    log = open(events, "w")

    def pump(deadline):
        r, _, _ = select.select([fd], [], [], max(0.0, deadline - time.time()))
        if not r:
            return None
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return b""
        return chunk

    status = None
    for step in steps:
        kind, _, arg = step.partition("=")
        if kind == "send":
            os.write(fd, arg.encode().decode("unicode_escape").encode())
            continue
        pat = re.compile(arg.encode())
        deadline = time.time() + 60
        while not pat.search(bytes(out[mark:])):
            chunk = pump(deadline)
            if chunk is None or chunk == b"":
                status = 124 if chunk is None else None
                break
            out += chunk
        else:
            log.write(f"expect\t{arg}\t{count()}\n")
            log.flush()
            mark = len(out)
            continue
        log.write(f"missing\t{arg}\t{count()}\n")
        break
    end = time.time() + 60
    resent = 0
    while status != 124:
        # Under load the answer to a repeated prompt can be lost (the terminal flushes input when the agent switches echo off), so a prompt left
        # unanswered for 15 s is answered again (at most 3 times); the repeat text is a wrong password, so a second answer proves nothing false.
        chunk = pump(min(end, time.time() + 15) if repeat else end)
        if chunk is None and repeat and time.time() < end and resent < 3 and repeat[0].search(bytes(out[max(0, len(out) - 200):])):
            resent += 1
            log.write(f"resend\t{repeat[0].pattern.decode()}\t{count()}\n")
            log.flush()
            os.write(fd, repeat[1])
            continue
        if chunk is None:
            status = 124
            break
        if chunk == b"":
            break
        out += chunk
        if repeat and repeat[0].search(bytes(out[mark:])):
            log.write(f"expect\t{repeat[0].pattern.decode()}\t{count()}\n")
            log.flush()
            os.write(fd, repeat[1])
            mark = len(out)
    if status == 124:
        os.kill(pid, 9)
    _, st = os.waitpid(pid, 0)
    with open(transcript, "wb") as f:
        f.write(bytes(out))
    log.close()
    sys.exit(status if status == 124 else os.waitstatus_to_exitcode(st) % 256)


main()
