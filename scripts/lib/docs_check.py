#!/usr/bin/env python3
"""Shared checks of the user documents (README.md, docs/threat-model.md, SECURITY.md) for the F185 script tests.

  docs_check.py kinds DOC                  every fenced block has an info string the tests know (`console`, `bash`)
  docs_check.py links DOC [REQUIRED...]    every relative link resolves to a file, and a #anchor to a heading of it;
                                           each REQUIRED path (relative to the repository root) is linked
  docs_check.py run DOC BASEDIR            run every `console` block (see below)

`console` blocks are run; a `bash` block is never run (the document keeps those to what no test can exercise); any other
info string, or none, fails, so nothing is skipped silently. In a run `$ COMMAND` lines (with `\\` continuations) execute
in one bash per block, and the lines after a command are its standard output, compared with what it printed. The only attribute after `console` is
`fails=yes` (the last command of the block must exit non-zero). The rest comes from the caller's environment:
  DOCS_PASSWORD  typed at a password prompt on /dev/tty (`custodio import` reads it there, not from stdin)
  DOCS_ANSWER    typed at the confirmation prompt of `custodio delete`
  DOCS_HOME_SHOWN  the home directory the document shows; the real $HOME in the output is rewritten to it
  DOCS_CHECK     a program run after each block as `$DOCS_CHECK 'FIRST COMMAND OF THE BLOCK'`; non-zero fails
Only standard output is compared: standard error (the full-disk warning, which depends on the host) is not.
The environment of the block (HOME, PATH, the bus address ...) is the caller's. The commands run in BASEDIR and run with a pseudo-terminal as the controlling terminal: standard output stays a pipe.
"""

import os
import pty
import re
import select
import subprocess
import sys
import threading
import fcntl
import termios

KNOWN = ("console", "bash")
ROOT = os.getcwd()


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def blocks(text):
    """[(info string, body lines, first body line number)] of the fenced blocks; an unclosed fence is an error."""
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        m = re.match(r"```(.*)$", lines[i])
        if not m:
            i += 1
            continue
        info, start, body = m.group(1).strip(), i + 2, []
        i += 1
        while i < len(lines) and not lines[i].startswith("```"):
            body.append(lines[i])
            i += 1
        if i >= len(lines):
            raise ValueError(f"line {start - 1}: a fenced block is never closed")
        i += 1
        out.append((info, body, start))
    return out


def prose(text):
    """The text outside fenced blocks and inline code spans."""
    out, fence = [], False
    for line in text.split("\n"):
        if line.startswith("```"):
            fence = not fence
            continue
        if not fence:
            out.append(re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


def slug(heading):
    """GitHub's anchor of a heading: lower case, punctuation dropped, spaces to hyphens."""
    s = re.sub(r"`", "", heading.strip().lower())
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def anchors(path):
    seen, out, fence = {}, set(), False
    for line in read(path).split("\n"):
        if line.startswith("```"):
            fence = not fence
        m = None if fence else re.match(r"#{1,6} +(.*?) *#*$", line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
    return out


def links(doc):
    """[(target, line number)] of the inline links `[text](target)` outside code."""
    found, fence = [], False
    for n, line in enumerate(read(doc).split("\n"), 1):
        if line.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        for m in re.finditer(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", re.sub(r"`[^`]*`", "", line)):
            found.append((m.group(1), n))
    return found


def check_kinds(doc):
    bad, bash = [], 0
    try:
        found = blocks(read(doc))
    except ValueError as e:
        return [str(e)], 0
    for info, _, line in found:
        word = info.split()[0] if info else ""
        if word not in KNOWN:
            bad.append(f"{doc}:{line}: a fenced block with info string {info!r}: use `console` (run by the test) or `bash` (never run)")
        elif word == "bash":
            bash += 1
    return bad, bash


def check_links(doc, required):
    bad, base, resolved = [], os.path.dirname(os.path.abspath(doc)), set()
    for target, line in links(doc):
        if re.match(r"[a-z][a-z0-9+.-]*:", target):  # https:, mailto: ...: not fetched
            continue
        path, _, frag = target.partition("#")
        dest = os.path.normpath(os.path.join(base, path)) if path else os.path.abspath(doc)
        if not os.path.isfile(dest):
            bad.append(f"{doc}:{line}: the link {target!r} does not resolve to a file")
            continue
        resolved.add(dest)
        if frag and frag not in anchors(dest):
            bad.append(f"{doc}:{line}: the link {target!r} names a heading that {os.path.relpath(dest, ROOT)} does not have")
    for req in required:
        if os.path.abspath(req) not in resolved:
            bad.append(f"{doc}: it does not link {req}")
    return bad


def commands(body):
    """[[command text, [expected lines]]] of a console block."""
    cmds = []
    for line in body:
        if line.startswith("$ "):
            cmds.append([line[2:], []])
        elif cmds and cmds[-1][0].endswith("\\") and not cmds[-1][1]:
            cmds[-1][0] += "\n" + line
        elif cmds:
            cmds[-1][1].append(line)
        elif line.strip():
            raise ValueError("text before the first `$ ` command")
    return cmds


def drive_terminal(master, password, answer, stop):
    """Types the answers on the pseudo-terminal when its prompts appear (the prompt of `import` is `Password for ...: `)."""
    seen = b""
    while not stop.is_set():
        ready, _, _ = select.select([master], [], [], 0.1)
        if not ready:
            continue
        try:
            data = os.read(master, 4096)
        except OSError:
            return
        if not data:
            return
        seen += data
        if re.search(rb"[Pp]assword[^\n]*: $", seen) and password is not None:
            os.write(master, password.encode() + b"\n")
            seen = b""
        elif re.search(rb"cancel: $", seen) and answer is not None:
            os.write(master, answer.encode() + b"\n")
            seen = b""


def run_block(cmds, attrs, env, cwd):
    """Run the commands of one block in one bash; [(output, rc)] per command."""
    script = ""
    for i, (cmd, _) in enumerate(cmds):
        script += f"{cmd}\nprintf '\\n@@END {i} %d\\n' \"$?\"\n"
    master, slave = pty.openpty()

    def own_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    stop = threading.Event()
    thread = threading.Thread(target=drive_terminal, args=(master, os.environ.get("DOCS_PASSWORD"), os.environ.get("DOCS_ANSWER"), stop))
    thread.start()
    try:
        proc = subprocess.run(["bash", "-c", script], env=env, cwd=cwd, capture_output=True, text=True, timeout=120,
                              check=False, stdin=subprocess.DEVNULL, preexec_fn=own_terminal)  # noqa: PLW1509
    finally:
        stop.set()
        thread.join()
        os.close(master)
        os.close(slave)
    parts = re.split(r"\n@@END (\d+) (\d+)\n", proc.stdout)
    return [(parts[k], int(parts[k + 2]), proc.stderr) for k in range(0, len(parts) - 2, 3)]


def run_doc(doc, cwd):
    """Run the console blocks of DOC; returns (failures, number of blocks run). Each block is followed by
    `$DOCS_CHECK 'FIRST COMMAND'`, which must exit 0 (the effect of the commands: the caller knows where to look)."""
    bad, ran = [], 0
    env = dict(os.environ)
    for info, body, line in blocks(read(doc)):
        words = info.split()
        if not words or words[0] != "console":
            continue
        attrs = dict(w.split("=", 1) for w in words[1:])
        try:
            cmds = commands(body)
        except ValueError as e:
            bad.append(f"{doc}:{line}: {e}")
            continue
        if not cmds:
            bad.append(f"{doc}:{line}: a console block with no command")
            continue
        results = run_block(cmds, attrs, env, cwd)
        ran += 1
        if len(results) != len(cmds):
            bad.append(f"{doc}:{line}: the commands did not all run")
            continue
        home = os.environ.get("HOME", "")
        for i, ((cmd, expected), (out, rc, err)) in enumerate(zip(cmds, results)):
            shown = cmd.split("\n")[0][:70]
            if os.environ.get("DOCS_HOME_SHOWN") and home:
                out = out.replace(home, os.environ["DOCS_HOME_SHOWN"])
            actual = out.split("\n") if out else []
            if actual and actual[-1] == "":
                actual.pop()
            want = list(expected)
            while want and want[-1] == "":
                want.pop()
            last = i == len(cmds) - 1
            if last and attrs.get("fails") == "yes":
                if rc == 0:
                    bad.append(f"{doc}:{line}: `{shown}` should fail")
            elif rc != 0:
                bad.append(f"{doc}:{line}: `{shown}` exited {rc}: {err[-300:]!r}")
            if actual != want:
                bad.append(f"{doc}:{line}: `{shown}` printed {actual!r}, the document shows {want!r}")
        print(f"{'FAIL' if any(b.startswith(f'{doc}:{line}:') for b in bad) else 'ok  '} {doc}:{line} ({len(cmds)} commands)")
        if os.environ.get("DOCS_CHECK"):
            first = cmds[0][0].split("\n")[0]
            if subprocess.run([os.environ["DOCS_CHECK"], first], env=env, cwd=cwd, check=False).returncode != 0:
                bad.append(f"{doc}:{line}: the effect check after `{first}` failed")
    return bad, ran


def main(argv):
    if len(argv) >= 3 and argv[1] == "kinds":
        bad, bash = check_kinds(argv[2])
        print(f"{argv[2]}: {bash} bash block(s), never run")
    elif len(argv) >= 3 and argv[1] == "links":
        bad = check_links(argv[2], argv[3:])
    elif len(argv) == 4 and argv[1] == "run":
        bad, ran = run_doc(argv[2], argv[3])
        if not ran:
            print(f"{argv[2]}: no console block", file=sys.stderr)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for b in bad:
        print(b, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
