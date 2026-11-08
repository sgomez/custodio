#!/usr/bin/python3 -I
"""The channel into the VM guest: its serial console on a unix socket (docs/findings/F151.md).

    chan.py SOCKET wait [--timeout S] [--pid-file F]     wait until the guest answers at a shell (logs in if needed)
    chan.py SOCKET run [--timeout S] [--pid-file F] CMD  run CMD (a shell string) in the guest; its output (stdout and stderr
                                                         together) goes to stdout, its exit code is ours; 124 on timeout
    chan.py SOCKET poweroff [--timeout S] [--pid-file F] ask the guest to power off (`sudo systemctl poweroff`) and wait for the console to close
    chan.py SOCKET put LOCAL REMOTE                      copy a file into the guest, byte for byte
    chan.py SOCKET get REMOTE LOCAL                      copy a file out of the guest, byte for byte

The account is VM_USER / VM_PASSWORD from the environment (vm.sh sets them from its seed). Exit codes: 0, the command's own, 124 timeout,
2 usage, 3 the guest or its QEMU is gone, 4 a transfer failed. Standard library only. Nothing is installed in the guest: it uses the
login shell, `base64` and `wc` from coreutils.
"""

import base64
import os
import re
import secrets
import select
import shlex
import socket
import sys
import time

USER = os.environ.get("VM_USER", "ubuntu")
PASSWORD = os.environ.get("VM_PASSWORD", "")
CHUNK = 1536  # raw bytes per typed line: 2048 base64 characters, well under the tty's 4095-byte line limit
BATCH = 24  # lines sent before one sentinel is awaited


class Gone(Exception):
    pass


class Timeout(Exception):
    pass


def alive(pid_file):
    if not pid_file:
        return True
    try:
        pid = int(open(pid_file).read().split()[0])
        os.kill(pid, 0)
        return True
    except (OSError, ValueError, IndexError):
        return False


class Chan:
    def __init__(self, path, pid_file=None):
        self.path = path
        self.pid_file = pid_file
        self.sock = None
        self.buf = b""

    def connect(self, deadline):
        while True:
            if not alive(self.pid_file):
                raise Gone("QEMU is not running")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(self.path)
                self.sock = s
                return
            except OSError:
                s.close()
            if time.monotonic() >= deadline:
                raise Timeout("cannot connect to the serial socket")
            time.sleep(0.05)

    def send(self, data):
        self.sock.setblocking(True)
        self.sock.sendall(data)

    def pump(self, until, wait=0.5):
        """Reads for up to `wait` seconds into the buffer; returns False when the peer closed."""
        r, _, _ = select.select([self.sock], [], [], min(wait, max(until, 0)))
        if not r:
            return True
        try:
            d = self.sock.recv(1 << 16)
        except OSError:
            d = b""
        if not d:
            return False
        self.buf += d
        return True

    def expect(self, regex, deadline, poke=None):
        """Waits for `regex` (bytes pattern) in the buffer; returns the match and drops everything up to its end."""
        rx = re.compile(regex)
        last_poke = time.monotonic()
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            now = time.monotonic()
            if now >= deadline:
                raise Timeout("timeout")
            if not alive(self.pid_file):
                raise Gone("QEMU is not running")
            if poke and now - last_poke > 2:
                self.send(poke)
                last_poke = now
            if not self.pump(deadline - now):
                raise Gone("the serial connection closed")

    # --- the shell ---

    def sync(self, deadline):
        """Gets to a quiet shell: logs in if the console asks, switches echo, the prompt and bracketed paste off. Returns when ready."""
        self.connect(deadline)
        self.send(b"\n")
        last_poke = time.monotonic()
        token = None
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise Timeout("the guest did not show a login prompt or a shell")
            if not alive(self.pid_file):
                raise Gone("QEMU is not running")
            tail = self.buf[-200:]
            if token is not None:
                m = re.search(b"SYNC_" + token + b"\r?\n", self.buf)
                if m:
                    self.buf = b""
                    return
            if re.search(rb"login: ?$", tail):
                self.buf = b""
                token = None
                self.send(USER.encode() + b"\n")
                last_poke = now
            elif re.search(rb"[Pp]assword: ?$", tail):
                self.buf = b""
                self.send(PASSWORD.encode() + b"\n")
                last_poke = now
            elif token is None and re.search(rb"[#$>] ?$", tail):
                token = secrets.token_hex(6).encode()
                self.buf = b""
                # The typed line is echoed until `stty -echo` runs, so the token is split in the text: only the output matches.
                line = (
                    "stty -echo -onlcr 2>/dev/null; PS1='<<P>> '; unset PS0 PROMPT_COMMAND; "
                    "bind 'set enable-bracketed-paste off' 2>/dev/null; echo SYNC_\"\"" + token.decode() + "\n"
                )
                self.send(line.encode())
                last_poke = now
            elif now - last_poke > 2:
                if token is not None:
                    token = None  # the line was lost (a console message cut it): try again at the next prompt
                self.send(b"\n")
                last_poke = now
            if not self.pump(deadline - now):
                raise Gone("the serial connection closed")

    def interrupt(self):
        try:
            self.send(b"\x03\n")
        except OSError:
            pass

    def run_out(self, cmd, timeout):
        """Runs `cmd` (a shell string; stdin is /dev/null, stderr joins stdout); returns (output bytes, exit code).
        The output sits between two lines that hold a token chosen for this call, so a prompt that arrives late and any text
        that looks like a sentinel in the output change nothing; one newline before the end token is the sentinel's own."""
        deadline = time.monotonic() + timeout
        t = secrets.token_hex(8)
        b64 = base64.b64encode(cmd.encode()).decode()
        line = (
            "printf '__BEG_" + t + "__\\n'; ( eval \"$(printf %s '" + b64 + "' | base64 -d)\" ) < /dev/null 2>&1; "
            "printf '\\n__END_" + t + "__%s\\n' $?\n"
        )
        self.buf = b""
        self.send(line.encode())
        rx = re.compile(rb"__BEG_" + t.encode() + rb"__\n(.*?)\n__END_" + t.encode() + rb"__(\d+)\n", re.S)
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m.group(1), int(m.group(2))
            now = time.monotonic()
            if now >= deadline:
                self.interrupt()
                raise Timeout("timeout")
            if not alive(self.pid_file):
                raise Gone("QEMU is not running")
            if not self.pump(deadline - now):
                raise Gone("the serial connection closed")


def usage():
    sys.stderr.write(__doc__)
    sys.exit(2)


def main(argv):
    if len(argv) < 3:
        usage()
    sock, op, rest = argv[1], argv[2], argv[3:]
    timeout = 120.0
    pid_file = None
    while rest and rest[0] in ("--timeout", "--pid-file") and len(rest) >= 2:
        if rest[0] == "--timeout":
            timeout = float(rest[1])
        else:
            pid_file = rest[1]
        rest = rest[2:]
    ch = Chan(sock, pid_file)
    try:
        start = time.monotonic()
        if op == "wait" and not rest:
            ch.sync(start + timeout)
            return 0
        if op == "run" and len(rest) == 1:
            ch.sync(start + min(timeout, 60))
            out, rc = ch.run_out(rest[0], max(timeout - (time.monotonic() - start), 1))
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()
            return rc
        if op == "poweroff" and not rest:
            ch.sync(start + min(timeout, 60))
            ch.send(b"sudo systemctl poweroff\n")
            while ch.pump(start + timeout - time.monotonic(), 0.5):  # ends when QEMU closes the console
                ch.buf = b""
                if time.monotonic() >= start + timeout:
                    raise Timeout("the console stayed open")
            return 0
        if op == "put" and len(rest) == 2:
            return put(ch, rest[0], rest[1], timeout)
        if op == "get" and len(rest) == 2:
            return get(ch, rest[0], rest[1], timeout)
        usage()
    except Timeout as e:
        sys.stderr.write("chan.py: %s after %gs\n" % (e, timeout))
        return 124
    except Gone as e:
        sys.stderr.write("chan.py: %s\n" % e)
        return 3
    finally:
        if ch.sock:
            ch.sock.close()
    return 2


def put(ch, local, remote, timeout):
    start = time.monotonic()
    ch.sync(start + min(timeout, 60))
    q = shlex.quote(remote)
    _, rc = ch.run_out(": > " + q, 30)
    if rc:
        sys.stderr.write("chan.py: cannot create %s in the guest\n" % remote)
        return 4
    size = 0
    with open(local, "rb") as f:
        while True:
            lines = []
            for _ in range(BATCH):
                d = f.read(CHUNK)
                if not d:
                    break
                size += len(d)
                lines.append("printf %s '" + base64.b64encode(d).decode() + "' | base64 -d >> " + q)
            if not lines:
                break
            _, rc = ch.run_out("\n".join(lines), max(timeout - (time.monotonic() - start), 1))
            if rc:
                sys.stderr.write("chan.py: writing %s in the guest failed (%d)\n" % (remote, rc))
                return 4
    out, rc = ch.run_out("wc -c < " + q, 30)
    if rc or out.strip() != str(size).encode():
        sys.stderr.write("chan.py: %s has %r bytes in the guest, sent %d\n" % (remote, out.strip(), size))
        return 4
    return 0


def get(ch, remote, local, timeout):
    start = time.monotonic()
    ch.sync(start + min(timeout, 60))
    out, rc = ch.run_out("base64 -w0 < " + shlex.quote(remote), max(timeout - (time.monotonic() - start), 1))
    if rc:
        sys.stderr.write("chan.py: cannot read %s in the guest\n" % remote)
        return 4
    try:
        data = base64.b64decode(out.strip(), validate=True)
    except ValueError:
        sys.stderr.write("chan.py: the guest's answer for %s is not base64\n" % remote)
        return 4
    with open(local, "wb") as f:
        f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
