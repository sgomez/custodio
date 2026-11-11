#!/usr/bin/env python3
"""Checks section 24 of docs/manual-acceptance.md (M5 acceptance 17, F165) by running what it says.

Usage: python3 -I docs-manual-m5-check.py PAGE FIXTURE_DIR ROOT
PAGE is the page (the real one or a broken copy), FIXTURE_DIR holds the credentials of e2e/vm/mkcreds.sh, ROOT is the
repository (the reader, the request vector of the service's unit test). Only section 24 is read. Exit 0 when every check holds,
1 with one line per failure on stderr.
"""
import base64
import json
import os
import re
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import threading

page_path, fixdir, root = sys.argv[1:4]
fails = []


def bad(msg):
    fails.append(msg)


def section(text):
    m = re.search(r"^## 24\. .*?(?=^## |\Z)", text, re.S | re.M)
    return m.group(0) if m else None


def blocks(sec):
    """Fenced blocks as (lang, text), in order; the fence indent is removed."""
    out = []
    for m in re.finditer(r"^( *)```(\w*)\n(.*?)^\1```$", sec, re.S | re.M):
        ind = len(m.group(1))
        out.append((m.group(2), "".join(l[ind:] if l.strip() else l for l in m.group(3).splitlines(True))))
    return out


def find(bl, lang, needle, after=-1):
    for i, (l, t) in enumerate(bl):
        if i > after and l == lang and needle in t:
            return i
    return None


def to_binary(path):
    data = open(path, "rb").read()
    if all(b in set(string.printable.encode()) for b in data):
        return base64.b64decode(b"".join(data.split()), validate=True)
    return data


def sh(cmd, cwd, timeout=20):
    p = subprocess.run(["bash", "-c", "set -e\n" + cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


text = open(page_path).read()
sec = section(text)
if sec is None:
    print("no section 24", file=sys.stderr)
    sys.exit(1)
bl = blocks(sec)
work = tempfile.mkdtemp(prefix="m5doc.")
os.symlink(os.path.join(root, "e2e"), os.path.join(work, "e2e"))


def put_cred(name_or_bytes):
    data = to_binary(os.path.join(fixdir, name_or_bytes)) if isinstance(name_or_bytes, str) else name_or_bytes
    with open(os.path.join(work, "pcr.cred"), "w") as f:
        f.write(base64.b64encode(data).decode())


# ---- step 1: has-tpm2
i_has = find(bl, "sh", "systemd-analyze has-tpm2")
if i_has is None:
    bad("step 1: no systemd-analyze has-tpm2 command")
else:
    pr = subprocess.run(["bash", "-c", bl[i_has][1]], cwd=work, capture_output=True, text=True, timeout=20)
    rc, out, err = pr.returncode, pr.stdout, pr.stderr
    real = [l for l in out.splitlines() if not l.startswith("exit status")]
    i_q = find(bl, "text", "libtss2", i_has)
    quote = None if i_q is None else [l for l in bl[i_q][1].splitlines() if not l.startswith("exit status")]
    if rc != 0 or not real:
        bad("step 1: the has-tpm2 command printed nothing (rc %d): %s" % (rc, err.strip()))
    elif quote is None:
        bad("step 1: no quoted output of full support naming libtss2-rc")
    else:
        flag = re.compile(r"^[+-](firmware|driver|system|subsystem|libraries)$|^  [+-]libtss2-[a-z]+\.so\.\d+$")
        if real[0] not in ("yes", "partial", "no") or not all(flag.match(l) for l in real[1:]):
            bad("step 1: the real has-tpm2 output has another format: %r" % real)
        key = lambda ls: [re.sub(r"^( *)[+-]", r"\1", l) for l in ls[1:]]
        if key(real) != key(quote):
            bad("step 1: the quoted lines and the real ones differ in their keys")
        if quote[0] != "yes" or any(l.lstrip()[:1] == "-" for l in quote[1:]) or "  +libtss2-rc.so.0" not in quote:
            bad("step 1: the quote is not full support with libtss2-rc.so.0")
    if not re.search(r"first line is not `yes`.{0,200}?stop the run", sec, re.S):
        bad("step 1: the page does not stop the run on less than full support")
    if "libtss2-rc" not in sec.split("2. Seal")[0]:
        bad("step 1: libtss2-rc is not named")

# ---- step 2: the Varlink call against a stub socket, then the extraction
i_seal = find(bl, "sh", "varlinkctl call")
i_ext = None if i_seal is None else find(bl, "sh", "sed -n", i_seal)
recorded = {}
if i_seal is None or i_ext is None:
    bad("step 2: no varlinkctl call, or no command that extracts the blob")
else:
    seal = bl[i_seal][1]
    sock = os.path.join(work, "s.sock")
    if "unix:/run/systemd/io.systemd.Credentials" not in seal:
        bad("step 2: the call is not on /run/systemd/io.systemd.Credentials")
    seal = seal.replace("/run/systemd/io.systemd.Credentials", sock)
    scoped_bin = to_binary(os.path.join(fixdir, "scoped"))
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(sock)
    srv.listen(1)
    srv.settimeout(0.1)
    done = threading.Event()

    def serve():
        try:
            while True:
                try:
                    c, _ = srv.accept()
                    break
                except socket.timeout:
                    if done.is_set():
                        return
            c.settimeout(10)
            buf = b""
            while not buf.endswith(b"\0"):
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            recorded["req"] = buf
            reply = {"parameters": {"blob": base64.b64encode(scoped_bin).decode()}}
            c.sendall(json.dumps(reply).encode() + b"\0")
            c.close()
        except OSError:
            pass

    t = threading.Thread(target=serve)
    t.start()
    rc, out, err = sh(seal, work)
    done.set()
    t.join()
    srv.close()
    if rc != 0:
        bad("step 2: the call failed (rc %d): %s" % (rc, err.strip()[:200]))
    req = recorded.get("req")
    if req is None:
        bad("step 2: the call never reached the socket")
    else:
        # the request the service builds for name k and data foo (the vector of the unit test)
        src = open(os.path.join(root, "crates/custodiod/src/creds/systemd/tests.rs")).read()
        m = re.search(r'br#"(\{"method":"io\.systemd\.Credentials\.Encrypt".*?\})"#', src)
        got = json.loads(req.rstrip(b"\0"))
        if m is None:
            bad("step 2: the service's request vector is not in tests.rs")
        elif got != json.loads(m.group(1)):
            bad("step 2: request %s differs from the service's %s" % (got, m.group(1)))
        p = got.get("parameters", {})
        if "withKey" in p or p.get("scope") != "user" or base64.b64decode(p.get("data", "")) != b"foo":
            bad("step 2: the request has withKey, a scope other than user, or bad data")
    rc, out, err = sh(bl[i_ext][1], work)
    if rc != 0:
        bad("step 2: the blob extraction failed (rc %d)" % rc)
    elif not os.path.exists(os.path.join(work, "pcr.cred")) or os.path.getsize(os.path.join(work, "pcr.cred")) == 0:
        bad("step 2: no pcr.cred")
    else:
        i_rd = find(bl, "sh", "credread.py", i_ext)
        if i_rd is None:
            bad("step 3: no reader command")
        else:
            rc, out, err = sh(bl[i_rd][1], work)
            if rc != 0 or out.strip() != "host+tpm2-scoped mask 0x0":
                bad("seal to read: the reader printed %r (rc %d), expected host+tpm2-scoped mask 0x0" % (out, rc))

# ---- step 3 and 4: the reader on every fixture, judged by the page's table
i_rd = find(bl, "sh", "credread.py")
i_hand = find(bl, "sh", "python3 -I -c")
rows = []
for m in re.finditer(r"^ *\| (.+?) \| (.+?) \|$", sec, re.M):
    rows.append((m.group(1).replace("`", ""), m.group(2).replace("`", "")))
table = {}
for a, b in rows:
    if re.fullmatch(r"[0-9a-f]{32}", b):
        continue
    if a.startswith("host+tpm2-scoped mask") and "other" in a:
        table["other"] = b
    elif a.startswith("anything else"):
        table["else"] = b
    else:
        table[a] = b


def judge(line):
    if line in table:
        return table[line]
    if re.fullmatch(r"host\+tpm2-scoped mask 0x[0-9a-f]+", line) and "other" in table:
        return table["other"]
    return table.get("else")


ids = {a: b for a, b in rows if re.fullmatch(r"[0-9a-f]{32}", b)}
if i_rd is None:
    bad("step 3: no reader command")
else:
    reader = bl[i_rd][1]
    scoped = to_binary(os.path.join(fixdir, "scoped"))
    other_mask = scoped[:48] + (1).to_bytes(8, "little") + scoped[56:]
    unknown = bytes(16) + scoped[16:]
    cases = [("scoped-pcr7", "PCR 7 confirmed", 0), ("scoped", "PCR 7 refuted", 0), (other_mask, "recorded as found", 0),
             ("host-scoped", "invalid reading", 0), ("null", "invalid reading", 0), ("host", "invalid reading", 0),
             ("tpm2", "invalid reading", 0), ("host-tpm2", "invalid reading", 0), (unknown, "invalid reading", 1)]
    for src, want, want_rc in cases:
        put_cred(src)
        r = subprocess.run(["bash", "-c", reader], cwd=work, capture_output=True, text=True, timeout=20)
        line = r.stdout.strip()
        label = src if isinstance(src, str) else line
        got = judge(line)
        if r.returncode != want_rc or got is None or want not in got:
            bad("table: %s: reader printed %r (rc %d), the page says %r, expected %r" % (label, line, r.returncode, got, want))
    # the documented equivalent equals the reader
    if i_hand is None:
        bad("step 3: no hand-read command")
    else:
        for name in ("scoped", "scoped-pcr7", "host-scoped"):
            put_cred(name)
            r = subprocess.run(["bash", "-c", reader], cwd=work, capture_output=True, text=True, timeout=20)
            h = subprocess.run(["bash", "-c", "set -e\n" + bl[i_hand][1]], cwd=work, capture_output=True, text=True, timeout=20)
            m = re.fullmatch(r"id ([0-9a-f]{32})( mask (0x[0-9a-f]+))?", h.stdout.strip())
            names = {v: k for k, v in ids.items()}
            if h.returncode != 0 or m is None or m.group(1) not in names:
                bad("hand read: %s: output %r (rc %d)" % (name, h.stdout, h.returncode))
                continue
            expect = names[m.group(1)] + (" mask " + m.group(3) if m.group(3) else "")
            if expect != r.stdout.strip():
                bad("hand read: %s: %r but the reader printed %r" % (name, expect, r.stdout.strip()))

# ---- step 5: the record
i5 = sec.find("5. Record in")
rec = sec[i5:] if i5 >= 0 else ""
for what, rx in [("date", r"\bdate\b"), ("machine", r"\bmachine\b"), ("systemd version", r"systemd version"),
                 ("hardware or virtual", r"hardware or virtual"), ("has-tpm2", r"has-tpm2"), ("identifier", r"identifier"),
                 ("mask", r"PCR mask"), ("confirmed", r"PCR 7 confirmed"), ("refuted", r"refuted"),
                 ("F166.md", r"docs/findings/F166\.md")]:
    if not re.search(rx, rec):
        bad("record: the page does not name the " + what)
if "unverified" not in sec:
    bad("the page does not say it is unverified")

shutil.rmtree(work, ignore_errors=True)
for f in fails:
    print("test-docs-manual-m5: " + f, file=sys.stderr)
sys.exit(1 if fails else 0)
