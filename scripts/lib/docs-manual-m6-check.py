#!/usr/bin/env python3
"""Checks of section 25 of docs/manual-acceptance.md (F186, M6 acceptance 19) for scripts/test-docs-manual-m6.sh.

  docs-manual-m6-check.py PAGE ROOT

Only section 25 is read (`## 25.` up to the next `## ` heading or the end). Its fenced blocks are `sh` (run here), `sh vm`
(needs the VM: counted and listed, never run) or `text` (the expected output of the `sh` block before it); another info
string fails. What it runs, in an empty directory:

  * every `sh` block that is not a server, a client or a journal block, one `bash -e` each; a `text` block after it is compared with
    its output;
  * the keys' types are read with `openssl pkey -text` (RSA 2048, prime256v1);
  * the page's `openssl s_server` block, once per `openssl s_client` line of the page, with these substitutions and no others:
    `-accept 4433` becomes `-accept 127.0.0.1:0` (the port is read from the server's ACCEPT line) and `localhost:4433` in the
    client line becomes `127.0.0.1:<that port>`. The server's own output judges the run, never the exit status of `s_client`:
    a certificate that the page's CA signed must show `verify return:1` for its subject and no `verify error`, no certificate must show
    `peer did not return a certificate`. A client certificate of another CA (made here with the page's commands, with the
    names `rsa2048` replaced by `wrongca`) must be refused too;
  * the journal block statically: the match arguments are exactly the unit, the service's uid, the sign operation and the
    full Firefox label (as one argument, equal to the label that custodiod accepts and that docs/audit.md names), every
    `CUSTODIO_` name exists in docs/audit.md, the pid is printed; and it is parsed by `journalctl --directory <empty>` with
    `custodio` replaced by the current user in `id -u custodio` (the only substitution);
  * the result table at the end: every row has the step, expected and result columns.
"""

import os
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import docs_check as dc  # noqa: E402

LABEL = "snap.firefox.firefox (enforce)"


def blocks_of(text):
    """[(info, body lines, first body line)] of the fenced blocks, which sit inside list items (indented fences)."""
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        m = re.match(r"^(\s*)```(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, info, start, body = len(m.group(1)), m.group(2).strip(), i + 2, []
        i += 1
        while i < len(lines) and not re.match(r"^\s*```\s*$", lines[i]):
            body.append(lines[i][indent:])
            i += 1
        i += 1
        out.append((info, body, start))
    return out


def fail(errors, msg):
    errors.append(msg)


def section25(page):
    text = dc.read(page)
    m = re.search(r"^## 25\. .*$", text, re.M)
    if not m:
        return None
    rest = text[m.start():]
    n = re.search(r"^## ", rest[3:], re.M)
    return rest if not n else rest[: n.start() + 3]


def sh(cmd, cwd, timeout=60):
    return subprocess.run(["bash", "-ec", cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL)


def run_exchange(server_cmd, client_cmd, cwd, errors):
    """Start the page's server (substituted), wait for its ACCEPT line, run the client line (substituted); returns the server's output."""
    server = server_cmd.replace("-accept 4433", "-accept 127.0.0.1:0")
    if server == server_cmd:
        fail(errors, "the server block has no `-accept 4433` for the test to replace")
        return None
    proc = subprocess.Popen(["bash", "-c", "exec " + server], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, stdin=subprocess.DEVNULL)
    out, port, deadline = "", None, time.monotonic() + 20
    try:
        while port is None and time.monotonic() < deadline:
            # raw reads: select() does not see lines a buffered readline() already pulled in, so ACCEPT could be missed
            if select.select([proc.stdout], [], [], 0.2)[0]:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                out += chunk.decode(errors="replace")
                m = re.search(r"^ACCEPT 127\.0\.0\.1:(\d+)", out, re.M)
                port = m.group(1) if m else None
        if port is None:
            fail(errors, f"the server did not print ACCEPT: {out[-300:]!r}")
            return None
        client = client_cmd.replace("localhost:4433", f"127.0.0.1:{port}")
        if client == client_cmd:
            fail(errors, "a client line has no `localhost:4433` for the test to replace")
        try:
            subprocess.run(["bash", "-c", client], cwd=cwd, capture_output=True, timeout=30, check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            fail(errors, "a client did not finish in 30 s")
    finally:
        proc.terminate()
    try:
        rest, _ = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        rest, _ = proc.communicate()
    return out + (rest or "")


def journal(block, root, errors, tmp):
    text = " ".join(line.rstrip("\\").strip() for line in block)
    m = re.match(r"journalctl\s+(.*)$", text)
    if not m:
        return fail(errors, "the journal block does not start with `journalctl`")
    args = shlex.split(m.group(1).replace("$(id -u custodio)", "UIDOFCUSTODIO"))
    matches = [a for a in args if not a.startswith("-") and "=" in a]
    options = [a for a in args if a.startswith("-") or "=" not in a]
    want = ["_SYSTEMD_UNIT=custodio.service", "_UID=UIDOFCUSTODIO", "CUSTODIO_OPERATION=sign", f"CUSTODIO_PEER_LABEL={LABEL}"]
    # the label is the one the code accepts and the document names
    code = dc.read(os.path.join(root, "crates/custodiod/src/peer_label.rs"))
    audit = dc.read(os.path.join(root, "docs/audit.md"))
    if LABEL not in code or LABEL not in audit:
        fail(errors, f"the label {LABEL!r} is not in peer_label.rs and docs/audit.md")
    if sorted(matches) != sorted(want):
        fail(errors, f"the journal matches are {matches}, they must be exactly {want}")
    fields = set(re.findall(r"CUSTODIO_[A-Z_]+", text))
    known = set(re.findall(r"^\| `(CUSTODIO_[A-Z_]+)` \|", audit, re.M))
    for f in sorted(fields - known):
        fail(errors, f"the field {f} is not in the fields table of docs/audit.md")
    out_fields = [o for o in options if o.startswith("--output-fields=")]
    if not out_fields or "CUSTODIO_PID" not in out_fields[0].split("=", 1)[1].split(","):
        fail(errors, "the query does not print CUSTODIO_PID with --output-fields")
    # syntax: journalctl parses the matches (an empty directory has no entries)
    jdir = os.path.join(tmp, "journal")
    os.makedirs(jdir, exist_ok=True)
    cmd = "journalctl --directory=" + shlex.quote(jdir) + " " + m.group(1).replace("$(id -u custodio)", "$(id -u)")
    r = sh(cmd, tmp)
    if r.returncode != 0:
        fail(errors, f"journalctl rejects the query: {r.stderr.strip()[-200:]}")


def table(sec, errors):
    lines = [ln for ln in sec.rstrip().split("\n")]
    last = []
    for ln in reversed(lines):
        if ln.startswith("|"):
            last.append(ln)
        else:
            break
    rows = list(reversed(last))
    if len(rows) < 4:
        return fail(errors, "the section does not end with the result table")
    for ln in rows:
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) != 4:
            fail(errors, f"the table row {ln[:60]!r} has {len(cells)} columns, it needs 4 (#, step, expected, result)")
        elif ln is not rows[0] and not set(ln) <= set("|- ") and (not cells[1] or not cells[2]):
            fail(errors, f"the table row {ln[:60]!r} has no step or no expected value")


def main(argv):
    page, root = argv[1], argv[2]
    errors = []
    sec = section25(page)
    if sec is None:
        print("no section '## 25.'", file=sys.stderr)
        return 1
    blocks = blocks_of(sec)
    vm = []
    for info, body, line in blocks:
        if info not in ("sh", "sh vm", "text"):
            fail(errors, f"section 25: a block with info string {info!r}: use `sh`, `sh vm` or `text`")
        if info == "sh vm":
            vm.append(body[0] if body else "")
    tmp = tempfile.mkdtemp(prefix="m6-")
    work = os.path.join(tmp, "work")
    os.makedirs(work)
    server = None
    clients = []
    jblock = None
    for i, (info, body, line) in enumerate(blocks):
        if info != "sh":
            continue
        text = "\n".join(body)
        if "openssl s_server" in text:
            server = text.replace("\\\n", " ")
        elif "openssl s_client" in text:
            clients += [ln for ln in body if "openssl s_client" in ln]
        elif text.startswith("journalctl"):
            jblock = body
        else:
            r = sh(text, work)
            if r.returncode != 0:
                fail(errors, f"section 25 line {line}: the block exited {r.returncode}: {r.stderr.strip()[-200:]}")
                continue
            nxt = blocks[i + 1] if i + 1 < len(blocks) else None
            if nxt and nxt[0] == "text":
                got = [x.rstrip() for x in r.stdout.strip().split("\n")]
                if got != [x.rstrip() for x in nxt[1]]:
                    fail(errors, f"section 25 line {line}: the block printed {got!r}, the page shows {nxt[1]!r}")
    # the keys' types, read here as well as by the page's own block
    if os.path.exists(os.path.join(work, "rsa2048.key")):
        for key, want in (("rsa2048.key", "(2048 bit"), ("p256.key", "prime256v1")):
            r = sh(f"openssl pkey -in {key} -noout -text", work)
            if want not in r.stdout:
                fail(errors, f"{key} is not of the type the page says ({want}): {r.stdout.splitlines()[:1]}")
    else:
        fail(errors, "the page's first block did not make rsa2048.key")
    if jblock is None:
        fail(errors, "the section has no journalctl block")
    else:
        journal(jblock, root, errors, tmp)
    if server is None or len(clients) < 3:
        fail(errors, "the section needs the s_server block and three s_client lines (RSA, P-256, none)")
    elif not errors:
        # a client certificate of another CA, made with the page's commands
        sh("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out wrongca.key && "
           "openssl req -new -x509 -key wrongca.key -subj '/CN=Other CA' -days 2 -out wrongca.crt && "
           "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out wrong.key && "
           "openssl req -new -key wrong.key -subj '/CN=Custodio test wrong' -out wrong.csr && "
           "openssl x509 -req -in wrong.csr -CA wrongca.crt -CAkey wrongca.key -CAcreateserial -days 2 -out wrong.crt", work)
        cases = []
        for c in clients:
            if "-cert rsa2048.crt" in c:
                cases.append(("rsa2048", c))
                cases.append(("wrong CA", c.replace("rsa2048", "wrong")))
            elif "-cert p256.crt" in c:
                cases.append(("p256", c))
            elif "-cert" not in c:
                cases.append(("none", c))
        for need in ("rsa2048", "p256", "none"):
            if need not in [k for k, _ in cases]:
                fail(errors, f"the section has no s_client line for the case '{need}'")
        for kind, c in cases:
            out = run_exchange(server, c, work, errors)
            if out is None:
                continue
            if kind in ("rsa2048", "p256"):
                if f"depth=0 CN=Custodio test {kind}\nverify return:1" not in out or "verify error" in out or "peer did not return" in out:
                    fail(errors, f"the server did not accept the {kind} client certificate: {out[-300:]!r}")
            elif kind == "none":
                if "peer did not return a certificate" not in out:
                    fail(errors, f"the server accepted a client with no certificate: {out[-300:]!r}")
            elif "verify error" not in out or "certificate verify failed" not in out:
                fail(errors, f"the server accepted a client certificate of another CA: {out[-300:]!r}")
    table(sec, errors)
    print(f"section 25: {len(vm)} `sh vm` block(s), never run: " + "; ".join(v[:50] for v in vm))
    for e in errors:
        print(e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
