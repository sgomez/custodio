#!/usr/bin/env python3
"""Checks of docs/api.md for scripts/test-docs-api.sh (F98).

  docs_api_run.py static DOC                        what the document must state (no service needed)
  docs_api_run.py run DOC BUS_ADDRESS WORKDIR SERVER_BIN
                                                    runs every `console` example of the document in order

An example is a fenced block whose info string is `console` followed by attributes:
  op=NAME       the operation (ListKeys, ImportP12, ReplaceCertificate, Sign, DeleteKey) the block shows
  polkit=MODE   approve | deny | unreachable: the fake polkit's answer for the block
  action=A,B    the polkit actions the service must have asked for, in order (absent: none)
  fails=yes     the last command must fail (a bus error, not one of the service), and print what the document shows
  error=NAME    the last command must fail with the message the document gives for the error NAME
  server=absent no service runs on the bus (detection of a missing service)
Lines `$ COMMAND` (with `\\` continuations) are run by bash in one shell per block, with `busctl --system`
pointed at the private bus and nothing else changed; the lines after a command are its stdout+stderr.
"""

import os
import re
import subprocess
import sys

OPS = ["ListKeys", "ImportP12", "ReplaceCertificate", "Sign", "DeleteKey"]
OP_ACTION = {
    "ImportP12": "com.rfirma.custodio.import-certificate",
    "DeleteKey": "com.rfirma.custodio.delete-certificate",
    "ReplaceCertificate": "com.rfirma.custodio.replace-certificate",
    "Sign": "com.rfirma.custodio.sign",
}
TRIGGERED = ["PolkitDenied", "NoSuchKey", "KeyIdTaken", "InvalidArgs", "CertificateMismatch",
             "WrongPasswordOrBadP12", "AuthorizationUnavailable"]
ERROR_PREFIX = "com.rfirma.Custodio1.Error."
BUS_NAME = "com.rfirma.Custodio1"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def section(text, heading_re):
    """The heading line that matches, up to the next heading of the same or a higher level."""
    out, level, fence = [], 0, False
    for line in text.split("\n"):
        if line.startswith("```"):
            fence = not fence
        m = None if fence else re.match(r"(#+) ", line)
        if m:
            lvl = len(m.group(1))
            if level and lvl <= level:
                level = 0
            if not level and re.search(heading_re, line):
                level = lvl
        if level:
            out.append(line)
    return "\n".join(out)


def squash(text):
    return re.sub(r"\s+", " ", text)


def error_items(doc):
    """name -> text of the `- error` list item of the document."""
    items, cur = {}, None
    for line in doc.split("\n"):
        m = re.match(r"- error `" + re.escape(ERROR_PREFIX) + r"(\w+)`:(.*)", line)
        if m:
            cur = m.group(1)
            items[cur] = m.group(2)
        elif cur and line.startswith("  ") and line.strip():
            items[cur] += " " + line.strip()
        else:
            cur = None
    return items


def messages(doc):
    """name -> the message busctl shows for it, as the document states it (Message `text`)."""
    out = {}
    for name, text in error_items(doc).items():
        m = re.search(r"Message `([^`]+)`", text)
        if m:
            out[name] = m.group(1)
    return out


class Example:
    def __init__(self, attrs, commands, line):
        self.attrs, self.commands, self.line = attrs, commands, line  # commands: [(text, [expected lines])]


def examples(doc):
    found, lines, i = [], doc.split("\n"), 0
    while i < len(lines):
        m = re.match(r"```console(?: (.*))?$", lines[i])
        if not m:
            i += 1
            continue
        attrs = dict(a.split("=", 1) for a in (m.group(1) or "").split())
        start, body, i = i + 1, [], i + 1
        while i < len(lines) and not lines[i].startswith("```"):
            body.append(lines[i])
            i += 1
        i += 1
        commands = []
        for line in body:
            if line.startswith("$ "):
                commands.append([line[2:], []])
            elif commands and commands[-1][0].endswith("\\") and not commands[-1][1]:
                commands[-1][0] += "\n" + line
            elif commands:
                commands[-1][1].append(line)
        found.append(Example(attrs, commands, start))
    return found


def doc_error_message(msg_by_name, name):
    return "Call failed: " + msg_by_name[name] if name in msg_by_name else None


# --- static checks -------------------------------------------------------------------------------

def static(doc_path):
    doc, bad = read(doc_path), []
    audit = read("docs/audit.md")
    findings = read("docs/findings.md")
    f68 = section(findings, r"^## F68")
    errs = error_items(doc)
    msgs = messages(doc)

    # Detection.
    det = squash(section(doc, r"^#+ Detect"))
    if not det:
        bad.append("no detection section")
    for need, what in [(r"--system-talk-name=com\.rfirma\.Custodio1", "the --system-talk-name=com.rfirma.Custodio1 permission"),
                       (r"(?i)not installed", "the situation: service absent"),
                       (r"(?i)not activatable", "the situation: not activatable"),
                       (r"(?i)blocked by the sandbox", "the situation: blocked by the sandbox"),
                       (r"NameHasOwner", "NameHasOwner"), (r"ListActivatableNames", "ListActivatableNames"),
                       (r"StartServiceByName", "StartServiceByName")]:
        if det and not re.search(need, det):
            bad.append(f"detection section lacks {what}")
    if det and not re.search(r"(?i)treat any error|any error from .{0,30}as not activatable", det):
        bad.append("detection section lacks the rule: any error of StartServiceByName means not activatable")
    if det and not re.search(r"(?i)do not (rely|branch)[^.]*(one|which) error name", det):
        bad.append("detection section lacks the sentence: do not rely on one error name")
    if det and not re.search(r"(?i)(absent|not installed)[^.]*blocked[^.]*(look the same|indistinguishable)", det):
        bad.append("detection section lacks the sentence: absent and blocked look the same through the proxy")
    if not f68 or "Detection:" not in f68:
        bad.append("docs/findings.md has no F68 Detection line")
    for tok in set(re.findall(r"`([A-Za-z0-9_.]+)`", det)):
        if re.search(r"[A-Z]", tok) and tok not in f68:  # error names, methods and bus names must be the ones of F68
            bad.append(f"detection section quotes `{tok}`, which docs/findings.md F68 does not")
    detection_line = next((l for l in f68.split("\n") if l.startswith("Detection:")), "")
    for tok in ("NameHasOwner", "ListActivatableNames", "StartServiceByName"):
        if tok not in detection_line:
            bad.append(f"F68 Detection line lacks {tok}")

    # Errors: a "when" sentence and the message of every name; the message is a string of the service.
    src = read("crates/custodiod/src/error.rs")
    if not errs:
        bad.append("no `- error` lines")
    for name, text in errs.items():
        when = re.sub(r"Message `[^`]*`\.?", "", text).strip()
        if len(when) < 20:
            bad.append(f"error {name} has no explanation of when it occurs")
        if name not in msgs:
            bad.append(f"error {name} has no Message `...`")
        elif f'"{msgs[name]}"' not in src:
            bad.append(f"error {name}: message `{msgs[name]}` is not a message of crates/custodiod/src/error.rs")
    if len(set(msgs.values())) != len(msgs):
        bad.append("two errors share a message, so busctl cannot tell them apart")

    # Ownership.
    own = squash(section(doc, r"^#+ Ownership"))
    if not own:
        bad.append("no Ownership section")
    else:
        for need, what in [(r"(?i)another user", "another user's id"), (r"NoSuchKey", "NoSuchKey"),
                           (r"(?i)no method takes an owner", "that no method takes an owner"),
                           (r"(?i)bus.{0,40}uid|uid.{0,40}bus", "that the owner is the uid the bus reports")]:
            if not re.search(need, own):
                bad.append(f"ownership section lacks {what}")

    # Dialogs: the table row of every method.
    pol = section(doc, r"^#+ Polkit actions")
    for op in OPS:
        row = next((l for l in pol.split("\n") if l.startswith("|") and f"`{op}`" in l), None)
        if row is None:
            bad.append(f"polkit table has no row for {op}")
        elif op == "ListKeys":
            if "no dialog" not in row.lower() or "com.rfirma" in row:
                bad.append("polkit table: ListKeys must show no action and 'no dialog'")
        elif f"`{OP_ACTION[op]}`" not in row or "dialog" not in row.lower() or "no dialog" in row.lower():
            bad.append(f"polkit table: row of {op} lacks its action {OP_ACTION[op]} or the dialog")

    # Journal.
    jr = section(doc, r"^#+ .*[Jj]ournal")
    if not jr:
        bad.append("no journal section")
    else:
        for need in ("sign", "import", "delete", "replace_certificate", "CUSTODIO_APP_ID", "audit.md"):
            if need not in jr:
                bad.append(f"journal section lacks {need}")
    for field in set(re.findall(r"CUSTODIO_[A-Z_]+", doc)):
        if f"`{field}`" not in audit:
            bad.append(f"{field} is not a field of docs/audit.md")

    # Hashing and the compatibility rule.
    hs = squash(section(doc, r"^#+ Hashing"))
    if not re.search(r"(?i)client", hs) or not re.search(r"(?i)never hash|does not hash", hs):
        bad.append("no 'Hashing stays in the client' section that says the service does not hash")
    if "audit.md#compatibility-rule" not in doc:
        bad.append("no link to audit.md#compatibility-rule")
    if not re.search(r"^## Compatibility rule$", audit, re.M):
        bad.append("docs/audit.md has no 'Compatibility rule' heading")

    # Examples exist for every operation, and the errors are triggered.
    ex = examples(doc)
    for op in OPS:
        if not any(e.attrs.get("op") == op and any(op in c[0] for c in e.commands) for e in ex):
            bad.append(f"no example whose command calls {op}")
    for name in TRIGGERED:
        if not any(e.attrs.get("error") == name for e in ex):
            bad.append(f"no example triggers {name}")
    if not any(e.attrs.get("server") == "absent" for e in ex):
        bad.append("no detection example without a service")
    for e in ex:
        if "server" in e.attrs and e.attrs["server"] != "absent":
            bad.append(f"line {e.line}: unknown server attribute")
        if e.attrs.get("op") in OP_ACTION and e.attrs.get("polkit") in ("approve", "deny", "unreachable") \
                and e.attrs.get("error") not in ("InvalidArgs", "NoSuchKey", "KeyIdTaken"):
            if e.attrs.get("action") != OP_ACTION[e.attrs["op"]]:
                bad.append(f"line {e.line}: an example of {e.attrs['op']} that reaches polkit must name its action")
    return bad


# --- running ---------------------------------------------------------------------------------------

def match_line(expected, actual):
    """Exact match, except the named placeholders <DER> and <BYTES:n> and their stated rules."""
    parts = re.split(r"(<DER>|<BYTES:\d+>)", expected)
    if len(parts) == 1:
        return expected == actual
    pattern = "".join(
        re.escape(p) if i % 2 == 0 else r"(\d+)((?: \d+)+)" for i, p in enumerate(parts))
    m = re.fullmatch(pattern, actual)
    if not m:
        return False
    for k, ph in enumerate(parts[1::2]):
        n, rest = int(m.group(2 * k + 1)), [int(b) for b in m.group(2 * k + 2).split()]
        if len(rest) != n or any(b > 255 for b in rest):
            return False
        if ph == "<DER>" and rest[:2] != [48, 130]:  # a DER certificate: SEQUENCE with a two-byte length
            return False
        if ph.startswith("<BYTES:") and n != int(ph[7:-1]):
            return False
    return True


PRELUDE = r'''exec 2>&1
cd "$WORKDIR"
busctl() { if [ "${1:-}" = --system ]; then shift; command busctl --address="$ADDRESS" "$@"; else command busctl "$@"; fi; }
'''


def run_block(ex, env, msgs):
    fails = []
    script = PRELUDE
    for i, (cmd, _) in enumerate(ex.commands):
        script += f"{cmd}\nprintf '\\n@@END {i} %d\\n' \"$?\"\n"
    proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=120, check=False)
    parts = re.split(r"\n@@END (\d+) (\d+)\n", proc.stdout)
    # parts: out0, i0, rc0, out1, i1, rc1, ..., ""
    results = [(parts[k], int(parts[k + 2])) for k in range(0, len(parts) - 2, 3)]
    if len(results) != len(ex.commands):
        return [f"line {ex.line}: the commands did not all run: {proc.stdout[-300:]!r}"]
    err = ex.attrs.get("error")
    for i, ((cmd, expected), (out, rc)) in enumerate(zip(ex.commands, results)):
        shown = cmd.split("\n")[0][:70]
        actual = out.split("\n") if out else []
        if actual and actual[-1] == "":
            actual.pop()
        exp = list(expected)
        while exp and exp[-1] == "":
            exp.pop()
        last = i == len(ex.commands) - 1
        if err and last:
            want = doc_error_message(msgs, err)
            if rc == 0:
                fails.append(f"line {ex.line}: `{shown}` should fail as {err}")
            if want is None or exp != [want]:
                fails.append(f"line {ex.line}: the documented result of the failing call is {exp!r}, not {want!r} (the message of {err})")
        elif last and ex.attrs.get("fails") == "yes":
            if rc == 0:
                fails.append(f"line {ex.line}: `{shown}` should fail")
        elif rc != 0:
            fails.append(f"line {ex.line}: `{shown}` exited {rc}: {out[-200:]!r}")
        if len(actual) != len(exp) or not all(match_line(e, a) for e, a in zip(exp, actual)):
            fails.append(f"line {ex.line}: `{shown}` printed {actual!r}, the document says {exp!r}")
    return fails


def run(doc_path, address, workdir, server_bin):
    doc = read(doc_path)
    msgs = messages(doc)
    ctl = os.path.join(workdir, "ctl")
    os.makedirs(ctl, exist_ok=True)
    state = os.path.join(workdir, "state")
    os.makedirs(state, mode=0o700, exist_ok=True)
    work = os.path.join(workdir, "work")
    os.makedirs(work, exist_ok=True)
    env = dict(os.environ, ADDRESS=address, WORKDIR=work)
    server, fails, ran = None, [], 0
    exs = examples(doc)
    seen_server = False
    try:
        for ex in exs:
            absent = ex.attrs.get("server") == "absent"
            if absent and seen_server:
                fails.append(f"line {ex.line}: an example without a service must come before the first one with it")
                continue
            if not absent and server is None:
                server = subprocess.Popen([server_bin, address, state, ctl], stdout=subprocess.PIPE, text=True)
                if server.stdout.readline().strip() != "ready":
                    return ["the test server did not start"]
                seen_server = True
            mode = ex.attrs.get("polkit", "approve")
            with open(os.path.join(ctl, "mode"), "w", encoding="utf-8") as f:
                f.write(mode)
            asked_path = os.path.join(ctl, "asked")
            if os.path.exists(asked_path):
                os.remove(asked_path)
            got = run_block(ex, env, msgs)
            asked = read(asked_path).split() if os.path.exists(asked_path) else []
            want = ex.attrs.get("action", "").split(",") if ex.attrs.get("action") else []
            if asked != want:
                got.append(f"line {ex.line}: polkit was asked under {asked}, the document says {want}")
            label = ex.attrs.get("op") or ex.attrs.get("error") or "example"
            print(f"{'FAIL' if got else 'ok  '} line {ex.line} {label} ({len(ex.commands)} commands, polkit {mode})")
            fails += got
            ran += 1
    finally:
        if server:
            server.kill()
            server.wait()
    if not ran:
        fails.append("the document has no examples")
    for op in OPS:
        if not any(e.attrs.get("op") == op and any(op in c[0] for c in e.commands) for e in exs):
            fails.append(f"no example calls {op}")
    return fails


def main(argv):
    if len(argv) == 3 and argv[1] == "static":
        bad = static(argv[2])
    elif len(argv) == 6 and argv[1] == "run":
        bad = run(*argv[2:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for b in bad:
        print(f"docs/api.md: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
