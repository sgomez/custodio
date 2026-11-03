#!/usr/bin/python3 -I
"""The caller of one call of the appid-* cases (F95): runs as alice, inside the scope its launcher chose (appid-user.sh), and runs the command as its child.
The child makes the call, so the pid the bus reports is the child's; the child is in the cgroup of this process.
Usage: appid-enter.py DIR LABEL CLASSIFIER [--cg CGLABEL] -- COMMAND...
  --cg    first makes the child of alice's app.slice that DIR/names.tsv names CGLABEL (if it is not there) and moves this process into it, by writing its pid to
          the cgroup.procs of that child. That works only from inside the subtree of her user manager, so the launcher is `systemd-run --user --scope`. The
          hostile name is read from the file: it is on no command line, which the user manager would log.
Records one line in DIR/observed: LABEL, pid of the child, uid, result, wall time of the call in ms, requests the agent got, polkit subjects it saw.
CLASSIFIER p11 (pkcs11-tool): p11-ok / p11-failed by the exit status; dbus (owner-call.py): ok, or denied / mismatch / wrong-password / error:... by its line."""
import os
import subprocess
import sys
import time


def lines(path):
    try:
        with open(path, "rb") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def enter(directory, cg_label):
    with open(os.path.join(directory, "names.tsv"), encoding="ascii") as f:
        rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    name = next(bytes.fromhex(r[1]) for r in rows if r[0] == cg_label)
    with open("/proc/self/cgroup", "rb") as f:
        own = next(line[3:] for line in f.read().splitlines() if line.startswith(b"0::"))
    parent = b"/sys/fs/cgroup" + os.path.dirname(own)
    if not parent.endswith(b"/app.slice"):
        sys.exit(f"appid-enter: this process is not in a scope of alice's app.slice but in {own.decode()}")
    child = os.path.join(parent, name)
    try:
        os.mkdir(child)
    except FileExistsError:
        pass
    with open(os.path.join(child, b"cgroup.procs"), "wb") as f:
        f.write(b"%d\n" % os.getpid())


def classify(kind, status, out):
    if kind == "p11":
        return "p11-ok" if status == 0 else "p11-failed"
    text = out.strip()
    if text == "ok":
        return "ok"
    for tail, word in (("PolkitDenied", "denied"), ("CertificateMismatch", "mismatch"), ("WrongPasswordOrBadP12", "wrong-password")):
        if text.endswith(tail):
            return word
    return "error:" + text.replace(" ", "_")[:60]


def main():
    args = sys.argv[1:]
    directory, label, kind = args[:3]
    rest = args[3:]
    cg = None
    if rest[:1] == ["--cg"]:
        cg, rest = rest[1], rest[2:]
    if rest[:1] != ["--"] or len(rest) < 2:
        sys.exit("usage: appid-enter.py DIR LABEL p11|dbus [--cg CGLABEL] -- COMMAND...")
    command = rest[1:]
    if cg:
        enter(directory, cg)
    agent = os.environ["E2E_DIR"]
    requests, subjects = len(lines(os.path.join(agent, "requests"))), lines(os.path.join(agent, "subjects"))
    start = time.monotonic()
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    with open(os.path.join(directory, f"pid-{label}"), "w", encoding="ascii") as f:
        f.write(f"{child.pid}\n")
    out, _ = child.communicate()
    elapsed = time.monotonic() - start
    gained = lines(os.path.join(agent, "subjects"))[len(subjects):]
    subj = ",".join(f"{words[1].decode()}/{words[2].decode()}" for words in (g.split() for g in gained)) or "-"
    record = "\t".join([label, str(child.pid), str(os.getuid()), classify(kind, child.returncode, out), str(round(elapsed * 1000)),
                        str(len(lines(os.path.join(agent, "requests"))) - requests), subj])
    fd = os.open(os.path.join(directory, "observed"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
    os.write(fd, (record + "\n").encode())
    os.close(fd)
    return 0


sys.exit(main())
