#!/usr/bin/python3 -I
"""Judges of the snap-* cases (F179, acceptances 17 and 18 of SPEC.md). Usage: snap.py CASE DIR [ID...]
Prints the problems of the case, one per line, and nothing when it holds. DIR holds the evidence the guest collected (e2e/vm/snap.sh); a
missing evidence file is a problem, never an empty answer. Every judge fails closed: the three things snapd may change under us (the label
is not snap.firefox.* in enforce mode, the socket is unreachable, the bus is not denied) say what moved and that a person must look.
Evidence files (DIR/): record (key=value), snap-list.out, snap-known.out, dir.stat, sock.stat (`stat -c %F|%U|%G|%a|%n`), list.out/list.rc
(the client's `token<TAB>LABEL` lines), keys.alice, keys.foreign (labels, one per line), sign-NAME.{pid,rc,crt,digest,sig,kind}, subjects (the
agent's `ACTION PID UID`), alice.uid, journal.json (`journalctl -o json` of the service during the group), bus-in.out, bus-out.out, audit.log,
register.out, register.rc (the `custodio register` of the place phase), module.sha, copy.sha (hashes of the installed module and of the snap copy), unconf.*/root.*/other.* (client output, rc, refusal.log, signs.before/after), um-METHOD.out, um.*."""
import json
import os
import subprocess
import sys
import tempfile

LABEL = "snap.firefox.firefox (enforce)"
SOCK = "/run/snap.firefox/custodio.sock"
RECORD_KEYS = ("snap_revision", "snap_base", "snapd_deb", "snapd_snap", "apparmor", "dbus_daemon", "peer_label")
SIGNS = ("rsa", "ec", "rsa2")
MOVED = "snapd's rules changed; a person must look"
SIGN_ACTION = "com.rfirma.custodio.sign"


def read(d, name):
    try:
        with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def need(d, *names):
    miss = [n for n in names if read(d, n) is None]
    return [f"evidence file {n} is missing" for n in miss]


def lines(d, name):
    t = read(d, name)
    return [] if t is None else [x for x in t.splitlines() if x.strip()]


def kv(d, name):
    out = {}
    for x in lines(d, name):
        if "=" in x:
            k, v = x.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def entries(d, name="journal.json"):
    out = []
    for x in lines(d, name):
        try:
            out.append(json.loads(x))
        except ValueError:
            out.append({"_unparsed": x})
    return out


def tokens(d, prefix="list"):
    return [x.split("\t", 1)[1] for x in lines(d, prefix + ".out") if x.startswith("token\t")]


def j_register(d):
    """The command that placed the copy (F183): it succeeded, said the snap profile is registered, and the copy is the installed module."""
    p = []
    rc = read(d, "register.rc").strip()
    if rc != "0":
        p.append(f"custodio register exited with '{rc}', not 0")
    report = lines(d, "register.out")
    if not any(x.startswith("Firefox (snap) ") and ": registered" in x for x in report):
        p.append("the report of custodio register does not say the Firefox snap profile was registered")
    if any(": skipped" in x or "copy failed" in x for x in report):
        p.append("the report of custodio register has a skipped or failed line")
    module, copy = read(d, "module.sha").strip(), read(d, "copy.sha").strip()
    if not module or module == "missing":
        p.append("the installed module has no hash")
    elif copy != module:
        p.append(f"the snap copy of the module ({copy or 'no hash'}) is not the installed module ({module})")
    return p


def j_record(d, _):
    p = need(d, "record", "snap-list.out", "snap-known.out", "register.out", "register.rc", "module.sha", "copy.sha")
    if p:
        return p
    p += j_register(d)
    r = kv(d, "record")
    for k in RECORD_KEYS:
        if not r.get(k):
            p.append(f"the record has no {k}")
        elif r[k] == "unknown":
            p.append(f"the record field {k} is unknown")
    if r.get("peer_label") and r["peer_label"] != "unknown" and r["peer_label"] != LABEL:
        p.append(f"the label the service observed is '{r['peer_label']}', not '{LABEL}': {MOVED}")
    row = [x.split() for x in lines(d, "snap-list.out") if x.split()[:1] == ["firefox"]]
    if len(row) != 1 or len(row[0]) < 6:
        return p + ["snap list firefox has no usable row"]
    _, _, rev, track, pub, notes = row[0][:6]
    if track != "latest/stable":
        p.append(f"firefox tracks '{track}', not latest/stable")
    if not pub.lower().startswith("mozilla"):
        p.append(f"the publisher is '{pub}', not Mozilla")
    if "dangerous" in notes or "try" in notes:
        p.append(f"the Notes column is '{notes}': the snap was not installed from the store")
    if r.get("snap_revision") not in (None, rev):
        p.append(f"the record revision {r.get('snap_revision')} is not the installed {rev}")
    known = read(d, "snap-known.out")
    if "type: snap-revision" not in known or f"snap-revision: {rev}" not in known:
        p.append(f"snap known has no signed snap-revision assertion for revision {rev}")
    return p


def j_socket_dir(d, _):
    p = need(d, "dir.stat", "sock.stat")
    if p:
        return p
    dm = (read(d, "dir.stat").strip().split("|") + [""] * 4)[:4]
    if dm != ["directory", "root", "root", "755"]:
        p.append(f"/run/snap.firefox is {'|'.join(dm)}, not directory|root|root|755")
    sm = (read(d, "sock.stat").strip().split("|") + [""] * 5)[:5]
    if sm[0] != "socket":
        p.append(f"custodio.sock is a '{sm[0]}', not a socket")
    if os.path.basename(sm[4]) != "custodio.sock":
        p.append(f"the socket is named '{sm[4]}', not custodio.sock")
    return p


def j_list_keys(d, _):
    p = need(d, "list.out", "list.rc", "keys.alice", "keys.foreign")
    if p:
        return p
    rc = read(d, "list.rc").strip()
    got = tokens(d)
    if rc != "0":
        return [f"the client could not list the keys from the confinement (exit {rc}): the socket {SOCK} is unreachable; {MOVED}"]
    if not got:
        return ["the client listed no key"]
    for k in lines(d, "keys.alice"):
        if k not in got:
            p.append(f"the key {k} of the user is not listed")
    for k in lines(d, "keys.foreign"):
        if k in got:
            p.append(f"the key {k} of another user is listed")
    if not lines(d, "keys.foreign"):
        p.append("no key of another user exists: 'only hers' is vacuous")
    return p


def run(args, data=None):
    r = subprocess.run(args, input=data, capture_output=True, check=False)
    return r.returncode


def raw_to_der(raw):
    def integer(b):
        b = b.lstrip(b"\0") or b"\0"
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + bytes([len(b)]) + b
    half = len(raw) // 2
    body = integer(raw[:half]) + integer(raw[half:])
    return b"\x30" + bytes([len(body)]) + body


def verify(d, name):
    """openssl verifies the signature NAME against the certificate the client read through the module."""
    kind = (read(d, f"sign-{name}.kind") or "").strip()
    with tempfile.TemporaryDirectory() as t:
        pub = os.path.join(t, "pub.pem")
        pr = subprocess.run(["openssl", "x509", "-inform", "der", "-in", os.path.join(d, f"sign-{name}.crt"), "-pubkey", "-noout"], capture_output=True, check=False)
        if pr.returncode != 0:
            return "openssl cannot read the certificate"
        with open(pub, "wb") as f:
            f.write(pr.stdout)
        sig = os.path.join(d, f"sign-{name}.sig")
        digest = os.path.join(d, f"sign-{name}.digest")
        base = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-in", digest]
        if kind == "rsa":
            ok = run(base + ["-sigfile", sig, "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "digest:sha256", "-pkeyopt", "rsa_mgf1_md:sha256", "-pkeyopt", "rsa_pss_saltlen:32"])
        elif kind == "ec":
            der = os.path.join(t, "sig.der")
            with open(sig, "rb") as f, open(der, "wb") as g:
                g.write(raw_to_der(f.read()))
            ok = run(base + ["-sigfile", der, "-pkeyopt", "digest:sha256"])
        else:
            return f"the kind of {name} is '{kind}'"
    return None if ok == 0 else "openssl does not verify the signature"


def j_sign(d, ids):
    name = ids[0]
    p = need(d, f"sign-{name}.pid", f"sign-{name}.rc", f"sign-{name}.crt", f"sign-{name}.digest", f"sign-{name}.sig", f"sign-{name}.kind")
    if p:
        return p
    if read(d, f"sign-{name}.rc").strip() != "0":
        return [f"the client could not sign with {name} (exit {read(d, f'sign-{name}.rc').strip()}): is the socket {SOCK} reachable? {MOVED}"]
    bad = verify(d, name)
    return [f"{name}: {bad}"] if bad else []


def j_polkit(d, _):
    p = need(d, "subjects", "alice.uid", "journal.json", *[f"sign-{n}.pid" for n in SIGNS])
    if p:
        return p
    pids = [read(d, f"sign-{n}.pid").strip() for n in SIGNS]
    uid = read(d, "alice.uid").strip()
    subs = [x.split() for x in lines(d, "subjects") if x.split()[:1] == [SIGN_ACTION]]
    if len(subs) != len(SIGNS):
        p.append(f"polkit was asked {len(subs)} times for {len(SIGNS)} signatures (one question per signature)")
    if sorted(s[1] for s in subs if len(s) > 1) != sorted(pids):
        p.append(f"the pids polkit was asked about {sorted(s[1] for s in subs if len(s) > 1)} are not the client pids {sorted(pids)}")
    for s in subs:
        if len(s) < 3 or s[2] != uid:
            p.append(f"polkit was asked about uid {s[2] if len(s) > 2 else '-'}, not {uid}")
    jp = sorted(str(e.get("CUSTODIO_PID", "")) for e in entries(d) if e.get("CUSTODIO_OPERATION") == "sign")
    if jp != sorted(pids):
        p.append(f"the journal CUSTODIO_PID values {jp} are not the client pids {sorted(pids)}")
    return p


def j_journal(d, _):
    p = need(d, "journal.json")
    if p:
        return p
    signs = [e for e in entries(d) if e.get("CUSTODIO_OPERATION") == "sign"]
    if len(signs) < len(SIGNS):
        p.append(f"the journal has {len(signs)} sign entries, expected {len(SIGNS)}")
    for e in signs:
        if e.get("CUSTODIO_TRANSPORT") != "socket":
            p.append(f"a sign entry has transport '{e.get('CUSTODIO_TRANSPORT')}', not socket")
        if e.get("CUSTODIO_PEER_LABEL") != LABEL:
            p.append(f"a sign entry has the label '{e.get('CUSTODIO_PEER_LABEL')}', not '{LABEL}': {MOVED}")
    return p


def j_bus(d, _):
    p = need(d, "bus-in.out", "bus-out.out", "audit.log")
    if p:
        return p
    ins = read(d, "bus-in.out").strip()
    if not ins.startswith("error"):
        return [f"the bus call from the confinement was not denied ('{ins[:80]}'): {MOVED}"]
    if "AccessDenied" not in ins and "Permission denied" not in ins and "PermissionError" not in ins:
        p.append(f"the bus call from the confinement failed, but not as a denial: '{ins[:80]}'")
    if read(d, "bus-out.out").strip() != "ok":
        p.append(f"the identical call outside the confinement did not succeed ('{read(d, 'bus-out.out').strip()[:80]}'): the denial proves nothing")
    if not any('apparmor="DENIED"' in x and "snap.firefox" in x and ("Custodio1" in x or "system_bus_socket" in x or "dbus" in x) for x in lines(d, "audit.log")):
        p.append("no apparmor=\"DENIED\" record of snap.firefox for the bus call: the denial is not AppArmor's")
    return p


def refusal(d, pre, reason):
    p = need(d, f"{pre}.out", f"{pre}.rc", f"{pre}.refusal.log", f"{pre}.signs.before", f"{pre}.signs.after", "list.out", "list.rc")
    if p:
        return p
    if read(d, "list.rc").strip() != "0" or not tokens(d):
        p.append("the positive control failed: the confined client did not list keys through the same socket")
    if tokens(d, pre):
        p.append(f"the {pre} client listed keys")
    if read(d, f"{pre}.signs.before").strip() != read(d, f"{pre}.signs.after").strip():
        p.append(f"a sign entry was added by the {pre} client")
    if not any("peer refused:" in x and x.rstrip().endswith(reason) for x in lines(d, f"{pre}.refusal.log")):
        p.append(f"the journal has no refusal line 'peer refused: {reason}' for the {pre} client")
    return p


def j_refused_other(d, _):
    p = refusal(d, "other", "peer is another snap")
    p += need(d, "other.label", "other.connect")
    if p:
        return p
    if read(d, "other.label").strip() != "snap.e2e-other.app (enforce)":
        p.append(f"the child's label is '{read(d, 'other.label').strip()}', not snap.e2e-other.app (enforce): the case is vacuous")
    if read(d, "other.connect").strip() != "connected":
        p.append("the child could not connect() to the socket: AppArmor, not the service, refused")
    return p


def j_unknown(d, ids):
    methods = ("ImportP12", "DeleteKey", "ReplaceCertificate")
    p = need(d, *[f"um-{m}.out" for m in methods], "um.keys.before", "um.keys.after", "um.state.before", "um.state.after", "um.journal.before", "um.journal.after", "um.agent.before", "um.agent.after")
    if p:
        return p
    for m in methods:
        t = read(d, f"um-{m}.out").strip()
        if "UnknownMethod" not in t:
            p.append(f"{m} did not fail as an unknown method: '{t[:80]}'")
    for n, what in (("keys", "the key list"), ("state", "the state directory listing"), ("journal", "the audit entries"), ("agent", "the agent's requests")):
        if read(d, f"um.{n}.before") != read(d, f"um.{n}.after"):
            p.append(f"{what} changed")
    if not read(d, "um.state.before").strip():
        p.append("the state directory listing is empty")
    return p


JUDGES = {
    "snap-record": j_record, "snap-socket-dir": j_socket_dir, "snap-list-keys": j_list_keys,
    "snap-sign-rsa": lambda d, i: j_sign(d, ["rsa"]), "snap-sign-ec": lambda d, i: j_sign(d, ["ec"]),
    "snap-polkit-per-signature": j_polkit, "snap-journal-label": j_journal, "snap-bus-denied": j_bus,
    "snap-refused-unconfined": lambda d, i: refusal(d, "unconf", "peer is unconfined"),
    "snap-refused-root": lambda d, i: refusal(d, "root", "peer is unconfined"),
    "snap-refused-other-snap": j_refused_other, "snap-unknown-methods": j_unknown,
}


def main(argv):
    if len(argv) < 2 or argv[0] not in JUDGES:
        print(f"the judge snap.py has no case '{argv[0] if argv else ''}'")
        return 0
    for line in JUDGES[argv[0]](argv[1], argv[2:]):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
