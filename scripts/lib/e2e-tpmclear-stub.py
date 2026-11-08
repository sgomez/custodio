#!/usr/bin/python3 -I
"""Stand-in for the guest of tpmclear-run.sh in a VM run, on fixtures (F163): usage e2e-tpmclear-stub.py NAME ARGS... where NAME is the command it replaces (su, id, journalctl,
tpm2_*, pkcs11-tool, busctl, systemctl) or `scan`. The TPM is a seed in $STUB_STATE; `tpm2_clear` changes it and the owner primary's name follows it. Alice (su) keeps tc-rsa and tc-ec with REAL
openssl keys; after the clear her signatures fail with KeyLost / CKR_DEVICE_ERROR and each Sign call leaves a journal entry. Knobs (environment): STUB_KIND (kind of the keys, default tpm),
STUB_NOCLEAR (tpm2_clear changes nothing), STUB_SIGNAFTER (signing still works after the clear), STUB_NOJOURNAL, STUB_JOURNAL=sign|secret|kind (a wrong entry), STUB_TEXT (other error text),
STUB_LOSEKEY (the list after the clear lacks tc-ec), STUB_KINDAFTER (the list after the clear gives tc-rsa that kind), STUB_DELFAIL, STUB_NOREIMPORTSIGN, STUB_TCTI_LOG (file: the TCTI of each tpm2 command)."""
import json
import os
import re
import subprocess
import sys

S = os.environ["STUB_STATE"]
env = os.environ
ERR = "com.rfirma.Custodio1.Error."


def path(n):
    return os.path.join(S, n)


def rd(n, default=None):
    try:
        with open(path(n)) as f:
            return f.read()
    except OSError:
        return default


def wr(n, data, mode="w"):
    with open(path(n), mode) as f:
        f.write(data)


def ssl(*args, data=None):
    return subprocess.run(["openssl", *args], capture_output=True, check=True, input=data).stdout


def tool(name, a):
    if env.get("STUB_TCTI_LOG"):
        with open(env["STUB_TCTI_LOG"], "a") as f:
            f.write(f"{name} {env.get('TPM2TOOLS_TCTI', '')}\n")
    seed = rd("seed", "1").strip()
    if name == "tpm2_clear":
        if not env.get("STUB_NOCLEAR"):
            wr("seed", str(int(seed) + 1))
            wr("cleared", "1")
    elif name == "tpm2_createprimary":
        open(a[a.index("-c") + 1], "a").close()
    elif name == "tpm2_readpublic":
        with open(a[a.index("-n") + 1], "wb") as f:
            f.write(bytes.fromhex("000b" + ("%064x" % int(seed))))
    return 0


def entry(key, op, outcome, cause, kind):
    uid = "1000"
    e = {"SYSLOG_IDENTIFIER": "custodiod", "CUSTODIO_OPERATION": op, "CUSTODIO_OUTCOME": outcome, "CUSTODIO_KEY_ID": key, "CUSTODIO_UID": uid}
    if cause:
        e["CUSTODIO_CAUSE"] = cause
    if kind:
        e["CUSTODIO_STORAGE_KIND"] = kind
    return e


def journal_add(es):
    if env.get("STUB_NOJOURNAL"):
        return
    with open(path("journal"), "a") as f:
        for e in es:
            f.write(json.dumps(e) + "\n")


def journalctl(a):
    lines = [ln for ln in (rd("journal", "") or "").split("\n") if ln]
    if "--show-cursor" in a:
        print(f"-- cursor: {len(lines)}")
    for x in a:
        if x.startswith("--after-cursor="):
            for ln in lines[int(x.split("=", 1)[1]):]:
                print(ln)
    return 0


def alice(cmdline):
    m = re.search(r"WORK=(\S+) .*?tpmclear-user\.sh (\S+)\s*(.*)$", cmdline)
    work, cmd, rest = m.group(1), m.group(2), m.group(3).split()
    tc = os.path.join(work, "tpmclear")
    kind = env.get("STUB_KIND", "tpm")
    cleared = rd("cleared") == "1"
    state = env["TC_STATE_DIR"]
    types = {"rsa": "rsa2048", "ec": "ecdsa-p256"}

    def listing(out, ids):
        os.makedirs(out, exist_ok=True)
        rows = []
        for i in ids:
            k = kind
            if cleared and env.get("STUB_LOSEKEY") and i == "tc-ec":
                continue
            if cleared and env.get("STUB_KINDAFTER") and i == "tc-rsa":
                k = env["STUB_KINDAFTER"]
            rows.append("\t".join((i, types[i.split("-")[1]], k)))
        with open(os.path.join(out, "list.out"), "w") as f:
            f.write("".join(r + "\n" for r in rows))
        return rows

    cur = lambda: [i for i in (rd("imported", "") or "").split() if i]  # noqa: E731
    if cmd == "import":
        out, ts = rest[0], rest[1:]
        ids = cur()
        for t in ts:
            i = "tc-" + t
            alg = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"] if t == "rsa" else ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
            # the same p12 is imported again after the clear: the same key
            if not os.path.exists(path(i + ".key")):
                open(path(i + ".key"), "wb").write(ssl(*alg))
            key = open(path(i + ".key"), "rb").read()
            os.makedirs(os.path.join(tc, "in"), exist_ok=True)
            open(os.path.join(tc, "in", i + ".pub.pem"), "wb").write(ssl("pkey", "-pubout", data=key))
            os.makedirs(os.path.join(state, "1000"), exist_ok=True)
            open(os.path.join(state, "1000", i), "w").write("record " + i)
            wr(i + ".seed", rd("seed", "1"))
            ids.append(i)
        wr("imported", " ".join(ids))
        listing(out, ids)
    elif cmd == "sign":
        tag, ts = rest[0], rest[1:]
        os.makedirs(os.path.join(tc, "out"), exist_ok=True)
        n = 0
        for t in ts:
            i = "tc-" + t
            base = os.path.join(tc, "out", f"{tag}-{i}")
            if rd(i + ".seed") != rd("seed", "1") and not env.get("STUB_SIGNAFTER"):
                text = env.get("STUB_TEXT", "the stored key can no longer be used")
                open(base + ".dbus", "w").write(f"error {ERR}KeyLost: {text}\n")
                open(base + ".rc", "w").write("1\n")
                open(base + ".log", "w").write("error: PKCS11 function C_Sign failed: rv = CKR_DEVICE_ERROR (0x5)\n")
                jk = "encrypted-host" if env.get("STUB_JOURNAL") == "kind" else kind
                es = [entry(i, "sign", "signing_failed", "key_lost", jk) for _ in range(2)]
                if env.get("STUB_JOURNAL") == "sign":
                    es = [entry(i, "sign", "signed", "", jk) for _ in range(2)]
                if env.get("STUB_JOURNAL") == "secret":
                    es[0]["MESSAGE"] = "e2e-password"
                journal_add(es)
                n += 2
            else:
                open(base + ".dbus", "w").write("ok\n")
                sig = ssl("dgst", "-sha256", "-sign", path(i + ".key"), os.path.join(tc, "in", "msg.bin"))
                open(base + ".sig", "wb").write(sig)
                open(base + ".rc", "w").write("0\n")
                n += 2
        open(os.path.join(tc, "out", tag + ".count"), "w").write(f"{n}\n")
    elif cmd == "list":
        rows = listing(rest[0], cur())
        with open(os.path.join(rest[0], "cli.out"), "w") as f:
            for r in rows:
                i, ty, k = r.split("\t")
                f.write(f"id: {i}\n  type: {ty}\n  kind: {k}\n\n")
    elif cmd == "delete":
        out, ids = rest[0], rest[1:]
        os.makedirs(out, exist_ok=True)
        keep = cur()
        for i in ids:
            open(os.path.join(out, f"delete-{i}.rc"), "w").write("1\n" if env.get("STUB_DELFAIL") else "0\n")
            open(os.path.join(out, f"delete-{i}.out"), "w").close()
            if env.get("STUB_DELFAIL"):
                continue
            keep = [k for k in keep if k != i]
            try:
                os.remove(os.path.join(state, "1000", i))
            except OSError:
                pass
            journal_add([entry(i, "delete", "deleted", "", "")])
        wr("imported", " ".join(keep))
        listing(out, keep)
    elif cmd == "restore":
        # the setup keys are deleted and imported again from the kept p12 files; STUB_RESTOREFAIL=delete|import makes that step fail
        for k in ("rsa1", "ec1"):
            if env.get("STUB_RESTOREFAIL") == "delete":
                print(f"delete of {k} failed", file=sys.stderr)
                return 1
            with open(path("restore.log"), "a") as f:
                f.write(f"delete {k}\n")
            if env.get("STUB_RESTOREFAIL") == "import" or not os.path.exists(os.path.join(work, "setup-keep", k + ".p12")):
                print(f"import of {k} failed", file=sys.stderr)
                return 1
            with open(path("restore.log"), "a") as f:
                f.write(f"import {k}\n")
    return 0


def scan():
    sd = sys.argv[2]
    d = os.path.join(sd, "1000")
    kind = env.get("STUB_KIND", "tpm")
    for i in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        print(f"1000\t{i}\t{kind}\t0b")
    return 0


def main():
    name, a = sys.argv[1], sys.argv[2:]
    if name == "scan":
        return scan()
    if name.startswith("tpm2_"):
        return tool(name, a)
    if name == "su":
        return alice(a[3])
    if name == "journalctl":
        return journalctl(a)
    if name == "id":
        print("1000")
    return 0


sys.exit(main() or 0)
