#!/usr/bin/python3 -I
"""Stand-in for the guest of pcr-vm.sh on fixtures (F163): usage e2e-pcr-stub.py NAME ARGS... where NAME is the command it replaces (tpm2_*, systemctl, busctl, su) or `cycle`
(the test's power cycle). Its TPM is a directory ($STUB_STATE): PCRs 0 and 7 that start at fixed values, extend as sha256(old || digest) and are back at the start values after
`cycle`; the PolicyPCR object unseals only while PCR 7 is what it was when the policy was made. Alice (su) keeps pr-rsa and pr-ec with REAL openssl keys and signatures.
Knobs (environment): STUB_KIND (kind of both keys, default tpm), STUB_NOEXTEND, STUB_NOPID (restart keeps the pid), STUB_BADSIG=TAG, STUB_SIGFAIL=TAG, STUB_DROPKEY=TAG (the list of that
round lacks pr-ec), STUB_KINDAFTER=TAG:KIND (the list of that round gives pr-rsa that kind), STUB_UNSEALALWAYS, STUB_CYCLE=keep|other|sameboot (what the power cycle does to the PCRs/boot id)."""
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid

S = os.environ["STUB_STATE"]
env = os.environ


def path(n):
    return os.path.join(S, n)


def rd(n, default=None):
    try:
        with open(path(n)) as f:
            return f.read()
    except OSError:
        return default


def wr(n, data):
    with open(path(n), "w") as f:
        f.write(data)


def pcrs():
    return json.loads(rd("pcrs") or json.dumps({"0": "00" * 31 + "aa", "7": "00" * 31 + "bb"}))


def put_pcrs(p):
    wr("pcrs", json.dumps(p))


def cycle():
    mode = env.get("STUB_CYCLE", "")
    first = json.loads(rd("pcrs0"))
    if mode == "keep":
        pass
    elif mode == "other":
        put_pcrs({k: hashlib.sha256((v + "x").encode()).hexdigest() for k, v in first.items()})
    else:
        put_pcrs(first)
    if mode != "sameboot":
        wr("boot", str(uuid.uuid4()) + "\n")


def tool(name, a):
    cwd = os.getcwd()
    if not os.path.exists(path("pcrs0")):
        wr("pcrs0", json.dumps(pcrs()))
    if name == "tpm2_pcrread":
        want = re.sub(r"^.*:", "", a[0]).split(",")
        p = pcrs()
        print("sha256:")
        for i in want:
            print(f"  {i} : 0x{p[i].upper()}")
    elif name == "tpm2_pcrextend":
        idx, _, dig = a[0].partition(":sha256=")
        if not env.get("STUB_NOEXTEND"):
            p = pcrs()
            p[idx] = hashlib.sha256(bytes.fromhex(p[idx]) + bytes.fromhex(dig)).hexdigest()
            put_pcrs(p)
    elif name == "tpm2_policypcr":
        cur = pcrs()["7"]
        if "-L" in a:
            open(a[a.index("-L") + 1], "w").write(cur)
        else:
            open(a[a.index("-S") + 1], "w").write(cur)
    elif name == "tpm2_create":
        pol = open(a[a.index("-L") + 1]).read()
        open(a[a.index("-u") + 1], "w").write(pol)
        open(a[a.index("-r") + 1], "w").write(open(a[a.index("-i") + 1]).read())
    elif name == "tpm2_load":
        open(a[a.index("-c") + 1], "w").write(open(a[a.index("-u") + 1]).read() + "\n" + open(a[a.index("-r") + 1]).read())
    elif name == "tpm2_unseal":
        pol, _, secret = open(a[a.index("-c") + 1]).read().partition("\n")
        sess = open(a[a.index("-p") + 1].removeprefix("session:")).read()
        if sess == pol or env.get("STUB_UNSEALALWAYS"):
            sys.stdout.write(secret)
        else:
            print("ERROR: Esys_Unseal(0x99D) - tpm:session(1):a policy check failed")
            return 1
    elif name in ("tpm2_createprimary", "tpm2_startauthsession"):
        for flag in ("-c", "-S"):
            if flag in a:
                open(a[a.index(flag) + 1], "a").close()
    del cwd
    return 0


def systemctl(a):
    if a[:1] == ["show"]:
        if rd("pid") is None:
            wr("pid", "1000")
        print(rd("pid").strip())
    elif a[:1] == ["restart"]:
        if not env.get("STUB_NOPID"):
            wr("pid", str(int(rd("pid", "1000")) + 1))
    return 0


def ssl(*args, data=None):
    return subprocess.run(["openssl", *args], capture_output=True, check=True, input=data).stdout


def alice(cmdline):
    m = re.search(r"PCR_DIR=(\S+).*?pcr-user\.sh (\S+)\s*(\S*)", cmdline)
    pc, cmd, tag = m.group(1), m.group(2), m.group(3)
    kind = re.search(r"PCR_KIND=(\S+)", cmdline).group(1)
    ids = (("pr-rsa", "rsa2048"), ("pr-ec", "ecdsa-p256"))
    for sub in ("in", "out"):
        os.makedirs(os.path.join(pc, sub), exist_ok=True)
    if cmd == "import":
        for k, alg in (("pr-rsa", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]), ("pr-ec", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])):
            key = ssl(*alg)
            open(path(k + ".key"), "wb").write(key)
            open(os.path.join(pc, "in", k + ".pub.pem"), "wb").write(ssl("pkey", "-pubout", data=key))
        wr("imported", "1")
        if "PCR_NOSIGN=1" not in cmdline:
            cmd, tag = "sign", "base"
    if cmd == "sign":
        if not rd("imported"):
            sys.exit("not imported")
        rows = []
        for k, alg in ids:
            if env.get("STUB_DROPKEY") == tag and k == "pr-ec":
                continue
            kd = env.get("STUB_KIND", "tpm")
            if env.get("STUB_KINDAFTER", "").partition(":")[0] == tag and k == "pr-rsa":
                kd = env["STUB_KINDAFTER"].partition(":")[2]
            rows.append((k, alg, kd))
        with open(os.path.join(pc, f"list-{tag}.out"), "w") as f:
            for r in rows:
                f.write("\t".join(r) + "\n")
        for k, alg, kd in rows:
            if kd != kind:
                continue
            base = os.path.join(pc, "out", f"{tag}-{k}")
            if env.get("STUB_SIGFAIL") == tag:
                open(base + ".rc", "w").write("1\n")
                open(base + ".log", "w").write("CKR_DEVICE_ERROR\n")
                continue
            sig = ssl("dgst", "-sha256", "-sign", path(k + ".key"), os.path.join(pc, "in", "msg.bin"))
            if env.get("STUB_BADSIG") == tag:
                sig = os.urandom(len(sig))
            open(base + ".sig", "wb").write(sig)
            open(base + ".rc", "w").write("0\n")
    elif cmd == "delete":
        wr("imported", "")
        open(os.path.join(pc, "list-after.out"), "w").close()
    return 0


def main():
    name, a = sys.argv[1], sys.argv[2:]
    if name == "cycle":
        return cycle()
    if name.startswith("tpm2_"):
        return tool(name, a)
    if name == "systemctl":
        return systemctl(a)
    if name == "su":
        return alice(a[3])
    return 0  # busctl, flush...


sys.exit(main() or 0)
