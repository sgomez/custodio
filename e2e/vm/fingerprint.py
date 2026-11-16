#!/usr/bin/python3 -I
"""Judges of the vm-fingerprint-* cases (F200, acceptances 18 and 19 of SPEC.md). Usage: fingerprint.py CASE DIR | fingerprint.py end DIR
Prints the problems of the case, one per line, and nothing when it holds. DIR holds the evidence the guest collected (e2e/vm/fingerprint.sh); a missing
evidence file is a problem, never an empty answer. A staging that was skipped is a problem (acceptance 19: no skip path exists).
Evidence files (DIR/):
  record            key=value: staging=ok|skipped, virtual_driver, socket, device, enrolled, override (each `yes`), and the versions polkit, fprintd, libfprint,
                    libpam-fprintd (`unknown` is a problem)
  CASE.events       one event per line, `SECONDS NAME [DETAIL]`, the seconds counted from the line `0 start`. Names: start, prompt-finger (the agent or sudo asked
                    for the finger), scan (a touch was sent), matched / nomatch (fprintd's VerifyStatus), prompt-password, typed-wrong, typed-right, refused,
                    approved, killed (the waiting process was killed by the harness)
  sudo.text         the transcript of sudo (case sudo)
  negative.action   `absent` or `present` (the file the approved action would leave)
  disabled.pam      `absent` or `no-fprintd` (what /etc/pam.d/polkit-1 is after disable), disabled.scans (scans consumed, a number)
  sign.{data,sig,pub}, sign.journal  the signed bytes, the DER signature, the public key (PEM), the journal entries of the service (`-o json`, one per line)
  CASE.restored     `unit=active device=listed` (fallback cases: fprintd is back before the next case)
  end.state         `polkit-1=back sudo-rule=back` (the files the group set aside are back; judged by `end`)"""
import json
import os
import re
import subprocess
import sys

CASES = ("stage", "polkit-finger", "polkit-unenrolled", "polkit-timeout", "sudo", "negative", "disabled", "sign",
         "fallback-module", "fallback-daemon", "fallback-reader", "fallback-finger")
VERSIONS = ("polkit", "fprintd", "libfprint", "libpam-fprintd")
STAGE_FACTS = ("virtual_driver", "socket", "device", "enrolled", "override")
TIMEOUT = 10.0  # pam_fprintd timeout=10
MARGIN = 5.0  # the password prompt of the timeout case comes between TIMEOUT and TIMEOUT + MARGIN seconds
NEGATIVE_WAIT = TIMEOUT + MARGIN  # the negative control waits this long before it declares "unapproved", then kills the waiting process
FALLBACK_BY = 5.0  # a fallback case asks for the password within this many seconds: no wait of the timeout
SIGN_ACTION = "signature made"


def read(d, name):
    try:
        with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def need(d, *names):
    return [f"evidence file {n} is missing" for n in names if read(d, n) is None]


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


def events(d, case):
    """[(seconds, name, detail)]; an unreadable line is kept as ('?', ...) so that a judge fails on it."""
    out = []
    for x in lines(d, case + ".events"):
        m = re.fullmatch(r"(\d+(?:\.\d+)?) ([a-z-]+)(?: (.*))?", x.strip())
        out.append((float(m[1]), m[2], m[3] or "") if m else (-1.0, "unreadable", x))
    return out


def names(ev):
    return [e[1] for e in ev]


def first(ev, name):
    return next((e for e in ev if e[1] == name), None)


def in_order(ev, wanted):
    """Problems unless the names of wanted occur in ev in that order (other events may lie between)."""
    ns, i = names(ev), 0
    for w in wanted:
        try:
            i = ns.index(w, i) + 1
        except ValueError:
            return [f"the events lack '{w}' after {'/'.join(wanted[:wanted.index(w)]) or 'the start'}: {' '.join(ns)}"]
    return []


def base(d, case):
    p = need(d, case + ".events")
    if p:
        return p, []
    ev = events(d, case)
    if "unreadable" in names(ev):
        p.append("the events hold a line that is not 'SECONDS NAME [DETAIL]'")
    if not ev or ev[0][1] != "start" or ev[0][0] != 0.0:
        p.append("the events do not begin with '0 start'")
    return p, ev


def forbid(ev, *bad):
    return [f"the events hold '{n}', which this case must not have" for n in bad if n in names(ev)]


def j_stage(d, _):
    p = need(d, "record")
    r = kv(d, "record")
    if r.get("staging") != "ok":
        p.append(f"staging is '{r.get('staging', 'missing')}', not ok: a failed or skipped staging fails the group (acceptance 19)")
    for k in STAGE_FACTS:
        if r.get(k) != "yes":
            p.append(f"staging fact {k} is '{r.get(k, 'missing')}', not yes")
    for k in VERSIONS:
        if r.get(k, "unknown") in ("", "unknown"):
            p.append(f"the version of {k} is unknown (acceptance 18)")
    return p


def j_finger(d, _):
    p, ev = base(d, "polkit-finger")
    if p:
        return p
    p += in_order(ev, ["prompt-finger", "scan", "matched", "approved"])
    return p + forbid(ev, "prompt-password", "typed-wrong", "typed-right", "nomatch", "refused")


def j_password_after(ev, first_event):
    """The finger did not match, the password prompt followed, the right password approved (the polkit text agent does not ask again after a wrong one:
    docs/findings/F200.md; a wrong password is covered by the sudo case)."""
    return in_order(ev, ["prompt-finger", *first_event, "prompt-password", "typed-right", "approved"]) + forbid(ev, "typed-wrong")


def j_unenrolled(d, _):
    p, ev = base(d, "polkit-unenrolled")
    if p:
        return p
    p += j_password_after(ev, ["scan", "nomatch"])
    return p + forbid(ev, "matched")


def j_timeout(d, _):
    p, ev = base(d, "polkit-timeout")
    if p:
        return p
    p += j_password_after(ev, [])
    p += forbid(ev, "scan", "matched")
    f, pw = first(ev, "prompt-finger"), first(ev, "prompt-password")
    if f and pw:
        wait = pw[0] - f[0]
        if wait < TIMEOUT:
            p.append(f"the password prompt came {wait:.1f} s after the finger prompt, before the {TIMEOUT:.0f} s timeout")
        elif wait > TIMEOUT + MARGIN:
            p.append(f"the password prompt came {wait:.1f} s after the finger prompt, after {TIMEOUT + MARGIN:.0f} s: not the timeout's fall-back")
    return p


def j_sudo(d, _):
    p, ev = base(d, "sudo")
    p += need(d, "sudo.text")
    if p:
        return p
    # the password was really asked and checked: a wrong one is refused before the right one is accepted (no passwordless rule in effect)
    p += in_order(ev, ["prompt-password", "typed-wrong", "refused", "prompt-password", "typed-right", "approved"])
    p += forbid(ev, "prompt-finger", "scan", "matched", "nomatch")
    if re.search(r"finger|swipe|touch|scan", read(d, "sudo.text"), re.I):
        p.append("the transcript of sudo shows a fingerprint prompt")
    return p


def j_negative(d, _):
    p, ev = base(d, "negative")
    p += need(d, "negative.action")
    if p:
        return p
    p += in_order(ev, ["prompt-finger", "prompt-password", "killed"])
    p += forbid(ev, "scan", "matched", "typed-wrong", "typed-right", "approved")
    k = first(ev, "killed")
    if k and k[0] < NEGATIVE_WAIT:
        p.append(f"the waiting process was killed after {k[0]:.1f} s, before the {NEGATIVE_WAIT:.0f} s the run waits")
    if read(d, "negative.action").strip() != "absent":
        p.append("the action the approval would perform was performed")
    return p


def j_disabled(d, _):
    p, ev = base(d, "disabled")
    p += need(d, "disabled.pam", "disabled.scans")
    if p:
        return p
    p += in_order(ev, ["prompt-password", "typed-right", "approved"])
    p += forbid(ev, "prompt-finger", "scan", "matched", "nomatch")
    if read(d, "disabled.pam").strip() not in ("absent", "no-fprintd"):
        p.append("/etc/pam.d/polkit-1 still names the fingerprint module after disable")
    if read(d, "disabled.scans").strip() != "0":
        p.append("a scan was consumed after disable")
    return p


def verify(d):
    data, sig, pub = (os.path.join(d, n) for n in ("sign.data", "sign.sig", "sign.pub"))
    try:
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig, data], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return f"openssl could not run: {e}"
    return None if r.returncode == 0 and "Verified OK" in r.stdout else "the signature does not verify with the public key (openssl)"


def j_sign(d, _):
    p, ev = base(d, "sign")
    p += need(d, "sign.data", "sign.sig", "sign.pub", "sign.journal", "sign.key", "sign.uid")
    if p:
        return p
    p += in_order(ev, ["prompt-finger", "scan", "matched", "approved"])
    p += forbid(ev, "prompt-password", "typed-wrong", "typed-right", "nomatch")
    v = verify(d)
    if v:
        p.append(v)
    key, uid = read(d, "sign.key").strip(), read(d, "sign.uid").strip()
    ents = []
    for x in lines(d, "sign.journal"):
        try:
            ents.append(json.loads(x))
        except ValueError:
            p.append("the journal evidence holds a line that is not JSON")
    ents = [e for e in ents if e.get("CUSTODIO_OPERATION") == "sign"]
    if len(ents) != 1:
        p.append(f"the journal holds {len(ents)} sign entries, expected exactly 1")
    for e in ents:
        if e.get("CUSTODIO_KEY_ID") != key or str(e.get("CUSTODIO_UID", "")) != uid:
            p.append(f"the journal entry is for key '{e.get('CUSTODIO_KEY_ID')}' uid '{e.get('CUSTODIO_UID')}', not '{key}' uid '{uid}'")
        if SIGN_ACTION not in str(e.get("MESSAGE", "")):
            p.append(f"the journal entry's message is not '{SIGN_ACTION}'")
    return p


def j_fallback(case):
    def judge(d, _):
        p, ev = base(d, case)
        p += need(d, case + ".restored")
        if p:
            return p
        p += in_order(ev, ["prompt-password", "typed-right", "approved"])
        p += forbid(ev, "prompt-finger", "scan", "matched", "nomatch", "typed-wrong")
        pw = first(ev, "prompt-password")
        if pw and pw[0] > FALLBACK_BY:
            p.append(f"the first prompt came after {pw[0]:.1f} s: the timeout was waited, the finger was tried")
        t = read(d, case + ".restored")
        if "unit=active" not in t or "device=listed" not in t:
            p.append("fprintd was not shown up again (unit active, device listed) before the next case")
        return p
    return judge


def j_end(d, _):
    p = need(d, "end.state")
    if p:
        return p
    t = read(d, "end.state")
    return [f"the file set aside was not put back: {w} missing" for w in ("polkit-1=back", "sudo-rule=back") if w not in t]


JUDGES = {"stage": j_stage, "polkit-finger": j_finger, "polkit-unenrolled": j_unenrolled, "polkit-timeout": j_timeout, "sudo": j_sudo,
          "negative": j_negative, "disabled": j_disabled, "sign": j_sign, "end": j_end}
for _c in CASES:
    if _c.startswith("fallback-"):
        JUDGES[_c] = j_fallback(_c)


def main(argv):
    if len(argv) != 3:
        print("usage: fingerprint.py CASE DIR", file=sys.stderr)
        return 2
    case = argv[1].removeprefix("vm-fingerprint-")
    if case not in JUDGES:
        print(f"unknown case '{argv[1]}'")
        return 1
    for line in JUDGES[case](argv[2], case):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
