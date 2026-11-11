#!/usr/bin/python3 -I
"""The judgements of the vm-silent-* cases (F161, acceptance 11 of SPEC.md) that e2e/tpmfail.py does not make, as functions of files. Each subcommand prints one problem per line and
nothing when the evidence is right (exit 0 either way; exit 2 on a bad call). The import that fails, the unchanged state, the journal entry and the kind after the restore are judged by
tpmfail.py (failed, nothing, journal, noweaker, kind); this file adds:
  silent.py hiding OUT RC           systemd-analyze has-tpm2 no longer says "yes" with exit 0 while the library is hidden (else the hiding did not work, and the case proves nothing)
  silent.py restored OUT RC         the same command says "yes", exit 0, once the library is back
  silent.py absent API CLI ID       no key ID of any kind: not a row of the API's list (ID<TAB>TYPE<TAB>KIND), not an "id: ID" block of `custodio list`
  silent.py reader OUT RC           the reader of the stored credential (e2e/vm/cred-lib.sh) exited 0
"""
import re
import sys


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().replace("\r", "")
    except OSError:
        return ""  # a file that was not made is evidence that is missing: the judgement reports it


def status(path):
    text = read(path).strip()
    return int(text) if re.fullmatch(r"[0-9]+", text) else None


def hiding_problems(out, rc):
    code = status(rc)
    if code is None:
        return [f"{rc}: not an exit status"]
    if read(out).strip() == "yes" and code == 0:
        return ["systemd-analyze has-tpm2 still says yes while the library is hidden: the hiding did not work"]
    return []


def restored_problems(out, rc):
    code, text = status(rc), read(out).strip()
    if code is None:
        return [f"{rc}: not an exit status"]
    if text != "yes" or code != 0:
        return [f"systemd-analyze has-tpm2 says '{text}' (exit {code}) after the library was put back, expected 'yes' (0)"]
    return []


def absent_problems(api, cli, key_id):
    problems = []
    for ln in read(api).split("\n"):
        row = ln.split("\t")
        if row and row[0] == key_id:
            kind = row[2] if len(row) > 2 else "?"
            problems.append(f"{api}: the key {key_id} is listed (kind {kind})")
    if re.search(rf"^\s*id:\s*{re.escape(key_id)}\s*$", read(cli), re.M):
        problems.append(f"{cli}: `custodio list` shows the key {key_id}")
    if not read(api).strip() and not read(cli).strip():
        problems.append("both lists are empty: they were not taken")
    return problems


def reader_problems(out, rc):
    code = status(rc)
    if code is None:
        return [f"{rc}: not an exit status"]
    if code != 0:
        return [f"the reader failed (exit {code}): {read(out).strip()}"]
    return []


def main(argv):
    table = {"hiding": (hiding_problems, 2), "restored": (restored_problems, 2), "absent": (absent_problems, 3), "reader": (reader_problems, 2)}
    if not argv or argv[0] not in table or len(argv) - 1 != table[argv[0]][1]:
        print(__doc__, file=sys.stderr)
        return 2
    print("\n".join(table[argv[0]][0](*argv[1:])))
    return 0


sys.exit(main(sys.argv[1:]))
