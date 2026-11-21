#!/usr/bin/python3 -I
"""The judgements of the tpmfail-* cases (F139, acceptance 7 of SPEC.md), as functions of files. Each subcommand prints one problem per line and nothing when the evidence is
right (exit 0 either way; exit 2 on a bad call), so scripts/test-e2e-tpmfail.sh can show each one fails on bad evidence. The five facts of an injection:
  tpmfail.py failed OUT RC ERROR       (a) the import exited non-zero, the CLI said what it says for com.rfirma.Custodio1.Error.ERROR, and printed no key line (no success)
  tpmfail.py nothing BEFORE AFTER LIST ID
                                       (b) the state directory listings (find + sha256) are identical, and LIST ("ID<TAB>TYPE<TAB>KIND") has no ID
  tpmfail.py journal JSON ID CAUSE SECRET...
                                       (c) JSON (journalctl -o json of the import entries after the attempt) holds exactly one entry: operation import, outcome storage_failure,
                                           CUSTODIO_CAUSE CAUSE, key ID, no stored kind, none of the SECRETs anywhere in it
  tpmfail.py noweaker OUT LIST JSON ID (d) no encrypted-host or encrypted-tpm in the CLI output, the entries, or the row of ID in the list (other keys may have any kind)
  tpmfail.py kind OUT LIST ID KIND     (d, e) a later import (or a control) of ID succeeded with exactly the kind KIND: one CLI key line and list row
The kind is compared by exact value: "tpm" and "encrypted-tpm" are other kinds.
"""
import json
import re
import sys

ERROR_PREFIX = "com.rfirma.Custodio1.Error."
# What the CLI says for each error (crates/custodio-cli/src/failure.rs): the error name itself is no longer printed
MESSAGE = {
    "TpmFailed": "the TPM failed or cannot be used; nothing was stored",
    "CredentialsUnavailable": "the credential service is unavailable; nothing was stored",
}
WEAKER = ("encrypted-host", "encrypted-tpm")


def read(path):
    return open(path, encoding="utf-8", errors="replace").read().replace("\r", "")


def failed_problems(out, rc, error):
    problems = []
    status = read(rc).strip()
    if not re.fullmatch(r"[0-9]+", status):
        problems.append(f"{rc}: not an exit status: {status!r}")
    elif int(status) == 0:
        problems.append("the import exited 0")
    text = read(out)
    if MESSAGE[error] not in text:
        problems.append(f"{out}: the CLI does not say {MESSAGE[error]!r} ({ERROR_PREFIX}{error})")
    for key in key_lines(text):
        problems.append(f"{out}: a success line: the key line of {key['id']!r}")
    return problems


# The key lines of `custodio import` output, read by layout (crates/custodio-cli/src/lib.rs, write_imported): "WORD  ID  TYPE  KIND" with WORD ok or warn,
# then the notes under it (indented 6 spaces). The words of a note are not judged, only that it is there.
KEY_LINE = re.compile(r"(ok|warn) +(\S+)  +(\S+)  +(\S+)")


def key_lines(text):
    # On a terminal (import.py runs the CLI on a pty) the CLI colours the word: the layout is read without the colour codes.
    lines = re.sub(r"\x1b\[[0-9;]*m", "", text).replace("\r", "").split("\n")
    found = []
    for i, ln in enumerate(lines):
        m = KEY_LINE.fullmatch(ln)
        if not m:
            continue
        notes = []
        for nxt in lines[i + 1:]:
            if not nxt.startswith("      ") or not nxt.strip():
                break
            notes.append(nxt.strip())
        # The next steps close the lines under the key, from the one that says "shred -u": they are not notes.
        steps = next((j for j, n in enumerate(notes) if "shred -u " in n), len(notes))
        found.append({"word": m[1], "id": m[2], "type": m[3], "kind": m[4], "notes": notes[:steps], "steps": notes[steps:]})
    return found


def rows(path):
    return [ln.split("\t") for ln in read(path).split("\n") if ln.strip()]


def nothing_problems(before, after, listing, key_id):
    problems = []
    if read(before) != read(after):
        problems.append(f"the state directory changed: {before} differs from {after}")
    if not read(before).strip():
        problems.append(f"{before}: empty listing of the state directory")
    if any(r and r[0] == key_id for r in rows(listing)):
        problems.append(f"{listing}: {key_id} is listed")
    return problems


def journal_problems(path, key_id, cause, secrets):
    entries = [json.loads(ln) for ln in read(path).split("\n") if ln.strip()]
    if len(entries) != 1:
        return [f"{path}: {len(entries)} import entries, expected exactly 1"]
    entry = entries[0]
    problems = []
    for field, want in (("CUSTODIO_OPERATION", "import"), ("CUSTODIO_OUTCOME", "storage_failure"), ("CUSTODIO_CAUSE", cause), ("CUSTODIO_KEY_ID", key_id)):
        if entry.get(field) != want:
            problems.append(f"{path}: {field} is {entry.get(field)!r}, expected {want!r}")
    if "CUSTODIO_STORAGE_KIND" in entry:
        problems.append(f"{path}: the entry names a stored kind: {entry['CUSTODIO_STORAGE_KIND']!r}")
    text = json.dumps(entry)
    for secret in secrets:
        if secret and secret in text:
            problems.append(f"{path}: the entry holds a secret")
    return problems


def noweaker_problems(out, listing, journal, key_id):
    problems = []
    texts = [(out, read(out)), (journal, read(journal)), (listing, "\n".join("\t".join(r) for r in rows(listing) if r and r[0] == key_id))]
    for path, text in texts:
        for kind in WEAKER:
            if kind in text:
                problems.append(f"{path}: names the kind {kind}")
    return problems


def kind_problems(out, listing, key_id, kind):
    problems = []
    keys = key_lines(read(out))
    if [(k["id"], k["kind"]) for k in keys] != [(key_id, kind)]:
        problems.append(f"{out}: key lines {[(k['id'], k['kind']) for k in keys]!r}, expected one of {key_id} with kind {kind}")
    found = [r for r in rows(listing) if r and r[0] == key_id]
    if len(found) != 1 or len(found[0]) < 3 or found[0][2] != kind:
        problems.append(f"{listing}: {key_id} is listed as {found!r}, expected once with kind {kind}")
    return problems


def main(argv):
    usage = {"failed": 3, "nothing": 4, "noweaker": 4, "kind": 4}
    if not argv or (argv[0] != "journal" and usage.get(argv[0]) != len(argv) - 1) or (argv[0] == "journal" and len(argv) < 4):
        print(__doc__, file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "failed":
        problems = failed_problems(*args)
    elif cmd == "nothing":
        problems = nothing_problems(*args)
    elif cmd == "journal":
        problems = journal_problems(args[0], args[1], args[2], args[3:])
    elif cmd == "noweaker":
        problems = noweaker_problems(*args)
    elif cmd == "kind":
        problems = kind_problems(*args)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print("\n".join(problems))
    return 0


sys.exit(main(sys.argv[1:]))
