"""Fails when the .deb, .rpm and Arch package install different paths, modes, owners or symlink targets.

usage: check_parity.py PKG_DIR EXCEPTIONS_FILE   (run as `python3 -I -B` by check-parity.sh)

Compared per installed path: presence, kind, mode, owner, group and symlink target. Package metadata (.PKGINFO, .MTREE,
.INSTALL, deb control, rpm header) is not an installed path. Owner: only uid/gid 0 and the name root are root.
Directory rule (confirmed on the real listings: rpm lists no directories, deb and Arch list the implicit parents): a
directory listed in all three formats is compared like any entry; one listed in only some formats is ignored if every
listing has it as 0755 root root, else it is compared (and is a presence difference).
Exceptions: see packaging/parity-exceptions.txt. An exception is stale when no difference it excuses exists.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_tree as tree  # noqa: E402

GATE = "parity"
FIELDS = ("presence", "kind", "mode", "owner", "group", "target")


def read_exceptions(path):
    out = []
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as err:
        tree.die(GATE, f"cannot read the exceptions file '{path}': {err.strerror}")
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ")]
        where = f"{path}:{number}"
        if len(parts) != 4 or not parts[0].startswith("/"):
            tree.die(GATE, f"{where}: expected 'PATH | PACKAGES | FIELD | REASON'")
        pkgs = {p.strip() for p in parts[1].split(",")}
        if not pkgs or not pkgs <= set(tree.PATTERNS) or len(pkgs) > 2:
            tree.die(GATE, f"{where}: PACKAGES must be one or two of deb, rpm, arch")
        if parts[2] not in FIELDS:
            tree.die(GATE, f"{where}: FIELD must be one of {', '.join(FIELDS)}")
        if not parts[3]:
            tree.die(GATE, f"{where}: the exception has no reason")
        out.append((parts[0], frozenset(pkgs), parts[2], where))
    return out


def differences(lists):
    """{(path, field): {format: value}} for every field whose values differ between the formats that have the path."""
    fmts = list(lists)
    diffs = {}
    for path in sorted(set().union(*lists.values())):
        have = {f: lists[f][path] for f in fmts if path in lists[f]}
        if (len(have) < len(fmts) and all(e[0] == "d" and e[1:4] == (0o755, "root", "root") for e in have.values())):
            continue  # an implicit parent directory that rpm and pacman create themselves
        if len(have) < len(fmts):
            diffs[(path, "presence")] = {f: "present" if f in have else "absent" for f in fmts}
        for i, field in enumerate(("kind", "mode", "owner", "group", "target")):
            values = {f: e[i] for f, e in have.items()}
            if len(set(values.values())) > 1:
                diffs[(path, field)] = values
    return diffs


def show(field, value):
    return f"{value:04o}" if field == "mode" else str(value) or "-"


def describe(entry):
    return f"{entry[0]} {entry[1]:04o} {entry[2]}:{entry[3]}" + (f" -> {entry[4]}" if entry[4] else "")


def main():
    pkg_dir, exceptions_file = sys.argv[1:3]
    exceptions = read_exceptions(exceptions_file)
    packages = tree.find_packages(GATE, pkg_dir)
    tmp = tempfile.mkdtemp(prefix="custodio-gate-")
    try:
        lists = {fmt: tree.listing(GATE, fmt, pkg, tmp) for fmt, pkg in packages.items()}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for fmt, entries in lists.items():
        if not entries:
            tree.die(GATE, f"the {fmt} package lists no installed path; nothing was compared")
    diffs = differences(lists)
    used = set()
    for key, values in sorted(diffs.items()):
        path, field = key
        for exc in exceptions:
            outside = {v for f, v in values.items() if f not in exc[1]}
            if exc[0] == path and exc[2] == field and len(outside) <= 1:
                used.add(exc[3])
                break
        else:
            detail = ", ".join(
                f"{fmt} {describe(lists[fmt][path]) if v == 'present' else show(field, v)}" for fmt, v in values.items()
            )
            print(f"{GATE}: FAIL {path}: {field} differs: {detail}", file=sys.stderr)
            used.add(None)
    stale = [exc for exc in exceptions if exc[3] not in used]
    for exc in stale:
        print(f"{GATE}: FAIL {exc[3]}: stale exception for {exc[0]} ({exc[2]}), it excuses no difference", file=sys.stderr)
    bad = None in used or stale
    total = len(set().union(*lists.values()))
    print(f"{GATE}: {len(lists)} packages, {total} paths compared, {len(diffs)} differences, {len(exceptions)} exceptions")
    sys.exit(1 if bad else 0)


main()
