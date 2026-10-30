"""Fails when an ELF file in the .deb, .rpm or Arch package needs a glibc symbol version above the ceiling.

usage: check_glibc_ceiling.py PKG_DIR CEILING_FILE   (run as `python3 -I -B` by check-glibc-ceiling.sh)
Every regular file starting with the ELF magic is checked, wherever it is installed. Versions compare per numeric
component, so 2.10 is above 2.9. GLIBC_PRIVATE is always a failure.
"""
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_tree as tree  # noqa: E402

GATE = "glibc-ceiling"


def version_key(text):
    return tuple(int(part) for part in text.split("."))


def read_ceiling(path):
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as err:
        tree.die(GATE, f"cannot read the ceiling file '{path}': {err.strerror}")
    values = [m[1] for m in (re.fullmatch(r"ceiling\s*=\s*(\S+)", line.strip()) for line in lines) if m]
    if len(values) != 1 or not re.fullmatch(r"\d+(\.\d+)+", values[0]):
        tree.die(GATE, f"'{path}' must hold exactly one 'ceiling = X.Y' line")
    return values[0]


def is_elf(path):
    with open(path, "rb") as handle:
        return handle.read(4) == b"\x7fELF"


def glibc_needs(path):
    """The GLIBC_ names in the version needs of one ELF file (an empty list for none)."""
    try:
        done = subprocess.run(["readelf", "-W", "-V", path], capture_output=True, text=True)
    except FileNotFoundError:
        tree.die(GATE, "required tool 'readelf' is not installed")
    if done.returncode != 0 or done.stderr.strip():
        tree.die(GATE, f"readelf failed on '{path}': {(done.stderr or done.stdout).strip()}")
    names, in_needs = [], False
    for line in done.stdout.splitlines():
        if line.startswith("Version "):
            in_needs = line.startswith("Version needs section")
        elif in_needs and (m := re.search(r"\bName: (\S+)", line)) and m[1].startswith("GLIBC_"):
            names.append(m[1].removeprefix("GLIBC_"))
    return names


def main():
    pkg_dir, ceiling_file = sys.argv[1:3]
    ceiling = read_ceiling(ceiling_file)
    packages = tree.find_packages(GATE, pkg_dir)
    tmp, dirs = tree.extract_all(GATE, packages)
    failures = []
    try:
        for fmt, root in dirs.items():
            count = 0
            for base, _, files in sorted(os.walk(root)):
                for name in sorted(files):
                    full = os.path.join(base, name)
                    if os.path.islink(full) or not os.path.isfile(full) or not is_elf(full):
                        continue
                    count += 1
                    path = "/" + os.path.relpath(full, root)
                    names = glibc_needs(full)
                    private = [n for n in names if not re.fullmatch(r"\d+(\.\d+)+", n)]
                    highest = max((n for n in names if n not in private), key=version_key, default=None)
                    print(f"{GATE}: {fmt} {path} highest {highest or 'none'} (ceiling {ceiling})")
                    for n in private:
                        failures.append(f"{fmt} {path} needs GLIBC_{n}")
                    if highest and version_key(highest) > version_key(ceiling):
                        failures.append(f"{fmt} {path} needs GLIBC_{highest}, above the ceiling {ceiling}")
            if count == 0:
                tree.die(GATE, f"the {fmt} package holds no ELF file; nothing was checked")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for failure in failures:
        print(f"{GATE}: FAIL {failure}", file=sys.stderr)
    sys.exit(1 if failures else 0)


main()
