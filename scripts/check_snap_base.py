"""Fails when an ELF file needs a GLIBC_x.y version above the glibc of the Firefox snap's base or a NEEDED library the base does not list.

usage: check_snap_base.py ELF [BASES_FILE]   (run by check-snap-base.sh; BASES_FILE defaults to packaging/snap-bases.txt)
Exit 1: the file does not fit; 2: unusable input.
"""
import os
import re
import subprocess
import sys

ELF, BASES = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packaging", "snap-bases.txt"))


def die(msg, code=2):
    print(f"check-snap-base: {msg}", file=sys.stderr)
    sys.exit(code)


def version(text):
    return tuple(int(p) for p in text.split("."))


def parse(path):
    """({base: glibc}, {base: {soname}})"""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as err:
        die(f"cannot read the bases file '{path}': {err.strerror}")
    glibc, libs = {}, {}
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        where = f"{path}:{number}"
        key, _, rest = line.partition(" = ")
        fields = [f.strip() for f in rest.split(" | ")]
        if key == "base":
            if len(fields) != 3 or not all(fields):
                die(f"{where}: expected 'base = NAME | GLIBC | SOURCE', each field filled")
            if not re.fullmatch(r"\d+\.\d+", fields[1]):
                die(f"{where}: the glibc '{fields[1]}' is not MAJOR.MINOR")
            glibc[fields[0]] = fields[1]
        elif key == "library":
            if len(fields) != 4 or not all(fields):
                die(f"{where}: expected 'library = BASE | SONAME | STATUS | SOURCE', each field filled")
            if fields[2] not in ("verified", "inferred"):
                die(f"{where}: STATUS must be verified or inferred")
            libs.setdefault(fields[0], set()).add(fields[1])
        else:
            die(f"{where}: unknown line '{line}'")
    if not glibc:
        die(f"{path} lists no base")
    for name in libs.keys() - glibc.keys():
        die(f"{path}: a library line names the base '{name}', which has no base line")
    return glibc, libs


def readelf(*args):
    try:
        return subprocess.run(["readelf", "-W", *args, ELF], check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        die("required tool 'readelf' is not installed")
    except subprocess.CalledProcessError as err:
        die(f"readelf {' '.join(args)} failed on {ELF}: {err.stderr.strip()}")


glibc, libs = parse(BASES)
if not os.path.isfile(ELF):
    die(f"{ELF}: no such file")
with open(ELF, "rb") as handle:
    if handle.read(4) != b"\x7fELF":
        die(f"{ELF} is not an ELF file")
needed_versions = sorted(set(re.findall(r"Name: (GLIBC_[0-9A-Za-z_.]+) ", readelf("-V"))))
needed_libs = sorted(set(re.findall(r"Shared library: \[(.*?)\]", readelf("-d"))))
symbols = readelf("--dyn-syms")
problems = []
for base, base_glibc in glibc.items():
    for name in needed_versions:
        if not re.fullmatch(r"GLIBC_\d+(\.\d+)+", name):
            problems.append(f"{name} is not a public glibc version; the base {base} does not provide it")
        elif version(name[6:]) > version(base_glibc):
            using = sorted({m for m in re.findall(rf"(\S+)@{re.escape(name)} ", symbols)})[:3]
            problems.append(f"{ELF} needs {name} ({', '.join(using) or 'no symbol shown'}), above glibc {base_glibc} of the base {base}")
    for soname in needed_libs:
        if soname not in libs.get(base, set()):
            problems.append(f"{ELF} needs the library {soname}, which the base {base} is not recorded to provide")
if problems:
    print("check-snap-base: " + "\ncheck-snap-base: ".join(problems), file=sys.stderr)
    sys.exit(1)
top = max((version(n[6:]) for n in needed_versions), default=None)
print(
    f"check-snap-base: {ELF} fits {', '.join(f'{b} (glibc {g})' for b, g in glibc.items())}: highest "
    + (".".join(map(str, top)) if top else "none")
    + f", {len(needed_libs)} libraries"
)
