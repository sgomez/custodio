"""Maps every libtss2 soname a binary needs to the package that must be declared in nfpm.yaml, for each format (run by check-tss-deps.sh).

usage: check_tss_deps.py BINARY NFPM_YAML
Exit 1: a dependency is missing, a libtss2 soname has no table entry, or the binary needs no libtss2 soname; 2: unusable input.
"""
import os
import re
import subprocess
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_table  # noqa: E402

expected = package_table.load()
binary, config_path = sys.argv[1:3]
LABELS = ("deb", "rpm", "arch")
NFPM = {"deb": "deb", "rpm": "rpm", "arch": "archlinux"}


def die(msg, code=2):
    print(f"check-tss-deps: {msg}", file=sys.stderr)
    sys.exit(code)


if not os.path.isfile(binary):
    die(f"{binary}: no such file")
if not os.path.isfile(config_path):
    die(f"{config_path}: no such file")
try:
    out = subprocess.run(["readelf", "-d", binary], check=True, capture_output=True, text=True).stdout
except FileNotFoundError:
    die("required tool 'readelf' is not installed")
except subprocess.CalledProcessError as err:
    die(f"readelf -d {binary} failed: {err.stderr.strip()}")

sonames = sorted(s for s in re.findall(r"Shared library: \[(.*?)\]", out) if s.startswith("libtss2"))
if not sonames:
    die(f"{binary} needs no libtss2 soname: the TPM2 Software Stack is not linked, so there is nothing to declare", 3)

cfg = yaml.safe_load(open(config_path))


def declared(label):
    names = [re.sub(r"\s+", " ", d.strip()) for d in cfg["overrides"][NFPM[label]].get("depends", [])]
    if label == "deb":
        names += [re.sub(r"\s+", " ", d.strip()) for d in cfg.get("deb", {}).get("predepends", [])]
    return {re.split(r"[ (<>=]", n)[0] for n in names}


problems = []
for soname in sonames:
    if soname not in expected.NEEDED:
        problems.append(f"{soname} is not in the soname table (scripts/package_expected.py)")
        continue
    for index, label in enumerate(LABELS):
        package = expected.NEEDED[soname][index]
        # An `a | b` alternative in the table is satisfied by either name.
        if not any(alt.strip() in declared(label) for alt in package.split("|")):
            problems.append(f"{label}: {soname} needs package '{package}', which {config_path} does not declare")
if problems:
    print("check-tss-deps: " + "\ncheck-tss-deps: ".join(problems), file=sys.stderr)
    sys.exit(1)
print(f"check-tss-deps: {len(sonames)} libtss2 sonames, declared for deb, rpm and arch")
