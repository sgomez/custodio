"""Compares the modutil package of scripts/package_expected.py (MODUTIL) with the `depends` of each format in nfpm.yaml (run by check-register-deps.sh).

usage: check_register_deps.py NFPM_YAML
Exit 1: a format lacks its modutil package under the table's exact entry, carries another format's name for it, or declares an
nss package the table does not list; 2: unusable input.
"""
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_table  # noqa: E402

LABELS = ("deb", "rpm", "arch")
NFPM = {"deb": "deb", "rpm": "rpm", "arch": "archlinux"}


def die(msg, code=2):
    print(f"check-register-deps: {msg}", file=sys.stderr)
    sys.exit(code)


if len(sys.argv) != 2:
    die("usage: check-register-deps.sh NFPM_YAML")
config_path = sys.argv[1]
if not os.path.isfile(config_path):
    die(f"{config_path}: no such file")
table = package_table.load().MODUTIL
try:
    cfg = yaml.safe_load(open(config_path))
except yaml.YAMLError as err:
    die(f"{config_path}: {err}")

problems = []
for label in LABELS:
    block = (cfg.get("overrides") or {}).get(NFPM[label]) or {}
    entries = [re.sub(r"\s+", " ", str(d).strip()) for d in block.get("depends") or []]
    want = table[label]
    if want not in entries:
        problems.append(f"{label}: the modutil package '{want}' is not in overrides.{NFPM[label]}.depends of {config_path}")
    others = {name for other, name in table.items() if other != label} - {want}
    for entry in entries:
        base = re.split(r"[ (<>=]", entry)[0]
        if entry == want:
            continue
        if base in others:
            problems.append(f"{label}: '{entry}' is the modutil package of another format; {label} needs '{want}'")
        elif base == want:
            problems.append(f"{label}: '{entry}' carries a version; the table has '{want}' without one")
        elif re.match(r"(lib)?nss", base):
            problems.append(f"{label}: '{entry}' is an nss package the table does not list (it lists '{want}')")
if problems:
    print("check-register-deps: " + "\ncheck-register-deps: ".join(problems), file=sys.stderr)
    sys.exit(1)
print("check-register-deps: modutil is declared for " + ", ".join(f"{label} ({table[label]})" for label in LABELS))
