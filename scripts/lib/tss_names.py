"""The TPM2 Software Stack dependency names of one format, sorted, one per line (run as `python3 -I` by test-docs-install.sh).

usage: tss_names.py FORMAT NFPM_YAML     FORMAT: deb | rpm | arch
They are the names the table (scripts/package_expected.py) expects for that format plus its systemd bound, and they must all be
declared in NFPM_YAML (a name the table expects but the file lacks is an error).
"""
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import package_table  # noqa: E402

label, config = sys.argv[1:3]
table = package_table.load()
names = set(table.TSS_LIBS[label]) | {table.SYSTEMD[label]}
cfg = yaml.safe_load(open(config))
nfpm = {"deb": "deb", "rpm": "rpm", "arch": "archlinux"}[label]
declared = {re.sub(r"\s+", " ", d.strip()) for d in cfg["overrides"][nfpm]["depends"]}
if label == "deb":
    declared |= {re.sub(r"\s+", " ", d.strip()) for d in cfg["deb"]["predepends"]}
missing = names - declared
if missing:
    sys.exit(f"tss_names: the table expects {sorted(missing)} for {label}, {config} does not declare them")
print("\n".join(sorted(names)))
