"""Derive a throwaway nfpm config from packaging/nfpm.yaml for a fixture case (run as `python3 -I`).

usage: nfpm_edit.py SRC DST OP [ARG...]
Ops: none | oldpath | daemon FMT PATH | unit-src FMT SRC | all-formats DST | drop DST | unpackager DST | mode DST MODE | owner DST NAME | group DST NAME | dup DST | add DST [MODE]
     | link DST TARGET | dir DST MODE [OWNER] | type DST TYPE | override-contents FMT | override-unknown FMT | dep-add FMT DEP | dep-del FMT DEP
     | dep-set FMT OLD NEW | script-del FMT KEY | script-add FMT KEY | provides-add FMT ENTRY | predep-add DEP | predep-del DEP | predep-to-depends DEP | script-set FMT KEY FILE
"""
import sys

import yaml

src, dst, op, *args = sys.argv[1:]
cfg = yaml.safe_load(open(src))
contents = cfg["contents"]


def entries(path):
    """Every entry for the path: the daemon and the unit are listed once per format (F61)."""
    found = [e for e in contents if e["dst"] == path]
    if not found:
        sys.exit(f"nfpm_edit: no entry for {path}")
    return found


def entry(path):
    return entries(path)[0]


PACKAGER = {"deb": "deb", "rpm": "rpm", "arch": "archlinux", "archlinux": "archlinux"}

if op == "drop":
    for e in entries(args[0]):
        contents.remove(e)
elif op == "unpackager":  # an Arch-only file listed for every format
    entry(args[0]).pop("packager")
elif op == "mode":
    for e in entries(args[0]):
        e["file_info"]["mode"] = int(args[1], 8)
elif op in ("owner", "group"):
    for e in entries(args[0]):
        e["file_info"][op] = args[1]
elif op == "dup":
    contents.append(dict(entry(args[0])))
elif op == "daemon":  # daemon FMT PATH: the daemon of that format is installed at PATH
    daemon = [e for e in contents if e.get("src") == "target/release/custodiod" and e.get("packager") == PACKAGER[args[0]]]
    daemon[0]["dst"] = args[1]
elif op == "unit-src":  # unit-src FMT SRC: the unit of that format comes from SRC
    unit = [e for e in contents if e["dst"] == "/usr/lib/systemd/system/custodio.service" and e.get("packager") == PACKAGER[args[0]]]
    unit[0]["src"] = args[1]
elif op == "oldpath":  # the package as the current M2 ones were: the .deb and the .rpm have the daemon at /usr/lib/custodio, the unit starts it there (F61)
    for e in contents:
        if e.get("src") == "target/release/custodiod" and e.get("packager") in ("deb", "rpm"):
            e["dst"] = "/usr/lib/custodio/custodiod"
        if e["dst"] == "/usr/lib/systemd/system/custodio.service" and e.get("packager") in ("deb", "rpm"):
            e["src"] = "target/units/archlinux/custodio.service"  # the unit source holds the old path
    contents[:] = [e for e in contents if e["dst"] != "/usr/libexec/custodio"]  # the rpm-only directory of the new path
elif op == "all-formats":  # all-formats DST: the entry for DST of the first format is listed for every format, the others dropped
    first, *rest = entries(args[0])
    first.pop("packager", None)
    for e in rest:
        contents.remove(e)
elif op == "add":
    mode = int(args[1], 8) if len(args) > 1 else 0o644
    contents.append({"src": "data/custodio.module", "dst": args[0], "file_info": {"mode": mode, "owner": "root", "group": "root"}})
elif op == "link":  # a symlink DST pointing at TARGET
    contents.append({"src": args[1], "dst": args[0], "type": "symlink", "file_info": {"owner": "root", "group": "root"}})
elif op == "dir":  # an explicit directory DST
    owner = args[2] if len(args) > 2 else "root"
    contents.append({"dst": args[0], "type": "dir", "file_info": {"mode": int(args[1], 8), "owner": owner, "group": owner}})
elif op == "type":
    for e in entries(args[0]):
        e["type"] = args[1]
elif op == "override-contents":
    cfg["overrides"][args[0]]["contents"] = [{"src": "data/custodio.module", "dst": "/usr/share/x"}]
elif op == "override-unknown":
    cfg["overrides"][args[0]]["suggests"] = ["bash"]
elif op == "dep-add":
    cfg["overrides"][args[0]]["depends"].append(args[1])
elif op == "dep-del":
    cfg["overrides"][args[0]]["depends"].remove(args[1])
elif op == "dep-set":
    deps = cfg["overrides"][args[0]]["depends"]
    deps[deps.index(args[1])] = args[2]
elif op == "provides-add":
    cfg["overrides"][args[0]].setdefault("provides", []).append(args[1])
elif op == "predep-add":  # the deb's Pre-Depends (top-level deb section)
    cfg["deb"]["predepends"].append(args[0])
elif op == "predep-del":
    cfg["deb"]["predepends"].remove(args[0])
elif op == "predep-to-depends":  # the dependency is only in Depends
    cfg["deb"]["predepends"].remove(args[0])
    cfg["overrides"]["deb"]["depends"].append(args[0])
elif op == "script-del":
    ov = cfg["overrides"][args[0]]
    (ov["archlinux"]["scripts"] if args[1] in ("preupgrade", "postupgrade") else ov["scripts"]).pop(args[1])
elif op == "script-add":  # a script file of the real set, under a key the gate does not allow
    ov = cfg["overrides"][args[0]]
    target = ov["archlinux"].setdefault("scripts", {}) if args[1] in ("preupgrade", "postupgrade") else ov["scripts"]
    target[args[1]] = ov["scripts"].get("postinstall", "packaging/deb/postinst")
elif op == "script-set":  # a script file of the test, under a key the real set has
    cfg["overrides"][args[0]]["scripts"][args[1]] = args[2]
elif op != "none":
    sys.exit("nfpm_edit: unknown op " + op)
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
