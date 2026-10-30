"""Derive a throwaway nfpm config from packaging/nfpm.yaml for a fixture case (run as `python3 -I`).

usage: nfpm_edit.py SRC DST OP [ARG...]
Ops: none | drop DST | unpackager DST | mode DST MODE | owner DST NAME | group DST NAME | dup DST | add DST [MODE]
     | link DST TARGET | dir DST MODE [OWNER] | type DST TYPE | override-contents FMT | override-unknown FMT | dep-add FMT DEP | dep-del FMT DEP
     | dep-set FMT OLD NEW | script-del FMT KEY | script-add FMT KEY | provides-add FMT ENTRY | predep-add DEP | predep-del DEP | predep-to-depends DEP | script-set FMT KEY FILE
"""
import sys

import yaml

src, dst, op, *args = sys.argv[1:]
cfg = yaml.safe_load(open(src))
contents = cfg["contents"]


def entry(path):
    return next(e for e in contents if e["dst"] == path)  # the first one: the Arch-only paths come once


if op == "drop":
    contents.remove(entry(args[0]))
elif op == "unpackager":  # an Arch-only file listed for every format
    entry(args[0]).pop("packager")
elif op == "mode":
    entry(args[0])["file_info"]["mode"] = int(args[1], 8)
elif op in ("owner", "group"):
    entry(args[0])["file_info"][op] = args[1]
elif op == "dup":
    contents.append(dict(entry(args[0])))
elif op == "add":
    mode = int(args[1], 8) if len(args) > 1 else 0o644
    contents.append({"src": "data/custodio.module", "dst": args[0], "file_info": {"mode": mode, "owner": "root", "group": "root"}})
elif op == "link":  # a symlink DST pointing at TARGET
    contents.append({"src": args[1], "dst": args[0], "type": "symlink", "file_info": {"owner": "root", "group": "root"}})
elif op == "dir":  # an explicit directory DST
    owner = args[2] if len(args) > 2 else "root"
    contents.append({"dst": args[0], "type": "dir", "file_info": {"mode": int(args[1], 8), "owner": owner, "group": owner}})
elif op == "type":
    entry(args[0])["type"] = args[1]
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
