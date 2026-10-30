"""Derive a throwaway nfpm config from packaging/nfpm.yaml for a fixture case (run as `python3 -I`).

usage: nfpm_edit.py SRC DST OP [ARG...]
Ops: none | drop DST | mode DST MODE | owner DST NAME | group DST NAME | dup DST | add DST [MODE]
     | type DST TYPE | override-contents FMT | override-unknown FMT | dep-add FMT DEP | dep-del FMT DEP
     | dep-set FMT OLD NEW | script-del FMT KEY
"""
import sys

import yaml

src, dst, op, *args = sys.argv[1:]
cfg = yaml.safe_load(open(src))
contents = cfg["contents"]


def entry(path):
    return next(e for e in contents if e["dst"] == path)


if op == "drop":
    contents.remove(entry(args[0]))
elif op == "mode":
    entry(args[0])["file_info"]["mode"] = int(args[1], 8)
elif op in ("owner", "group"):
    entry(args[0])["file_info"][op] = args[1]
elif op == "dup":
    contents.append(dict(entry(args[0])))
elif op == "add":
    mode = int(args[1], 8) if len(args) > 1 else 0o644
    contents.append({"src": "data/custodio.module", "dst": args[0], "file_info": {"mode": mode, "owner": "root", "group": "root"}})
elif op == "type":
    entry(args[0])["type"] = args[1]
elif op == "override-contents":
    cfg["overrides"][args[0]]["contents"] = [{"src": "data/custodio.module", "dst": "/usr/share/x"}]
elif op == "override-unknown":
    cfg["overrides"][args[0]]["version"] = "9.9.9"
elif op == "dep-add":
    cfg["overrides"][args[0]]["depends"].append(args[1])
elif op == "dep-del":
    cfg["overrides"][args[0]]["depends"].remove(args[1])
elif op == "dep-set":
    deps = cfg["overrides"][args[0]]["depends"]
    deps[deps.index(args[1])] = args[2]
elif op == "script-del":
    ov = cfg["overrides"][args[0]]
    (ov["archlinux"]["scripts"] if args[1] == "postupgrade" else ov["scripts"]).pop(args[1])
elif op != "none":
    sys.exit("nfpm_edit: unknown op " + op)
yaml.safe_dump(cfg, open(dst, "w"), sort_keys=False)
