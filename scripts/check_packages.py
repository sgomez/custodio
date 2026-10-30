"""Checks the .deb, .rpm and Arch package of `just package` (run as `python3 -I` by check-packages.sh).

usage: check_packages.py PKG_DIR NFPM_YAML EXTRACT_DIR
EXTRACT_DIR holds one extracted tree per format (deb, rpm, arch) and an empty `rpmdb` directory.
"""
import glob
import os
import re
import stat
import subprocess
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_expected as expected  # noqa: E402

pkg_dir, config_path, extract_dir = sys.argv[1:4]
problems = []


def fail(label, msg):
    problems.append(f"{label}: {msg}")


def run(cmd):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit(f"check-packages: required tool '{cmd[0]}' is not installed")
    except subprocess.CalledProcessError as err:
        sys.exit(f"check-packages: {' '.join(cmd)} failed: {err.stderr.strip()}")


def norm(path):
    path = path.removeprefix(".")
    path = path if path.startswith("/") else "/" + path
    return path.rstrip("/") or "/"


def symbolic_mode(text):
    bits = 0
    for i, ch in enumerate(text[1:10]):
        if ch in "rwxst":
            bits |= 1 << (8 - i)
        if ch in "sSt":
            bits |= {2: 0o4000, 5: 0o2000, 8: 0o1000}[i]
    return bits


def entries(label, pkg):
    """[(path, kind, mode, owner, group)] with kind 'd' for a directory, 'f' for a regular file, else the type character."""
    out = []
    if label == "deb":
        for line in run(["dpkg-deb", "-c", pkg]).splitlines():
            m = re.match(r"(\S+)\s+(\S+)/(\S+)\s+\d+\s+\S+\s+\S+\s+(.*?)( -> .*| link to .*)?$", line)
            out.append((norm(m[4]), "f" if m[1][0] == "-" else m[1][0], symbolic_mode(m[1]), m[2], m[3]))
    elif label == "rpm":
        for line in run(["rpm", "--dbpath", f"{extract_dir}/rpmdb", "-qp", "--dump", pkg]).splitlines():
            f = line.split(" ")
            mode = int(f[4], 8)
            kind = {stat.S_IFREG: "f", stat.S_IFDIR: "d", stat.S_IFLNK: "l"}.get(stat.S_IFMT(mode), "?")
            out.append((norm(f[0]), kind, mode & 0o7777, f[5], f[6]))
            if f[7] != "0":
                out.append((norm(f[0]), "config", mode & 0o7777, f[5], f[6]))
    else:
        for line in run(["bsdtar", "-tvf", pkg]).splitlines():
            m = re.match(r"(\S+)\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+\w+\s+\d+\s+\S+\s+(.*?)( -> .*)?$", line)
            if m[4].startswith(".") and "/" not in m[4]:
                continue  # .PKGINFO, .MTREE, .INSTALL
            out.append((norm(m[4]), "f" if m[1][0] == "-" else m[1][0], symbolic_mode(m[1]), m[2], m[3]))
    return out


def check_config():
    cfg = yaml.safe_load(open(config_path))
    seen = {}
    for item in cfg["contents"]:
        dst, info = item["dst"], item.get("file_info", {})
        if dst in seen:
            fail("nfpm.yaml", f"{dst} is listed twice")
        seen[dst] = info.get("mode")
        if not dst.startswith("/usr/"):
            fail("nfpm.yaml", f"{dst} is not under /usr")
        if item.get("type", "file") != "file":
            fail("nfpm.yaml", f"{dst} has type {item['type']}")
        if info.get("owner") != "root" or info.get("group") != "root":
            fail("nfpm.yaml", f"{dst} is not owned by root:root")
    for dst in expected.FILES.keys() - seen.keys():
        fail("nfpm.yaml", f"{dst} is missing from the file list")
    for dst in seen.keys() - expected.FILES.keys():
        fail("nfpm.yaml", f"{dst} is not in the expected file list")
    for dst, mode in expected.FILES.items():
        if dst in seen and seen[dst] != mode:
            fail("nfpm.yaml", f"{dst} has mode {seen[dst]:o}, expected {mode:o}")
    for fmt, block in (cfg.get("overrides") or {}).items():
        if "contents" in block:
            fail("nfpm.yaml", f"overrides.{fmt} has contents")
        for key in block.keys() - expected.OVERRIDE_KEYS:
            fail("nfpm.yaml", f"overrides.{fmt}.{key} is not allowed in an override")
        for key, value in (block.get("scripts") or {}).items():
            if not isinstance(value, str) or "\n" in value or not value.startswith("packaging/"):
                fail("nfpm.yaml", f"overrides.{fmt}.scripts.{key} is not a file path")


def check_package(label, nfpm_name, pattern):
    found = sorted(glob.glob(os.path.join(pkg_dir, pattern)))
    if len(found) != 1:
        fail(label, f"expected exactly one {pattern} in {pkg_dir}, found {len(found)}")
        return
    listing = entries(label, found[0])
    files = {}
    for path, kind, mode, owner, group in listing:
        if path != "/usr" and not path.startswith("/usr/"):
            fail(label, f"{path} is not under /usr")
        if owner not in ("root", "0") or group not in ("root", "0"):
            fail(label, f"{path} is owned by {owner}:{group}, expected root:root")
        if kind == "config":
            fail(label, f"{path} is a config file")
        elif kind == "f":
            files[path] = mode
        elif kind != "d":
            fail(label, f"{path} is not a regular file or directory (type {kind})")
    for path, mode in expected.FILES.items():
        if path not in files:
            fail(label, f"{path} is missing from the package")
        elif files[path] != mode:
            fail(label, f"{path} has mode {files[path]:o}, expected {mode:o}")
    for path in files.keys() - expected.FILES.keys():
        fail(label, f"{path} is not in the expected file list")
    check_unit(label, files)
    # Config-typed entries do not show in the listing of a .deb (conffiles) or an Arch package (backup).
    if label == "deb" and os.path.exists(f"{extract_dir}/deb-control/conffiles"):
        fail(label, "the package has conffiles")
    if label == "arch" and re.search(r"^backup = ", run(["bsdtar", "-xOf", found[0], ".PKGINFO"]), re.M):
        fail(label, "the package has backup (config) files")


def check_unit(label, files):
    root = os.path.join(extract_dir, label)
    try:
        unit = open(root + expected.UNIT).read()
        activation = open(root + expected.ACTIVATION).read().splitlines()
    except FileNotFoundError:
        return  # already reported as missing
    exec_start = re.findall(r"^ExecStart=(\S+)", unit, re.M)
    if exec_start != ["/usr/lib/custodio/custodiod"]:
        fail(label, f"ExecStart of the unit is {exec_start}, expected /usr/lib/custodio/custodiod")
    for path in exec_start:
        if files.get(path) != 0o755:
            fail(label, f"ExecStart {path} is not a regular file with mode 755 in the package")
    if any(p.startswith("/usr/libexec") for p in files):
        fail(label, "the package has a /usr/libexec path")
    for line in expected.ACTIVATION_LINES:
        if line not in activation:
            fail(label, f"{expected.ACTIVATION} lacks the line {line}")


check_config()
for label, nfpm_name, pattern in expected.FORMATS:
    check_package(label, nfpm_name, pattern)

for problem in problems:
    print("check-packages: FAIL " + problem, file=sys.stderr)
sys.exit(1 if problems else 0)
