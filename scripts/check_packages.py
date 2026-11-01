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


def run(cmd, optional=False):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit(f"check-packages: required tool '{cmd[0]}' is not installed")
    except subprocess.CalledProcessError as err:
        if optional:
            return ""
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


NFPM_TO_LABEL = {"deb": "deb", "rpm": "rpm", "archlinux": "arch"}
LABELS = ("deb", "rpm", "arch")


def wanted_files(label):
    """path -> mode of every file the package of this format installs."""
    return {**expected.FILES, expected.DAEMON[label]: 0o755, **(expected.ARCH_ONLY_FILES if label == "arch" else {})}


def check_config():
    cfg = yaml.safe_load(open(config_path))
    seen = {label: {} for label in LABELS}
    dirs = {}
    for item in cfg["contents"]:
        dst, info = item["dst"], item.get("file_info", {})
        packager = item.get("packager")
        if packager is not None and packager not in NFPM_TO_LABEL:
            fail("nfpm.yaml", f"{dst} is limited to packager {packager}, which is not deb, rpm or archlinux")
            continue
        labels = LABELS if packager is None else (NFPM_TO_LABEL[packager],)
        if item.get("type") == "dir":
            if dst in dirs:
                fail("nfpm.yaml", f"{dst} is listed twice")
            dirs[dst] = info.get("mode")
            if packager != "rpm" or dst not in expected.RPM_ONLY_DIRS:
                fail("nfpm.yaml", f"the directory {dst} is not one of the rpm-only directories")
            if info.get("owner") != "root" or info.get("group") != "root":
                fail("nfpm.yaml", f"{dst} is not owned by root:root")
            continue
        for label in labels:
            if dst in seen[label]:
                fail("nfpm.yaml", f"{dst} is listed twice" + ("" if packager is None else f" for {label}"))
            seen[label][dst] = info.get("mode")
            if packager is not None and dst not in expected.ARCH_ONLY_FILES and dst not in expected.DAEMON.values() and dst != expected.UNIT:
                # A packager-limited entry is for a file of that format's own: the Arch-only files, the daemon, the unit.
                fail("nfpm.yaml", f"{dst} is limited to packager {packager}, which only the Arch-only files, the daemon and the unit may be")
            if dst in expected.ARCH_ONLY_FILES and label != "arch":
                fail("nfpm.yaml", f"{dst} must be limited to the archlinux packager")
        if not dst.startswith("/usr/"):
            fail("nfpm.yaml", f"{dst} is not under /usr")
        if item.get("type", "file") != "file":
            fail("nfpm.yaml", f"{dst} has type {item['type']}")
        if info.get("owner") != "root" or info.get("group") != "root":
            fail("nfpm.yaml", f"{dst} is not owned by root:root")
        if dst == expected.UNIT:
            if len(labels) != 1:
                fail("nfpm.yaml", "the unit must be listed once per format, each from its own derived file")
            else:
                want_src = f"target/units/{packager}/custodio.service"
                if item.get("src") != want_src:
                    fail("nfpm.yaml", f"the unit of {labels[0]} comes from {item.get('src')}, expected {want_src} (derived from the one unit source)")
    for dst, mode in expected.RPM_ONLY_DIRS.items():
        if dst not in dirs:
            fail("nfpm.yaml", f"the rpm-only directory {dst} is missing")
        elif dirs[dst] != mode:
            fail("nfpm.yaml", f"the directory {dst} has mode {dirs[dst]:o}, expected {mode:o}")
    for label in LABELS:
        every = wanted_files(label)
        for dst in every.keys() - seen[label].keys():
            fail("nfpm.yaml", f"{dst} is missing from the file list of {label}")
        for dst in seen[label].keys() - every.keys():
            fail("nfpm.yaml", f"{dst} is not in the expected file list of {label}")
        for dst, mode in every.items():
            if dst in seen[label] and seen[label][dst] != mode:
                fail("nfpm.yaml", f"{dst} has mode {seen[label][dst]:o}, expected {mode:o} in {label}")
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
    listed_dirs = {}
    for path, kind, mode, owner, group in listing:
        if path != "/usr" and not path.startswith("/usr/"):
            fail(label, f"{path} is not under /usr")
        if owner not in ("root", "0") or group not in ("root", "0"):
            fail(label, f"{path} is owned by {owner}:{group}, expected root:root")
        if kind == "config":
            fail(label, f"{path} is a config file")
        elif kind == "f":
            files[path] = mode
        elif kind == "d":
            listed_dirs[path] = mode
        else:
            fail(label, f"{path} is not a regular file or directory (type {kind})")
    if label == "rpm":
        # rpm lists no implicit parent, so the directories it lists are exactly the ones it owns on purpose.
        for path, mode in expected.RPM_ONLY_DIRS.items():
            if path not in listed_dirs:
                fail(label, f"the directory {path} is missing from the package")
            elif listed_dirs[path] != mode:
                fail(label, f"the directory {path} has mode {listed_dirs[path]:o}, expected {mode:o}")
        for path in listed_dirs.keys() - expected.RPM_ONLY_DIRS.keys():
            fail(label, f"the directory {path} is not one of the rpm-only directories")
    wanted = wanted_files(label)
    for path, mode in wanted.items():
        if path not in files:
            fail(label, f"{path} is missing from the package")
        elif files[path] != mode:
            fail(label, f"{path} has mode {files[path]:o}, expected {mode:o}")
    for path in files.keys() - wanted.keys():
        fail(label, f"{path} is not in the expected file list")
    check_unit(label, files)
    # Config-typed entries do not show in the listing of a .deb (conffiles) or an Arch package (backup).
    if label == "deb" and os.path.exists(f"{extract_dir}/deb-control/conffiles"):
        fail(label, "the package has conffiles")
    if label == "arch" and re.search(r"^backup = ", run(["bsdtar", "-xOf", found[0], ".PKGINFO"]), re.M):
        fail(label, "the package has backup (config) files")
    check_deps(label, found[0])
    check_needed(label, found[0], files)
    check_scripts(label, found[0])
    return versions(label, found[0])


def squash(text):
    return re.sub(r"\s+", " ", text.strip())


def dependencies(label, pkg, field="Depends"):
    if label == "deb":
        return [squash(d) for d in run(["dpkg-deb", "-f", pkg, field], optional=True).split(",") if d.strip()]
    if label == "rpm":
        lines = run(["rpm", "--dbpath", f"{extract_dir}/rpmdb", "-qpR", pkg]).splitlines()
        return [squash(d) for d in lines if d.strip() and not d.startswith(("rpmlib(", "/"))]
    return [squash(m[1]) for m in re.finditer(r"^depend = (.*)$", run(["bsdtar", "-xOf", pkg, ".PKGINFO"]), re.M)]


def check_deps(label, pkg):
    have = dependencies(label, pkg)
    for dep in expected.DEPS[label]:
        if dep not in have:
            fail(label, f"dependency '{dep}' is missing (has: {', '.join(have) or 'none'})")
    for dep in have:
        if re.split(r"[ (<>=]", dep)[0] in expected.FORBIDDEN_DEPS[label]:
            fail(label, f"dependency '{dep}' is not allowed")
    # The Pre-Depends field is its own list: whatever it holds is not a Depends entry, and the other way round.
    pre = dependencies(label, pkg, "Pre-Depends") if label == "deb" else []
    want = expected.PRE_DEPS.get(label, [])
    if pre != want:
        fail(label, f"Pre-Depends is '{', '.join(pre) or 'empty'}', expected '{', '.join(want) or 'empty'}'")
    for dep in want:
        if dep in have:
            fail(label, f"'{dep}' is in Depends as well as in Pre-Depends")


def check_needed(label, pkg, files):
    index = ("deb", "rpm", "arch").index(label)
    have = set(dependencies(label, pkg))
    for path in (*expected.ELF_FILES, expected.DAEMON[label]):
        full = os.path.join(extract_dir, label) + path
        if path not in files or not os.path.exists(full):
            continue  # already reported as missing
        for soname in re.findall(r"Shared library: \[(.*?)\]", run(["readelf", "-d", full])):
            if soname in expected.NEEDED_EXEMPT:
                continue
            if soname not in expected.NEEDED:
                fail(label, f"{path} needs {soname}, which is not in the soname table")
            elif expected.NEEDED[soname][index] not in have:
                fail(label, f"{path} needs {soname}, so '{expected.NEEDED[soname][index]}' must be a dependency")


def check_scripts(label, pkg):
    if label == "deb":
        got = {n for n in ("preinst", "postinst", "prerm", "postrm") if os.path.exists(f"{extract_dir}/deb-control/{n}")}
        want = expected.DEB_SCRIPTS
    elif label == "rpm":
        tags = {"PREIN": "pre", "POSTIN": "post", "PREUN": "preun", "POSTUN": "postun", "PRETRANS": "pretrans", "POSTTRANS": "posttrans"}
        got = {n for t, n in tags.items() if run(["rpm", "--dbpath", f"{extract_dir}/rpmdb", "-qp", "--qf", f"%{{{t}}}", pkg]) != "(none)"}
        want = expected.RPM_SCRIPTS
    else:
        install = run(["bsdtar", "-xOf", pkg, ".INSTALL"], optional=True)
        got = set(re.findall(r"^\s*(?:function\s+)?(\w+)\s*\(\)", install, re.M)) - expected.ARCH_HELPERS
        want = expected.ARCH_FUNCTIONS
    if got != want:
        fail(label, f"lifecycle scripts are {sorted(got)}, expected {sorted(want)}")


def versions(label, pkg):
    """The version-release string of the package, with the pre-release marker of the format turned into '_'."""
    if label == "deb":
        text = run(["dpkg-deb", "-f", pkg, "Version"]).strip()
    elif label == "rpm":
        text = run(["rpm", "--dbpath", f"{extract_dir}/rpmdb", "-qp", "--qf", "%{VERSION}-%{RELEASE}", pkg]).strip()
    else:
        text = re.search(r"^pkgver = (.*)$", run(["bsdtar", "-xOf", pkg, ".PKGINFO"]), re.M)[1]
    if not text.endswith("-1"):
        fail(label, f"version {text} does not end in the packaging revision -1")
    return text.replace("~", "_")


def check_unit(label, files):
    root = os.path.join(extract_dir, label)
    try:
        unit = open(root + expected.UNIT).read()
        activation = open(root + expected.ACTIVATION).read().splitlines()
    except FileNotFoundError:
        return  # already reported as missing
    daemon = expected.DAEMON[label]
    exec_start = re.findall(r"^ExecStart=(\S+)", unit, re.M)
    if exec_start != [daemon]:
        fail(label, f"ExecStart of the unit is {exec_start}, expected {daemon}, the daemon of this package")
    for path in exec_start:
        if files.get(path) != 0o755:
            fail(label, f"ExecStart {path} is not a regular file with mode 755 in the package")
    for other in set(expected.DAEMON.values()) - {daemon}:
        if other in files:
            fail(label, f"the daemon is also at {other}, the path of another format")
    if label == "arch" and any(p.startswith("/usr/libexec") for p in files):
        fail(label, "the package has a /usr/libexec path")
    for line in expected.ACTIVATION_LINES:
        if line not in activation:
            fail(label, f"{expected.ACTIVATION} lacks the line {line}")


check_config()
seen_versions = {}
for label, nfpm_name, pattern in expected.FORMATS:
    seen_versions[label] = check_package(label, nfpm_name, pattern)
if len({v for v in seen_versions.values() if v}) > 1:
    fail("versions", f"the packages differ in version: {seen_versions}")

for problem in problems:
    print("check-packages: FAIL " + problem, file=sys.stderr)
sys.exit(1 if problems else 0)
