"""Shared by the package gates check_parity.py and check_glibc_ceiling.py (run as `python3 -I -B`).

Finds the .deb, .rpm and .pkg.tar.zst of a directory, lists their entries and extracts them. A gate that finds
nothing to check exits non-zero: every problem here ends the process with a message.
"""
import glob
import os
import re
import stat
import subprocess
import sys
import tempfile

PATTERNS = {"deb": "*.deb", "rpm": "*.rpm", "arch": "*.pkg.tar.zst"}


def die(gate, msg):
    sys.exit(f"{gate}: {msg}")


def run(gate, cmd, cwd=None):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=cwd).stdout
    except FileNotFoundError:
        die(gate, f"required tool '{cmd[0]}' is not installed")
    except subprocess.CalledProcessError as err:
        die(gate, f"{' '.join(cmd)} failed: {err.stderr.strip()}")


def find_packages(gate, pkg_dir):
    """{format: path}; exits when the directory is missing or a format is missing or present more than once."""
    if not os.path.isdir(pkg_dir):
        die(gate, f"package directory '{pkg_dir}' does not exist")
    found = {}
    for fmt, pattern in PATTERNS.items():
        paths = sorted(glob.glob(os.path.join(pkg_dir, pattern)))
        if not paths:
            die(gate, f"no {fmt} package ({pattern}) in '{pkg_dir}'")
        if len(paths) > 1:
            die(gate, f"more than one {fmt} package in '{pkg_dir}': {', '.join(map(os.path.basename, paths))}")
        found[fmt] = paths[0]
    return found


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


def owner(name):
    """Only uid/gid 0 and the name root are root; any other owner stays as it is."""
    return "root" if name in ("0", "root") else name


def listing(gate, fmt, pkg, rpmdb):
    """{path: (kind, mode, owner, group, target)}; kind is 'd' directory, 'f' file, 'l' symlink, else the type character."""
    out = {}
    if fmt == "rpm":
        for line in run(gate, ["rpm", "--dbpath", rpmdb, "-qp", "--dump", pkg]).splitlines():
            # path size mtime digest mode owner group isconfig isdoc rdev symlink; the path may hold spaces
            f = line.rsplit(" ", 10)
            mode = int(f[4], 8)
            kind = {stat.S_IFREG: "f", stat.S_IFDIR: "d", stat.S_IFLNK: "l"}.get(stat.S_IFMT(mode), "?")
            out[norm(f[0])] = (kind, mode & 0o7777, owner(f[5]), owner(f[6]), f[10] if kind == "l" else "")
        return out
    if fmt == "deb":
        cmd = ["dpkg-deb", "-c", pkg]
        pattern = r"(\S+)\s+(\S+)/(\S+)\s+\d+\s+\S+\s+\S+\s+(.*?)(?: -> (.*)| link to .*)?$"
    else:
        cmd = ["bsdtar", "-tvf", pkg]
        pattern = r"(\S+)\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+\w+\s+\d+\s+\S+\s+(.*?)(?: -> (.*))?$"
    for line in run(gate, cmd).splitlines():
        m = re.match(pattern, line)
        if not m:
            die(gate, f"cannot parse the {fmt} listing line '{line}'")
        if fmt == "arch" and m[4].startswith(".") and "/" not in m[4]:
            continue  # .PKGINFO, .MTREE, .INSTALL: package metadata, not installed paths
        kind = "f" if m[1][0] == "-" else m[1][0]
        out[norm(m[4])] = (kind, symbolic_mode(m[1]), owner(m[2]), owner(m[3]), m[5] or "")
    return out


def extract_all(gate, packages):
    """Extract every package into its own directory of a new temporary directory; returns (tmp, {format: dir})."""
    tmp = tempfile.mkdtemp(prefix="custodio-gate-")
    dirs = {}
    for fmt, pkg in packages.items():
        dirs[fmt] = os.path.join(tmp, fmt)
        os.mkdir(dirs[fmt])
        run(gate, ["dpkg-deb", "-x", pkg, dirs[fmt]] if fmt == "deb" else ["bsdtar", "-xf", pkg, "-C", dirs[fmt]])
    return tmp, dirs
