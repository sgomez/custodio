"""Checks the per-user refresh units from a source tree (run by test-user-refresh-units.sh; F184).

usage: check_user_units.py TREE [--exec-line]
TREE holds packaging/nfpm.yaml, the unit files it lists and crates/custodio-cli/src/register_native.rs (the real repository, or a fixture copy
with one fault). Prints one line per problem on stderr and exits 1; with --exec-line prints the service's ExecStart value and exits.
"""
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

USER_DIR = "/usr/lib/systemd/user"
BINARY = "/usr/bin/custodio"
SNAP_COMMON = "%h/snap/firefox/common"
tree = sys.argv[1]
problems = []


def bad(msg):
    problems.append(msg)


def read(path):
    with open(os.path.join(tree, path), encoding="utf-8") as handle:
        return handle.read()


def sections(text):
    """{section: {key: [values]}} of a unit file (comments and blank lines skipped)."""
    out, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("["):
            current = out.setdefault(line.strip("[]"), {})
        elif "=" in line and current is not None:
            key, value = line.split("=", 1)
            current.setdefault(key.strip(), []).append(value.strip())
    return out


cfg = yaml.safe_load(read("packaging/nfpm.yaml"))
files, links = {}, {}  # dst -> src, for files and symlinks of every format
for item in cfg["contents"]:
    dst = item["dst"]
    if not dst.startswith(USER_DIR + "/") or item.get("type") == "dir":  # the rpm-only directory entries own the two `*.target.wants`
        continue
    if item.get("packager") is not None:
        bad(f"{dst} is limited to packager {item['packager']}; the user units ship in every format")
    if item.get("type") == "symlink":
        links[dst] = item["src"]
    else:
        files[dst] = item["src"]

units = {}
for dst, src in files.items():
    name = posixpath.basename(dst)
    if not os.path.isfile(os.path.join(tree, src)):
        bad(f"{dst} comes from {src}, which does not exist")
        continue
    if name.endswith((".service", ".path")):
        units[name] = (src, read(src))
if not any(n.endswith(".service") for n in units):
    bad("no user service is shipped under " + USER_DIR)
if not any(n.endswith(".path") for n in units):
    bad("no user path unit is shipped under " + USER_DIR)

# The enabling links: each one points at a shipped unit.
for dst, target in links.items():
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(dst), target))
    if resolved not in files:
        bad(f"the link {dst} points at {target} ({resolved}), which the package does not ship")


def enabled_by(name, target):
    link = f"{USER_DIR}/{target}.wants/{name}"
    return links.get(link) == f"../{name}"


module = re.search(r'INSTALLED_MODULE: &str = "([^"]+)"', read("crates/custodio-cli/src/register_native.rs"))
if not module:
    bad("INSTALLED_MODULE is not in register_native.rs")
    module_path = None
else:
    module_path = module.group(1)

service_name = next((n for n in units if n.endswith(".service")), None)
service = sections(units[service_name][1]) if service_name else {}
exec_start = (service.get("Service", {}).get("ExecStart") or [None])[0]
if "--exec-line" in sys.argv:
    print(exec_start or "")
    sys.exit(0 if exec_start else 1)

for name, (_, text) in units.items():
    parsed = sections(text)
    for target in (t for v in parsed.get("Install", {}).get("WantedBy", []) for t in v.split()):
        if not enabled_by(name, target):
            bad(f"{name} is not enabled for every user: no link {USER_DIR}/{target}.wants/{name} -> ../{name} in the package")
    if "Install" not in parsed:
        bad(f"{name} has no [Install] section, so it is not enabled for any user")

# The login trigger.
if service_name:
    wanted = [t for v in service.get("Install", {}).get("WantedBy", []) for t in v.split()]
    if "default.target" not in wanted:
        bad(f"login trigger: {service_name} is not WantedBy=default.target")
# The change trigger.
paths = [(n, sections(t)) for n, (_, t) in units.items() if n.endswith(".path")]
change = [
    (n, p)
    for n, p in paths
    if module_path and module_path in p.get("Path", {}).get("PathChanged", []) + p.get("Path", {}).get("PathModified", [])
]
if not change:
    bad(f"change trigger: no path unit watches {module_path} (PathChanged= or PathModified=)")
for n, p in change:
    started = (p["Path"].get("Unit") or [n[:-5] + ".service"])[0]
    if started != service_name:
        bad(f"change trigger: {n} starts {started}, not {service_name}")
    if not any(t in ("paths.target", "default.target") for v in p.get("Install", {}).get("WantedBy", []) for t in v.split()):
        bad(f"change trigger: {n} is not WantedBy=paths.target or default.target")

# The service.
if service_name:
    commands = service.get("Service", {}).get("ExecStart", [])
    if len(commands) != 1:
        bad(f"{service_name} has {len(commands)} ExecStart lines, expected one")
    elif commands[0].lstrip("@-:+!").split()[0] != BINARY:
        bad(f"{service_name}: ExecStart runs {commands[0].split()[0]}, not {BINARY}")
    svc = service.get("Service", {})
    restricts = [k for k in ("ProtectHome", "ProtectSystem") if any(v != "no" for v in svc.get(k, []))] + (
        ["TemporaryFileSystem"] if svc.get("TemporaryFileSystem") else []
    )
    if restricts:
        writable = [
            re.sub(r"^[-+!:]+", "", p).split(":")[0]
            for k in ("ReadWritePaths", "BindPaths")
            for v in svc.get(k, [])
            for p in v.split()
        ]
        if not any(SNAP_COMMON == w or SNAP_COMMON.startswith(w.rstrip("/") + "/") for w in writable):
            bad(f"hardening: {service_name} sets {', '.join(restricts)} but no ReadWritePaths= or BindPaths= covers {SNAP_COMMON}")

# systemd-analyze verify on copies in which only the binary path is replaced by a stub.
if shutil.which("systemd-analyze"):
    with tempfile.TemporaryDirectory() as tmp:
        runtime = os.path.join(tmp, "run")
        os.mkdir(runtime, 0o700)
        work = os.path.join(tmp, "units")
        os.mkdir(work)
        stub = os.path.join(work, "custodio-stub")
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(stub, 0o755)
        copies = []
        for name, (_, text) in sorted(units.items()):
            copy = os.path.join(work, name)
            # The copy is made line by line; the check below compares it with the whole text with the token replaced.
            lines = [stub.join(line.split(BINARY)) for line in text.splitlines(keepends=True)]
            with open(copy, "w", encoding="utf-8") as handle:
                handle.write("".join(lines))
            expected = text.replace(BINARY, stub)
            with open(copy, encoding="utf-8") as handle:
                if handle.read() != expected:
                    bad(f"{name}: the verify copy differs from the shipped unit in more than the binary path")
            if BINARY not in text and expected != text:
                bad(f"{name}: a unit without {BINARY} must be copied unchanged")
            copies.append(copy)
        env = {**os.environ, "XDG_RUNTIME_DIR": runtime}
        done = subprocess.run(["systemd-analyze", "--user", "verify", *copies], env=env, capture_output=True, text=True, check=False)
        # A warning about a unit of the host that is not ours (it names neither a copy nor a unit) is not a finding.
        ours = [line for line in (done.stdout + done.stderr).splitlines() if work in line or any(name in line for name in units)]
        output = "\n".join(ours).replace(work + "/", "").strip()
        if done.returncode != 0:
            bad(f"systemd-analyze verify exited {done.returncode}: {(done.stdout + done.stderr).strip()}")
        elif output:
            bad(f"systemd-analyze verify exited 0 but printed output: {output}")
else:
    bad("required tool 'systemd-analyze' is not installed")

if problems:
    for p in problems:
        print(f"check-user-units: {p}", file=sys.stderr)
    sys.exit(1)
print(f"check-user-units: {len(units)} units verified, {len(links)} enabling links")
