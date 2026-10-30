"""The gate of `just package-lint` (run as `python3 -I -B` by package-lint.sh).

usage: package_lint.py PKG_DIR LINT_DIR

Runs lintian on the .deb, rpmlint on the .rpm and namcap on the Arch package of PKG_DIR, on the host when the host linter has the
version of LINT_DIR/pins.txt and otherwise in a container built from LINT_DIR/<linter>.Containerfile. Every finding must be
covered by an entry of LINT_DIR/<linter>.txt (`TAG | SUBJECT-GLOB | REASON`), and every entry must cover a finding. Exit statuses
are not trusted: every output line is parsed, and a line that is not understood fails the gate.
"""
import fnmatch
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys

GATE = "package-lint"
BASE_REGISTRY = "docker.io/library/"
# Lines that are neither findings nor failures. rpmlint sets LC_ALL itself and the Fedora image lacks the locale.
BANNERS = {"lintian": [r"running with root privileges is not recommended!"],
           "rpmlint": [r"/bin/sh: warning: setlocale: LC_ALL: cannot change locale \(\S+\): No such file or directory"],
           "namcap": []}
# Exit statuses besides 0 that mean "findings reported": lintian 2 (errors), rpmlint 64 (errors). Anything else is a crash.
FINDING_STATUS = {"lintian": {2}, "rpmlint": {64}, "namcap": set()}
FORMAT = {"lintian": ("deb", "*.deb"), "rpmlint": ("rpm", "*.rpm"), "namcap": ("arch", "*.pkg.tar.zst")}
LINTIAN_SEVERITIES = "EWIPXO"


def die(msg):
    sys.exit(f"{GATE}: FAIL {msg}")


def read_pins(path):
    pins = {}
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as err:
        die(f"cannot read the pins file '{path}': {err.strerror}")
    for line in lines:
        if line.strip() and not line.lstrip().startswith("#"):
            key, sep, value = line.partition("=")
            if not sep:
                die(f"{path}: unparsable line '{line}'")
            pins[key.strip()] = value.strip()
    return pins


def read_exceptions(path):
    """[(tag, glob, reason, 'path:line')]; exits on an unparsable line or an entry without a reason."""
    out = []
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as err:
        die(f"cannot read the exception list '{path}': {err.strerror}")
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        where = f"{path}:{number}"
        parts = [p.strip() for p in line.split(" | ", 2)]
        if len(parts) != 3 or not parts[0] or not parts[1]:
            die(f"{where}: expected 'TAG | SUBJECT-GLOB | REASON'")
        if not parts[2]:
            die(f"{where}: the exception has no reason")
        if set(parts[1]) == {"*"}:
            die(f"{where}: a subject glob that is only '*' is not accepted")
        out.append((parts[0], parts[1], parts[2], where))
    return out


def covers(entry, tag, subject):
    return entry[0] == tag and fnmatch.fnmatchcase(subject, entry[1])


def find_package(linter, pkg_dir):
    fmt, pattern = FORMAT[linter]
    if not os.path.isdir(pkg_dir):
        die(f"package directory '{pkg_dir}' does not exist")
    found = sorted(glob.glob(os.path.join(pkg_dir, pattern)))
    if not found:
        die(f"{linter}: no {fmt} package ({pattern}) in '{pkg_dir}'")
    if len(found) > 1:
        die(f"{linter}: more than one {fmt} package in '{pkg_dir}': {', '.join(map(os.path.basename, found))}")
    return found[0]


def check_deb_overrides(deb):
    try:
        listing = subprocess.run(["dpkg-deb", "-c", deb], check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        die("required tool 'dpkg-deb' is not installed")
    except subprocess.CalledProcessError as err:
        die(f"dpkg-deb -c {deb} failed: {err.stderr.strip()}")
    for line in listing.splitlines():
        if "usr/share/lintian/overrides/" in line:
            die(f"the .deb contains a lintian override ({line.split()[-1]}); overrides would bypass the exception list")


# ---- running -------------------------------------------------------------------------------------------------------------


class Ctx:
    def __init__(self, pkg_dir, lint_dir, pins):
        self.pkg_dir, self.lint_dir, self.pins = pkg_dir, lint_dir, pins
        self.force_container = os.environ.get("PACKAGE_LINT_FORCE_CONTAINER") == "1"


def commands(linter, pkg, conf):
    """(version command, profile version command or None, linter command) with the package and rpmlint config paths filled in."""
    if linter == "lintian":
        return (["lintian", "--print-version"], ["dpkg-query", "-W", "-f=${Version}", "lintian"],
                ["lintian", "--no-cfg", "--profile", "debian/main", "--display-info", "--display-experimental", "--pedantic",
                 "--show-overrides", "--tag-display-limit", "0", pkg])
    if linter == "rpmlint":
        return ["rpmlint", "--version"], None, ["rpmlint", "-c", conf, pkg]
    return ["namcap", "--version"], None, ["namcap", "-i", "-m", pkg]


def pin_of(linter, pins):
    try:
        return pins[linter]
    except KeyError:
        die(f"pins.txt has no pin for {linter}")


def version_matches(found, pin):
    return found == pin or pin.startswith(found + "-")


def execute(cmd, runner_prefix=(), env=None):
    """(status, merged output); a missing command or a launch failure exits."""
    try:
        done = subprocess.run([*runner_prefix, *cmd], capture_output=True, text=True, env=env, errors="replace")
    except OSError as err:
        die(f"cannot run {cmd[0]}: {err.strerror}")
    return done.returncode, done.stdout + done.stderr


def probe(linter, runner_prefix, env, pins, where, strict):
    """Versions of the linter as run by RUNNER_PREFIX. Returns (version, profile) or, when not STRICT, None on a mismatch."""
    pin = pin_of(linter, pins)
    version_cmd, profile_cmd, _ = commands(linter, "", "")
    status, out = execute(version_cmd, runner_prefix, env)
    found = out.strip().splitlines()[-1].strip() if out.strip() else ""
    found = found.removeprefix("Lintian v")
    if status != 0 or not found:
        if strict:
            die(f"{linter}: cannot read the version in the {where} run (status {status}): {out.strip()[:200]}")
        return None
    if not version_matches(found, pin):
        if strict:
            die(f"{linter}: version {found} in the {where} run differs from the pin {pin}")
        return None
    profile = None
    if profile_cmd:
        pin_profile = pins.get(f"{linter}_profile", pin)
        status, out = execute(profile_cmd, runner_prefix, env)
        profile = out.strip()
        if status != 0 or profile != pin_profile:
            if strict:
                die(f"{linter}: profile version {profile or '(none)'} in the {where} run differs from the pin {pin_profile}")
            return None
    return found, profile


def check_rpmlint_configs(output, conf, where, strict):
    """The configs rpmlint printed must be its built-in defaults and the committed empty config. Returns the list or None."""
    configs, inside = [], False
    for line in output.splitlines():
        if line.startswith("configuration:"):
            inside = True
        elif inside and line.startswith("    "):
            configs.append(line.strip())
        elif inside:
            break
    ok = bool(configs) and all(c.endswith("/rpmlint/configdefaults.toml") or c == conf for c in configs)
    if not ok:
        if strict:
            die(f"rpmlint: the {where} run loaded configs {configs or '(none listed)'}; only its built-in defaults and "
                f"{conf} are accepted")
        return None
    return configs


def runtime():
    for name in ("podman", "docker"):
        if shutil.which(name):
            return name
    return None


def rootless_single_uid():
    """True for a rootless podman whose user has no subuid range: its user namespace holds one uid only."""
    if os.getuid() == 0:
        return False
    try:
        names = {str(os.getuid()), os.environ.get("USER", "")}
        return not any(line.split(":")[0] in names for line in open("/etc/subuid") if line.strip())
    except OSError:
        return True


def container_user(rt):
    # A nested rootless podman maps one uid: uid 0 inside is the unprivileged invoking user, and no other uid exists.
    if rt == "podman" and rootless_single_uid():
        return "0:0"
    return f"{os.getuid()}:{os.getgid()}"


def image_for(linter, rt, ctx):
    pins, lint = ctx.pins, ctx.lint_dir
    containerfile = os.path.join(lint, f"{linter}.Containerfile")
    base_key = {"lintian": "base_debian13", "rpmlint": "base_fedora44", "namcap": "base_arch"}[linter]
    args = {"BASE": BASE_REGISTRY + pins.get(base_key, "")}
    if linter == "lintian":
        args.update(DEBIAN_SNAPSHOT=pins.get("debian_snapshot", ""), LINTIAN=pins.get("lintian", ""))
    elif linter == "rpmlint":
        args.update(RPMLINT=pins.get("rpmlint", ""), RPMLINT_KOJI=pins.get("rpmlint_koji", ""),
                    RPMLINT_SHA256=pins.get("rpmlint_sha256", ""))
    else:
        args.update(ALA_DATE=pins.get("namcap_ala_date", ""), NAMCAP=pins.get("namcap", ""))
    if not all(args.values()):
        die(f"{linter}: pins.txt lacks a value for {', '.join(k for k, v in args.items() if not v)}")
    try:
        digest = hashlib.sha256(open(containerfile, "rb").read() + repr(sorted(args.items())).encode()).hexdigest()[:12]
    except OSError as err:
        die(f"{linter}: cannot read {containerfile}: {err.strerror}")
    image = f"custodio-lint-{linter}:{digest}"
    if subprocess.run([rt, "image", "inspect", image], capture_output=True).returncode == 0:
        return image
    build = [rt, "build", "-q", "-t", image, "-f", containerfile]
    for key, value in args.items():
        build += ["--build-arg", f"{key}={value}"]
    done = subprocess.run([*build, lint], capture_output=True, text=True, errors="replace")
    if done.returncode != 0:
        die(f"{linter}: cannot build the image for the pinned version {pin_of(linter, pins)} ({rt} build exited "
            f"{done.returncode}); no other version is run. {(done.stderr or done.stdout).strip()[-300:]}")
    return image


def conf_path(ctx, in_container):
    return "/lint/rpmlint-empty.toml" if in_container else os.path.join(os.path.abspath(ctx.lint_dir), "rpmlint-empty.toml")


def run_one(linter, ctx):
    """Runs one linter. Returns (output, status, where, version, profile, configs)."""
    pkg = find_package(linter, ctx.pkg_dir)
    if linter == "lintian":
        check_deb_overrides(pkg)
    env = dict(os.environ, LC_ALL="C")
    if not ctx.force_container and shutil.which(linter):
        conf = conf_path(ctx, False)
        seen = probe(linter, (), env, ctx.pins, "host", strict=False)
        if seen:
            _, _, cmd = commands(linter, os.path.abspath(pkg), conf)
            status, out = execute(cmd, (), env)
            configs = check_rpmlint_configs(out, conf, "host", strict=False) if linter == "rpmlint" else None
            if linter != "rpmlint" or configs:
                return out, status, "host", seen[0], seen[1], configs
    rt = runtime()
    if not rt:
        die(f"{linter}: no usable host linter (version {pin_of(linter, ctx.pins)}) and no container runtime (podman or docker)")
    image = image_for(linter, rt, ctx)
    prefix = [rt, "run", "--rm", "--network", "none", "--user", container_user(rt), "-e", "LC_ALL=C",
              "-v", f"{os.path.abspath(ctx.pkg_dir)}:/pkg:ro", "-v", f"{os.path.abspath(ctx.lint_dir)}:/lint:ro", image]
    seen = probe(linter, prefix, None, ctx.pins, "container", strict=True)
    conf = conf_path(ctx, True)
    _, _, cmd = commands(linter, "/pkg/" + os.path.basename(pkg), conf)
    status, out = execute(cmd, prefix)
    configs = check_rpmlint_configs(out, conf, "container", strict=True) if linter == "rpmlint" else None
    return out, status, "container", seen[0], seen[1], configs


# ---- parsing -------------------------------------------------------------------------------------------------------------


def subject_of(rest):
    rest = (rest or "").strip()
    if rest.startswith("[") and rest.endswith("]") and rest.count("[") == 1:
        rest = rest[1:-1]
    return rest or "-"


def parse(linter, output, status):
    """[(severity, tag, subject)]; exits on a line it does not understand or a counts mismatch."""
    findings, summary = [], None
    for line in output.splitlines():
        text = line.rstrip()
        if not text.strip() or any(re.fullmatch(b, text.strip()) for b in BANNERS[linter]):
            continue
        if linter == "lintian":
            m = re.fullmatch(rf"([{LINTIAN_SEVERITIES}]): (\S+): (\S+)(?: (.*))?", text)
            if m:
                findings.append((m[1], m[3], subject_of(m[4])))
                continue
        elif linter == "namcap":
            m = re.fullmatch(r"(\S+) ([EWI]): (\S+)(?: (.*))?", text)
            if m:
                findings.append((m[2], m[3], subject_of(m[4])))
                continue
        else:
            m = re.fullmatch(r"(\S+): ([EW]): (\S+)(?: (.*))?", text)
            if m:
                findings.append((m[2], m[3], subject_of(m[4])))
                continue
            if re.fullmatch(r"=+ rpmlint session starts =+|rpmlint: \S+|configuration:|checks: \d+, packages: \d+", text) \
                    or text.startswith("    "):
                continue
            m = re.fullmatch(r"\s*\d+ packages and \d+ specfiles checked; (\d+) errors, (\d+) warnings, (\d+) filtered, .*", text)
            if m:
                summary = tuple(map(int, m.groups()))
                continue
        die(f"{linter}: output line not understood: '{text[:200]}'")
    if linter == "rpmlint":
        if summary is None:
            die("rpmlint: no summary line in the output")
        errors = sum(1 for f in findings if f[0] == "E")
        warnings = sum(1 for f in findings if f[0] == "W")
        if summary[2]:
            die(f"rpmlint: the summary reports {summary[2]} filtered findings; no filter may apply")
        if (summary[0], summary[1]) != (errors, warnings):
            die(f"rpmlint: the summary counts {summary[0]} errors and {summary[1]} warnings but {errors} and {warnings} were parsed")
    if status != 0 and status not in FINDING_STATUS[linter]:
        die(f"{linter}: exited with status {status}, which is neither clean nor 'findings'")
    if status != 0 and not findings:
        die(f"{linter}: exited with the findings status {status} but no finding was parsed from its output")
    return findings


# ---- main ----------------------------------------------------------------------------------------------------------------


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: package_lint.py PKG_DIR LINT_DIR")
    pkg_dir, lint_dir = sys.argv[1:3]
    pins = read_pins(os.path.join(lint_dir, "pins.txt"))
    lists = {name: read_exceptions(os.path.join(lint_dir, f"{name}.txt")) for name in FORMAT}
    ctx = Ctx(pkg_dir, lint_dir, pins)
    failures, total, excepted = [], 0, 0
    for linter in FORMAT:
        out, status, where, version, profile, configs = run_one(linter, ctx)
        ran = f"{GATE}: ran {linter} {version} {where}" + (f" profile {profile}" if profile else "")
        print(ran + (f" configs {' '.join(configs)}" if configs else ""))
        used = set()
        for sev, tag, subject in parse(linter, out, status):
            total += 1
            entry = next((e for e in lists[linter] if covers(e, tag, subject)), None)
            if entry and sev != "O":
                used.add(entry[3])
                excepted += 1
                print(f"{linter} | {tag} | {subject}  (excepted: {entry[3]})")
            else:
                failures.append(f"{linter} | {tag} | {subject}" + ("  (override)" if sev == "O" else ""))
                print(f"{linter} | {tag} | {subject}  (NOT excepted)")
        for entry in lists[linter]:
            if entry[3] not in used:
                failures.append(f"stale exception {entry[3]}: '{entry[0]} | {entry[1]}' covers no finding")
    if failures:
        for failure in failures:
            print(f"{GATE}: FAIL {failure}", file=sys.stderr)
        sys.exit(1)
    print(f"{GATE}: 3 linters, {total} findings, {excepted} excepted, 0 stale exceptions")


if __name__ == "__main__":
    main()
