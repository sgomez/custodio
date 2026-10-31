#!/usr/bin/env python3
"""Runs the checks that the changed files can break: lints of those files, `cargo clippy`/`cargo test` of the
affected crates (and the crates that depend on them), and the script tests that are, or mention, an affected file.

A file is affected when it changed or, under scripts/, e2e/ or packaging/, when it mentions an affected file (by path, by a
parent directory of two or more components, or by base name for siblings in scripts/ and e2e/). A crate is
affected when a file under it changed or its sources mention an affected file outside crates/.

Usage: changed_checks.py [--lint-only] [--dry-run] (--base REV | --staged | --files F...)
`just check` stays the gate: this is for the steps in between and the pre-commit hook.
"""

import argparse
import os
import re
import subprocess
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A change here can break anything: run `just check` instead.
FULL = {"mise.toml", "mise.lock", "rust-toolchain.toml"}
# A change here can break every crate.
ALL_CRATES = {"Cargo.toml", "Cargo.lock", "deny.toml", "clippy.toml", "rustfmt.toml", ".cargo/config.toml"}
TEST_RECIPES = ["package-gate-test", "test-scripts", "shell-scripts-test"]


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], check=True, capture_output=True, text=True).stdout.split("\n")


def changed_files(opts):
    if opts.files:
        return set(opts.files)
    if opts.staged:
        return {f for f in git("diff", "--cached", "--name-only") if f}
    files = git("diff", "--name-only", opts.base) + git("ls-files", "--others", "--exclude-standard")
    return {f for f in files if f}


def read(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, IsADirectoryError):
        return ""


def needles(path):
    out = {path}
    parts = path.split("/")
    out.update("/".join(parts[:i]) for i in range(2, len(parts)))
    if len(parts) == 2 and parts[0] in ("scripts", "e2e"):
        out.add(parts[1])
    return out


def mentions(text, path):
    return any(re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", text) for n in needles(path))


def affected_files(changed, tracked, tests):
    code = [f for f in tracked if f.startswith(("scripts/", "e2e/", "packaging/"))]
    texts = {f: read(f) for f in code}
    affected, todo = set(changed), list(changed)
    while todo:
        path = todo.pop()
        # Only the justfile runs a test; other files name tests in comments.
        if path in tests:
            continue
        for f in code:
            if f not in affected and mentions(texts[f], path):
                affected.add(f)
                todo.append(f)
    return affected


def crates():
    members = tomllib.loads(read("Cargo.toml"))["workspace"]["members"]
    out = {}
    for d in members:
        manifest = tomllib.loads(read(f"{d}/Cargo.toml"))
        deps = [v["path"] for k in ("dependencies", "dev-dependencies") for v in manifest.get(k, {}).values()
                if isinstance(v, dict) and "path" in v]
        out[manifest["package"]["name"]] = (d, {os.path.normpath(os.path.join(d, p)) for p in deps})
    return out


def affected_crates(changed, affected):
    ws = crates()
    if changed & ALL_CRATES:
        return set(ws)
    outside = [f for f in affected if not f.startswith("crates/")]
    hit = set()
    for name, (d, _) in ws.items():
        if any(f.startswith(d + "/") for f in changed):
            hit.add(name)
            continue
        srcs = subprocess.run(["git", "-C", ROOT, "ls-files", "--", f"{d}/*.rs"], capture_output=True, text=True).stdout.split()
        if any(mentions(read(s), f) for s in srcs for f in outside):
            hit.add(name)
    grew = True
    while grew:
        dirs = {ws[n][0] for n in hit}
        new = {n for n, (_, deps) in ws.items() if n not in hit and deps & dirs}
        hit |= new
        grew = bool(new)
    return hit


def script_tests():
    out = []
    for r in TEST_RECIPES:
        body = subprocess.run(["just", "--show", r], cwd=ROOT, check=True, capture_output=True, text=True).stdout
        out += [line.strip() for line in body.splitlines()[1:] if line.strip().startswith("scripts/")]
    return out


def plan(opts):
    changed = changed_files(opts)
    if changed & FULL:
        return [["just", "check"]]
    tracked = set(git("ls-files")) - {""}
    existing = {f for f in changed if os.path.isfile(os.path.join(ROOT, f))}
    tests = script_tests()
    affected = affected_files(changed, tracked, {t.split()[0] for t in tests})
    cmds = []
    shells = set(subprocess.run([os.path.join(ROOT, "scripts/list-shell-scripts.sh")], cwd=ROOT, check=True,
                                capture_output=True, text=True).stdout.split())
    # All of them, as `just lint` does: alone, a script does not see what the libraries it sources define.
    if existing & shells:
        cmds.append(["shellcheck", *sorted(shells)])
    if toml := sorted(f for f in existing if f.endswith(".toml")):
        cmds.append(["taplo", "fmt", "--check", *toml])
    if any(f.startswith(".github/workflows/") for f in changed):
        cmds += [["actionlint"], ["zizmor", "--offline", ".github/workflows"]]
    if changed & ALL_CRATES or any(f.endswith("/Cargo.toml") for f in changed):
        cmds += [["cargo", "deny", "check"], ["cargo", "machete"]]
    if existing:
        cmds.append(["scripts/check-files.sh"])
    hit = sorted(affected_crates(changed, affected))
    if hit:
        p = [a for n in hit for a in ("-p", n)]
        cmds.append(["cargo", "fmt", "--check", *p])
        cmds.append(["cargo", "clippy", *p, "--all-targets", "--locked", "--", "-D", "warnings"])
        if "custodio-pkcs11" in hit:
            cmds.append(["cargo", "clippy", "-p", "custodio-pkcs11", "--features", "fuzzing", "--all-targets", "--locked",
                         "--", "-D", "warnings"])
    if opts.lint_only:
        return cmds
    if any(f.startswith("data/") for f in affected):
        cmds.append(["just", "system-gates"])
    if hit:
        cmds.append(["cargo", "test", *p, "--locked"])
        if "custodio-pkcs11" in hit:
            cmds.append(["cargo", "test", "-p", "custodio-pkcs11", "--features", "fuzzing", "--lib", "--locked"])
    for t in tests:
        if t.split()[0] in affected:
            cmds.append(t.split())
    return cmds


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--base")
    src.add_argument("--staged", action="store_true")
    src.add_argument("--files", nargs="+")
    ap.add_argument("--lint-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    opts = ap.parse_args()
    cmds = plan(opts)
    failed = []
    for c in cmds:
        print("changed-checks: " + " ".join(c), flush=True)
        if opts.dry_run:
            continue
        try:
            ok = subprocess.run(c, cwd=ROOT).returncode == 0
        except FileNotFoundError:
            print(f"changed-checks: {c[0]} is not installed", file=sys.stderr)
            ok = False
        if not ok:
            failed.append(c[0] if c[0] != "cargo" else " ".join(c[:2]))
    if not cmds:
        print("changed-checks: nothing to check")
    if failed:
        print("changed-checks: failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
