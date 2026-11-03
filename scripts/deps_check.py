#!/usr/bin/env python3
"""Fails when a client crate reaches the service crate through the resolved dependency graph.

Reads `cargo metadata` (the resolved graph, so transitive edges count) and follows every dependency
kind: normal, build and dev. On a hit it prints the path, each edge with its kind, e.g.
`custodio-cli -[dev]-> custodiod`, and exits 1.

Usage: deps_check.py [--manifest-path Cargo.toml] [--clients NAME,...] [--service NAME]
"""

import argparse
import json
import subprocess
import sys
from collections import deque

# The dependency kinds that are followed. Cargo reports a normal dependency as kind null.
KINDS = ("normal", "build", "dev")


def metadata(manifest):
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if manifest:
        cmd += ["--manifest-path", manifest]
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def find_path(graph, names, start, target):
    """Shortest path from `start` to `target` as a list of (kind, package name) steps, or None."""
    queue = deque([(start, [])])
    seen = {start}
    while queue:
        node, path = queue.popleft()
        for dep in graph.get(node, []):
            for kind in dep["dep_kinds"]:
                label = kind["kind"] or "normal"
                if label not in KINDS:
                    continue
                step = path + [(label, names[dep["pkg"]])]
                if dep["pkg"] == target:
                    return step
                if dep["pkg"] not in seen:
                    seen.add(dep["pkg"])
                    queue.append((dep["pkg"], step))
    return None


def check(meta, clients, service):
    names = {p["id"]: p["name"] for p in meta["packages"]}
    ids = {n: i for i, n in names.items()}
    graph = {n["id"]: n["deps"] for n in meta["resolve"]["nodes"]}
    problems = []
    for need in [service, *clients]:
        if need not in ids:
            problems.append(f"deps-check: the workspace has no crate named {need}")
    if problems:
        return problems
    for client in clients:
        path = find_path(graph, names, ids[client], ids[service])
        if path:
            text = client + "".join(f" -[{k}]-> {n}" for k, n in path)
            problems.append(f"deps-check: {client} reaches {service}: {text}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest-path")
    ap.add_argument("--clients", default="custodio-cli,custodio-pkcs11")
    ap.add_argument("--service", default="custodiod")
    opts = ap.parse_args()
    problems = check(metadata(opts.manifest_path), opts.clients.split(","), opts.service)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
