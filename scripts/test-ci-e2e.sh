#!/usr/bin/env bash
# F131: .github/workflows/ci.yml has an e2e job for every target of e2e/targets/ in each of the modes swtpm and none; each runs `just e2e <target>` with E2E_TPM set to
# its mode, cannot pass without the run (no continue-on-error, no `|| true`, no exit 0, no echo-only step), and the `ci` job needs it. Controls: copies of the
# workflow without the `none` jobs, with a green fallback, or without the `needs` entry are refused.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CI=${CI_WORKFLOW:-$ROOT/.github/workflows/ci.yml}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "test-ci-e2e: $*" >&2; fail=1; }

# problems WORKFLOW: what is wrong with the e2e jobs of a workflow file (no output: nothing)
problems() {
    python3 -I - "$1" "$ROOT/e2e/targets" << 'PY'
import os, re, sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
targets = sorted(d for d in os.listdir(sys.argv[2]) if os.path.isdir(os.path.join(sys.argv[2], d)))
jobs = wf["jobs"]
seen = {}
for name, job in jobs.items():
    if not name.startswith("e2e"):
        continue
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    combos = [{}]
    for k, vals in axes.items():
        combos = [dict(c, **{k: v}) for c in combos for v in vals]
    for inc in matrix.get("include", []):
        combos.append(dict(inc))
    for c in combos:
        def sub(text):
            return re.sub(r"\$\{\{\s*matrix\.(\w+)\s*\}\}", lambda m: str(c.get(m.group(1), "?")), str(text))
        env = {k: sub(v) for k, v in (job.get("env") or {}).items()}
        steps = job.get("steps", [])
        runs = []
        for st in steps:
            senv = dict(env, **{k: sub(v) for k, v in (st.get("env") or {}).items()})
            if "run" in st:
                runs.append((sub(st["run"]), senv, st))
        tpm = None
        target = None
        for run, senv, st in runs:
            m = re.search(r"^\s*just\s+e2e\s+(\S+)", run, re.M)
            if m:
                target = m.group(1)
                if target.startswith('"$') or target.startswith("$"):
                    target = senv.get(target.strip('"$').strip("{}"), target)
                tpm = senv.get("E2E_TPM")
                for key in ("continue-on-error",):
                    if st.get(key) or job.get(key):
                        print(f"{name} {c}: continue-on-error on the job or the run step")
                if re.search(r"\|\|\s*(true|:|echo|exit\s+0)|exit\s+0|^\s*echo\b", run, re.M):
                    print(f"{name} {c}: the run step can pass without the run: {run!r}")
        if target is None:
            print(f"{name} {c}: no step runs `just e2e TARGET`")
            continue
        seen[(target, tpm)] = name
for t in targets:
    for m in ("swtpm", "none"):
        if (t, m) not in seen:
            print(f"no e2e job for {t} with E2E_TPM={m}")
for (t, m), name in seen.items():
    if m not in ("swtpm", "none", "lacking"):
        print(f"{name}: {t} runs with E2E_TPM={m!r}")
    if t not in targets:
        print(f"{name}: runs the unknown target {t}")
e2e_jobs = [n for n in jobs if n.startswith("e2e")]
needs = jobs.get("ci", {}).get("needs", [])
for n in e2e_jobs:
    if n not in needs:
        print(f"the ci job does not need {n}")
if not e2e_jobs:
    print("no e2e job")
for n in e2e_jobs:
    if (jobs[n].get("if") or "").strip():
        print(f"{n} has an if condition, so it can be skipped")
PY
}
p=$(problems "$CI")
[ -z "$p" ] || bad "ci.yml: $p"

# controls
python3 -I - "$CI" "$tmp" << 'PY'
import sys, yaml, copy
wf = yaml.safe_load(open(sys.argv[1]))
out = sys.argv[2]
def save(name, w):
    yaml.safe_dump(w, open(f"{out}/{name}.yml", "w"), sort_keys=False)
w = copy.deepcopy(wf)
for n, j in w["jobs"].items():
    if n.startswith("e2e"):
        j["strategy"]["matrix"]["tpm"] = ["swtpm"]
save("no-none", w)
w = copy.deepcopy(wf)
for n, j in w["jobs"].items():
    if n.startswith("e2e"):
        j["continue-on-error"] = True
save("green", w)
w = copy.deepcopy(wf)
for n, j in w["jobs"].items():
    if n.startswith("e2e"):
        for st in j["steps"]:
            if "run" in st and "just e2e" in st["run"]:
                st["run"] = "echo 'no privileged container on this runner'\njust e2e \"$TARGET\" || true"
save("echo", w)
w = copy.deepcopy(wf)
w["jobs"]["ci"]["needs"] = [n for n in w["jobs"]["ci"]["needs"] if not n.startswith("e2e")]
save("not-needed", w)
w = copy.deepcopy(wf)
for n, j in w["jobs"].items():
    if n.startswith("e2e"):
        j["env"] = {k: v for k, v in (j.get("env") or {}).items() if k != "E2E_TPM"}
save("no-variable", w)
PY
for c in no-none green echo not-needed no-variable; do
    [ -n "$(problems "$tmp/$c.yml")" ] || bad "control: the workflow variant '$c' was accepted"
done
exit "$fail"
