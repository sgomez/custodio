#!/usr/bin/env bash
# F164: .github/workflows/e2e-vm.yml runs `just e2e-vm full` and `just e2e-vm lacking` on a pull request whose head is a milestone/* branch of this
# repository and on nothing else (no push, no other trigger, no filter on the trigger); enables KVM for the runner user as docs/findings/F150.md says,
# checks the host and installs what the VM needs before the run; pins actions by commit and downloads by checksum; cannot pass without the run; and
# ends in one job, `e2e-vm`, that fails on a release head unless every VM job succeeded and passes on another head. e2e.yml stays as it was: every
# pull request and a push to main, no VM. Each rule has a control: a generated copy of the workflow that breaks it must be refused.
# The closing job decides "release head" with the same two-part test as the VM jobs (milestone/ prefix and the same repository), so a fork head
# named milestone/x, whose VM jobs are skipped, gets RELEASE=false and passes (it ran no VM and no KVM runner).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VM=${CI_VM_WORKFLOW:-$ROOT/.github/workflows/e2e-vm.yml}
exec python3 -I - "$VM" "$ROOT" << 'PY'
import copy, re, subprocess, sys, yaml

vm_path, root = sys.argv[1], sys.argv[2]
MODES = ("full", "lacking")
ROUND = {"full": 0, "lacking": 0}


def load(path):
    return yaml.safe_load(open(path))


def triggers(wf):
    on = wf.get("on", wf.get(True))
    return on


def sub_matrix(text, c):
    return re.sub(r"\$\{\{\s*matrix\.(\w+)\s*\}\}", lambda m: str(c.get(m.group(1), "?")), str(text))


def combos(job):
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    out = [{}]
    for k, vals in matrix.items():
        if k in ("include", "exclude"):
            continue
        out = [dict(c, **{k: v}) for c in out for v in vals]
    for inc in matrix.get("include", []):
        out.append(dict(inc))
    return out


def evaluate(cond, head_ref, head_repo, repo, base_ref="main"):
    """Evaluate a ${{ }} condition made of ==, &&, startsWith and the github.* names used here."""
    text = str(cond).strip()
    text = re.sub(r"^\$\{\{(.*)\}\}$", r"\1", text, flags=re.S).strip()
    names = {
        "github.event.pull_request.head.repo.full_name": "HEAD_REPO",
        "github.repository": "REPO",
        "github.head_ref": "HEAD_REF",
        "github.base_ref": "BASE_REF",
    }
    for k in sorted(names, key=len, reverse=True):
        text = text.replace(k, names[k])
    text = text.replace("&&", " and ").replace("||", " or ")
    if not re.fullmatch(r"[\sA-Za-z_'/().,=!-]*", text) or re.search(r"[A-Za-z_]+\(", re.sub(r"startsWith\(", "", text)):
        raise ValueError(f"unsupported expression: {cond!r}")
    env = {"HEAD_REPO": head_repo, "REPO": repo, "HEAD_REF": head_ref, "BASE_REF": base_ref,
           "startsWith": lambda s, p: s.lower().startswith(p.lower())}
    return bool(eval(text, {"__builtins__": {}}, env))  # noqa: S307 (only the whitelisted names above)


CASES = [  # head_ref, head_repo, repo, release?
    ("milestone/m5", "o/r", "o/r", True),
    ("milestone/x", "o/r", "o/r", True),
    ("feature/milestone/x", "o/r", "o/r", False),
    ("main", "o/r", "o/r", False),
    ("milestones/x", "o/r", "o/r", False),
    ("milestone/x", "fork/r", "o/r", False),
]
PACKAGES = sorted(set(re.findall(r"package ([a-z0-9-]+)", open(f"{root}/scripts/vm-host-check.sh").read())) - {"swtpm"} | {"swtpm"})


def problems(wf):
    out = []
    jobs = wf.get("jobs") or {}
    # trigger
    on = triggers(wf)
    if isinstance(on, str):
        on = {on: None}
    if isinstance(on, list):
        on = {k: None for k in on}
    if not isinstance(on, dict) or set(on) != {"pull_request"}:
        out.append(f"triggers are {sorted(on) if isinstance(on, dict) else on!r}, not pull_request only")
    elif on["pull_request"]:
        out.append(f"the pull_request trigger has a filter: {on['pull_request']!r}")
    # VM jobs
    vm_jobs, runs_seen = [], set()
    for name, job in jobs.items():
        for c in combos(job):
            for st in job.get("steps", []):
                if "run" in st and re.search(r"^\s*just\s+e2e-vm\b", sub_matrix(st["run"], c), re.M):
                    vm_jobs.append(name)
    vm_jobs = sorted(set(vm_jobs))
    if not vm_jobs:
        out.append("no job runs `just e2e-vm MODE`")
    for name in vm_jobs:
        job = jobs[name]
        cond = job.get("if")
        if not cond:
            out.append(f"{name}: no condition on the head branch")
        else:
            for ref, hrepo, repo, want in CASES:
                try:
                    got = evaluate(cond, ref, hrepo, repo)
                except Exception as e:  # noqa: BLE001
                    out.append(f"{name}: condition not understood ({e})")
                    break
                if got != want:
                    out.append(f"{name}: head {ref} of {hrepo} (repo {repo}): condition is {got}, expected {want}")
        for c in combos(job):
            env = {k: sub_matrix(v, c) for k, v in (job.get("env") or {}).items()}
            steps = job.get("steps", [])
            idx = {}
            run_i = None
            for i, st in enumerate(steps):
                run = sub_matrix(st.get("run", ""), c)
                senv = dict(env, **{k: sub_matrix(v, c) for k, v in (st.get("env") or {}).items()})
                m = re.search(r"^\s*just\s+e2e-vm\b(.*)$", run, re.M)
                if m:
                    arg = m.group(1).strip().strip('"')
                    if arg.startswith("$"):
                        arg = senv.get(arg.strip("${}"), arg)
                    run_i = i
                    if arg not in MODES:
                        out.append(f"{name} {c}: the mode is {arg!r}, not one of {MODES}")
                    else:
                        runs_seen.add(arg)
                    if re.search(r"\|\||exit\s+0|^\s*echo\b|;\s*(true|:)\s*$", run, re.M) or st.get("continue-on-error"):
                        out.append(f"{name} {c}: the run step can pass without the run: {run!r}")
                if re.search(r"/etc/udev/rules\.d/\S+", run) and 'KERNEL=="kvm"' in run and 'MODE="0666"' in run and "GROUP=" in run:
                    idx["rule"] = i
                if re.search(r"udevadm\s+control\s+--reload-rules", run):
                    idx["reload"] = i
                if re.search(r"udevadm\s+trigger\s+--name-match=kvm", run):
                    idx["trigger"] = i
                if re.search(r"ls\s+-l\s+/dev/kvm", run):
                    idx["ls"] = i
                if re.search(r"^\s*just\s+vm-host-check\s*$", run, re.M):
                    idx["check"] = i
                if re.search(r"apt-get\s+install", run):
                    idx.setdefault("apt", []).append((i, run))
            if run_i is None:
                out.append(f"{name} {c}: no run step")
                continue
            order = ["rule", "reload", "trigger", "ls", "check"]
            for k in order:
                if k not in idx:
                    out.append(f"{name} {c}: no {k} step for KVM and the host check")
            if all(k in idx for k in order):
                if not (idx["rule"] <= idx["reload"] <= idx["trigger"] <= idx["ls"] <= idx["check"] < run_i):
                    out.append(f"{name} {c}: the KVM, host check and run steps are out of order")
            installed = " ".join(r for i, r in idx.get("apt", []) if i < run_i)
            for p in PACKAGES:
                if not re.search(rf"(?<![\w-]){re.escape(p)}(?![\w-])", installed):
                    out.append(f"{name} {c}: package {p} is not installed by an apt step before the run")
    for m in MODES:
        if vm_jobs and m not in runs_seen:
            out.append(f"mode {m} never runs")
    # whole-file rules
    text = yaml.safe_dump(wf)
    if re.search(r"tcg|-accel\b|KVM_OFF|no[-_]?kvm", text, re.I):
        out.append("software emulation or a switch that turns KVM off is mentioned")
    for name, job in jobs.items():
        if job.get("continue-on-error"):
            out.append(f"{name}: continue-on-error on the job")
        for st in job.get("steps", []):
            if st.get("continue-on-error"):
                out.append(f"{name}: continue-on-error on a step")
            for u in [st.get("uses")] if st.get("uses") else []:
                if not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u):
                    out.append(f"{name}: action {u} is not pinned by a 40-hex commit")
            run = st.get("run", "")
            if re.search(r"\|\|\s*(true|:)\b|\|\|\s*exit\s+0", run):
                out.append(f"{name}: `|| true` in a step")
            if "curl" in run and not re.search(r"sha256sum\s+-c", run):
                out.append(f"{name}: a download is not followed by sha256sum -c")
            if run.strip() and all(re.match(r"\s*(echo\b|#|$)", ln) for ln in run.splitlines()):
                out.append(f"{name}: an echo-only run step")
    # closing job
    closers = [n for n, j in jobs.items() if j.get("name") == "e2e-vm"]
    if len(closers) != 1:
        out.append(f"{len(closers)} jobs are named e2e-vm (the required check)")
    else:
        cl = jobs[closers[0]]
        if closers[0] in vm_jobs:
            out.append("the closing job runs a VM")
        if not re.search(r"\balways\(\)", str(cl.get("if", ""))):
            out.append("the closing job does not run always()")
        needs = cl.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        for n in vm_jobs:
            if n not in needs:
                out.append(f"the closing job does not need {n}")
        for n, j in jobs.items():
            if n not in vm_jobs and n != closers[0]:
                continue
        names = [str(j.get("name", n)) for n, j in jobs.items()]
        if any(re.fullmatch(r"e2e", x) for x in names if x != "e2e-vm"):
            out.append("a job is named like the container e2e check")
        out.extend(closing_problems(cl, vm_jobs, needs))
    return out


def closing_problems(cl, vm_jobs, needs):
    out = []
    steps = [s for s in cl.get("steps", []) if "run" in s]
    if len(steps) != 1:
        return [f"the closing job has {len(steps)} run steps, expected 1"]
    st = steps[0]
    env = st.get("env") or {}
    ref = vm_jobs[0] if vm_jobs else "vm"
    res_var = next((k for k, v in env.items() if "needs." in str(v)), None)
    rel_var = next((k for k, v in env.items() if "github." in str(v)), None)
    if not res_var or not rel_var:
        return ["the closing job passes neither the release test nor the needs result through env"]
    for k, v in env.items():
        if "needs." in str(v) and any(f"needs.{n}.result" not in str(v) for n in vm_jobs):
            out.append("the result in env is not needs.<vm job>.result")
    if "github." in str(st["run"]):
        out.append("the closing run script reads github.* directly")
    for result in ("success", "failure", "skipped", "cancelled"):
        for hr, hrepo, repo, release in CASES:
            try:
                rel = "true" if evaluate(env[rel_var], hr, hrepo, repo) else "false"
            except Exception as e:  # noqa: BLE001
                return out + [f"closing release test not understood ({e})"]
            rc = subprocess.run(["bash", "-ec", st["run"]], env={"PATH": "/usr/bin:/bin", rel_var: rel, res_var: result},
                                capture_output=True).returncode
            # a VM job that ran or not: on a release head it must be success; elsewhere the VM jobs are skipped
            if release:
                want = 0 if result == "success" else 1
            else:
                if result != "skipped":
                    continue  # cannot happen: the VM jobs are skipped on this head
                want = 0
            if (rc == 0) != (want == 0):
                out.append(f"closing job on head {hr} of {hrepo} with VM result {result}: exit {rc}, expected {'0' if want == 0 else 'non-zero'}")
    return out


wf = load(vm_path)
fail = 0
p = problems(wf)
if p:
    fail = 1
    print("test-ci-e2e-vm: e2e-vm.yml: " + "\n  ".join(p), file=sys.stderr)


def vm_job(w):
    return next(j for n, j in w["jobs"].items() if n != "result" and j.get("name", "") != "e2e-vm")


def closer(w):
    return next(j for j in w["jobs"].values() if j.get("name") == "e2e-vm")


def steps_of(w):
    return vm_job(w)["steps"]


def edit_steps(f):
    def go(w):
        for st in steps_of(w):
            f(st)
    return go


def drop_step(pred):
    def go(w):
        j = vm_job(w)
        j["steps"] = [s for s in j["steps"] if not pred(s)]
    return go


def set_on(v):
    def go(w):
        w.pop(True, None)
        w.pop("on", None)
        w["on"] = v
    return go


def set_if(v):
    def go(w):
        vm_job(w)["if"] = v
    return go


def run_replace(a, b, only=None):
    def go(w):
        for st in steps_of(w):
            if "run" in st and a in st["run"] and (only is None or only in st["run"]):
                st["run"] = st["run"].replace(a, b)
    return go


def pkg_drop(pkg):
    return run_replace(" " + pkg + " ", " ", "apt-get install")


def closer_env(key_pred, new):
    def go(w):
        st = next(s for s in closer(w)["steps"] if "run" in s)
        for k in list(st["env"]):
            if key_pred(k, st["env"][k]):
                st["env"][k] = new
    return go


REL = "github.event.pull_request.head.repo.full_name == github.repository && startsWith(github.head_ref, 'milestone/')"
OTHER = "github.event.pull_request.head.repo.full_name == github.repository && startsWith(github.head_ref, 'release/')"
CONTROLS = {
    "push": set_on({"pull_request": None, "push": {"branches": ["main"]}}),
    "push-only": set_on({"push": None}),
    "target": set_on({"pull_request_target": None}),
    "schedule": set_on({"pull_request": None, "schedule": [{"cron": "0 3 * * *"}]}),
    "dispatch": set_on({"pull_request": None, "workflow_dispatch": None}),
    "merge-queue": set_on({"pull_request": None, "merge_group": None}),
    "paths-filter": set_on({"pull_request": {"paths": ["src/**"]}}),
    "branches-filter": set_on({"pull_request": {"branches": ["main"]}}),
    "types-labeled": set_on({"pull_request": {"types": ["labeled"]}}),
    "no-condition": lambda w: vm_job(w).pop("if"),
    "other-prefix": set_if(OTHER),
    "base-branch": set_if(REL.replace("github.head_ref", "github.base_ref")),
    "no-repo-test": set_if("startsWith(github.head_ref, 'milestone/')"),
    "no-prefix-test": set_if("github.event.pull_request.head.repo.full_name == github.repository"),
    "always-true": set_if("true"),
    "one-mode": lambda w: vm_job(w)["strategy"]["matrix"].update(mode=["full"]),
    "other-one-mode": lambda w: vm_job(w)["strategy"]["matrix"].update(mode=["lacking"]),
    "no-mode": run_replace('just e2e-vm "$MODE"', "just e2e-vm"),
    "unknown-mode": lambda w: vm_job(w)["strategy"]["matrix"].update(mode=["full", "partial"]),
    "no-udev-rule": drop_step(lambda s: "udev/rules.d" in s.get("run", "")),
    "no-reload": run_replace("sudo udevadm control --reload-rules\n", ""),
    "no-trigger": run_replace("sudo udevadm trigger --name-match=kvm\n", ""),
    "no-ls": run_replace("ls -l /dev/kvm\n", ""),
    "no-host-check": run_replace("just vm-host-check", "true"),
    "host-check-after": lambda w: vm_job(w)["steps"].append(vm_job(w)["steps"].pop(vm_job(w)["steps"].index(next(s for s in vm_job(w)["steps"] if s.get("name") == "Host check")))),
    "tcg": run_replace("just vm-host-check", "just vm-host-check\n          export QEMU_ACCEL=tcg"),
    "tag-pinned": lambda w: [st.update(uses=re.sub(r"@[0-9a-f]{40}", "@v4", st["uses"])) for st in steps_of(w) if "uses" in st][:1],
    "unchecked-download": run_replace('echo "6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750  /tmp/nfpm.tgz" | sha256sum -c -\n', ""),
    "job-continue": lambda w: vm_job(w).update({"continue-on-error": True}),
    "step-continue": edit_steps(lambda s: s.update({"continue-on-error": True}) if "just e2e-vm" in s.get("run", "") else None),
    "or-true": run_replace('just e2e-vm "$MODE"', 'just e2e-vm "$MODE" || true'),
    "echo-fallback": run_replace('just e2e-vm "$MODE"', "echo 'no kvm here'"),
    "exit-zero": run_replace('just e2e-vm "$MODE"', 'just e2e-vm "$MODE"; exit 0'),
    "close-no-needs": lambda w: closer(w).update(needs=[]),
    "close-not-always": lambda w: closer(w).pop("if"),
    "close-name": lambda w: closer(w).update(name="e2e"),
    "close-passes-skipped": closer_env(lambda k, v: "needs." in str(v), "success"),
    "close-other-prefix": closer_env(lambda k, v: "github." in str(v), OTHER),
    "close-no-repo-test": closer_env(lambda k, v: "github." in str(v), "startsWith(github.head_ref, 'milestone/')"),
    "close-green": lambda w: next(s for s in closer(w)["steps"] if "run" in s).update(run='[ "$RESULT" = success ] || true'),
    "close-always-fail": lambda w: next(s for s in closer(w)["steps"] if "run" in s).update(run='exit 1'),
}
for pkg in PACKAGES:
    CONTROLS[f"no-{pkg}"] = pkg_drop(pkg)

for name, mut in CONTROLS.items():
    w = copy.deepcopy(wf)
    mut(w)
    if w == wf:
        print(f"test-ci-e2e-vm: control {name} changed nothing", file=sys.stderr)
        fail = 1
        continue
    if not problems(w):
        print(f"test-ci-e2e-vm: control: the variant '{name}' was accepted", file=sys.stderr)
        fail = 1

# e2e.yml: unchanged for ordinary pull requests and pushes, and no VM in it
e2e = load(f"{root}/.github/workflows/e2e.yml")
on = triggers(e2e)
if not isinstance(on, dict) or set(on) != {"pull_request", "push"} or on["pull_request"] or on["push"] != {"branches": ["main"]}:
    print(f"test-ci-e2e-vm: e2e.yml triggers changed: {on!r}", file=sys.stderr)
    fail = 1
if re.search(r"e2e-vm|vm-host-check|kvm", open(f"{root}/.github/workflows/e2e.yml").read(), re.I):
    print("test-ci-e2e-vm: e2e.yml mentions the VM target", file=sys.stderr)
    fail = 1
for name, mut in {"e2e-push-gone": lambda w: w["on"].pop("push") if "on" in w else w[True].pop("push"),
                  "e2e-filtered": lambda w: (w.get("on") or w[True]).update(pull_request={"branches": ["main"]})}.items():
    w = copy.deepcopy(e2e)
    mut(w)
    on = triggers(w)
    if isinstance(on, dict) and set(on) == {"pull_request", "push"} and not on["pull_request"] and on["push"] == {"branches": ["main"]}:
        print(f"test-ci-e2e-vm: control: the e2e.yml variant '{name}' was accepted", file=sys.stderr)
        fail = 1
sys.exit(fail)
PY
