#!/usr/bin/python3 -I
"""The checks of the reader's rules, the scope names, the cap and the slice of the appid-* cases (appid_rules.py through appid.py) on made-up evidence, good and
bad (F95). Container-free; the guest runs it with appid-selftest.py. Usage: appid-selftest-rules.py E2E-DIR."""
import importlib.util
import os
import random
import sys

HERE = sys.argv[1]
spec = importlib.util.spec_from_file_location("appid", os.path.join(HERE, "appid.py"))
ai = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ai)
failures = []


def bad(msg):
    failures.append(msg)
    print(f"appid-selftest-rules: {msg}", file=sys.stderr)


def fails(name, problems):
    if not problems:
        bad(f"{name}: no problem on bad evidence")


def ok(name, problems):
    if problems:
        bad(f"{name}: problems on good evidence: {problems[:3]}")


NAMES_LIST = [("flatpak", ai.scope_name(ai.FLATPAK_ID, 5151), "read", ai.FLATPAK_ID, "-")] + ai.generate_names(random.Random(7))
NAMES = {label: {"name": name, "state": state, "id": ident, "marker": None if marker == "-" else marker} for label, name, state, ident, marker in NAMES_LIST}

# --- the names: the reader's rules, mirrored, give what each case needs
for name, want in [(b"app-flatpak-org.example.My_App\\x2dName-5151.scope", ("read", "org.example.My_App-Name")), (b"app-gnome-gedit-99b.scope", ("none", None)),
                   (b"run-p226-i4693560.scope", ("none", None)), (b"app-flatpak-org.a.b-1-2.scope", ("undetermined", None)),
                   (b"app-flatpak-org.a.b-4294967295.scope", ("read", "org.a.b")), (b"app-flatpak-org.a.b-4294967296.scope", ("undetermined", None)),
                   (b"app-flatpak-org.a.b\\x2D-1.scope", ("undetermined", None)), (b"app-flatpak-a.b-1.scope", ("undetermined", None)),
                   (b"app-flatpak-org.a.b-1.scoope", ("undetermined", None)), (b"app-flatpak-org.a.b--1.scope", ("undetermined", None))]:
    if ai.reader_state(name) != want:
        bad(f"reader_state({name!r}) is {ai.reader_state(name)}, expected {want}")
if len(NAMES["max"]["name"]) != 255 or ai.reader_state(NAMES["max"]["name"])[0] != "read":
    bad("the edge name is not 255 bytes and valid")
if [len(NAMES[k]["name"]) for k in ("h-256", "h-255-invalid")] != [256, 255]:
    bad("the oversized names are not 256 and 255 bytes")
for label, row in NAMES.items():
    if row["marker"] and (row["state"] != "undetermined" or row["id"] is not None):
        bad(f"{label}: a hostile name that is not undetermined")
    if row["marker"] and row["marker"].encode() not in row["name"]:
        bad(f"{label}: the marker is not in the name")
markers = [r["marker"] for r in NAMES.values() if r["marker"]]
if len(set(markers)) != len(markers) or len(markers) < 10:
    bad("the markers are not unique or too few")
for hostile in ("h-escape-other", "h-instance-overflow", "h-id-digit-start", "h-256"):
    if hostile not in NAMES:
        bad(f"no hostile name {hostile}")
# a name that would be valid is refused when it is made a hostile one
orig = ai.rules.reader_state
ai.rules.reader_state = lambda name: ("read", "org.a.b")
try:
    ai.generate_names(random.Random(1))
    bad("generate_names accepts names the reader would read")
except ValueError:
    pass
ai.rules.reader_state = orig
if ai.generate_names(random.Random(7)) != ai.generate_names(random.Random(7)):
    bad("generate_names is not a function of the seed")
if ai.slice_path("/sys/fs/cgroup", "/abc123/system.slice/custodio.service", 1000) != "/sys/fs/cgroup/abc123/user.slice/user-1000.slice/user@1000.service/app.slice":
    bad("slice_path in a container is wrong")
if ai.slice_path("/sys/fs/cgroup", "/system.slice/custodio.service", 7) != "/sys/fs/cgroup/user.slice/user-7.slice/user@7.service/app.slice":
    bad("slice_path on a host is wrong")
try:
    ai.slice_path("/sys/fs/cgroup", "/abc/custodio.service", 1)
    bad("slice_path accepts a control group without system.slice")
except ValueError:
    pass

# --- the cap
ORDER = [b"n%05d" % i for i in range(4400)]
ok("cap", ai.cap_problems(ORDER, ORDER[4300], ORDER[20], 4096))
ok("cap just after", ai.cap_problems(ORDER, ORDER[4098], ORDER[4093], 4096))
fails("cap the over-cap caller is the last of the cap", ai.cap_problems(ORDER, ORDER[4095], ORDER[20], 4096))
fails("cap the over-cap caller is the first past the cap", ai.cap_problems(ORDER, ORDER[4096], ORDER[20], 4096))
fails("cap the inside caller is too close to the cap", ai.cap_problems(ORDER, ORDER[4300], ORDER[4094], 4096))
fails("cap the inside caller is past the cap", ai.cap_problems(ORDER, ORDER[4300], ORDER[4200], 4096))
fails("cap the count is not over the cap", ai.cap_problems(ORDER[:4096], ORDER[4090], ORDER[20], 4096))
fails("cap a caller that is no child", ai.cap_problems(ORDER, b"nothing", ORDER[20], 4096))
if ai.cap_pick(ORDER, [ORDER[5], ORDER[900], ORDER[4300]], 4096) != (ORDER[4300], ORDER[5]):
    bad("cap_pick does not choose the highest and the lowest place")
if ai.cap_pick(ORDER, [ORDER[5]], 4096) is not None:
    bad("cap_pick chose with a single candidate")

sys.exit(1 if failures else 0)
