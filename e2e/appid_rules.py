#!/usr/bin/python3 -I
"""The reader's rules, the scope names of the appid-* cases and the children of app.slice that bring it over the cap (F95); a part of appid.py, which re-exports it."""
import os

PREFIX, SUFFIX = b"app-flatpak-", b".scope"
MAX_NAME = MAX_ID = 255  # MAX_SCOPE_NAME_LEN and MAX_APP_ID_LEN of crates/custodiod/src/app_id.rs; the reader's own rules, mirrored to build the names
MAX_INSTANCE_DIGITS = 10
FILL, CAP_ID = b"appid-fill-", "org.example.CapCaller"
FLATPAK_ID = "org.example.My_App-Name"

def valid_id(ident):
    if not ident or len(ident) > MAX_ID:
        return False
    parts = ident.split(b".")
    if len(parts) < 3:
        return False
    for number, element in enumerate(parts):
        if not element or element[:1].isdigit():
            return False
        for ch in element:
            if not (chr(ch).isascii() and (chr(ch).isalnum() or chr(ch) == "_" or (chr(ch) == "-" and number == len(parts) - 1))):
                return False
    return True


def reader_state(name):
    """(state, id) the reader gives for the name of a scope, apart from the cap on the number of children."""
    if not name.startswith(PREFIX):
        return "none", None
    if len(name) > MAX_NAME:
        return "undetermined", None
    middle = name[len(PREFIX):]
    if not middle.endswith(SUFFIX):
        return "undetermined", None
    middle = middle[:-len(SUFFIX)]
    split = middle.find(b"-")
    if split < 0 or middle.rfind(b"-") != split:
        return "undetermined", None
    escaped, instance = middle[:split], middle[split + 1:]
    if not (instance and len(instance) <= MAX_INSTANCE_DIGITS and instance.isdigit() and int(instance) <= 0xFFFFFFFF):
        return "undetermined", None
    ident, rest = b"", escaped
    while rest:
        if rest[:1] == b"\\":
            if not rest[1:].startswith(b"x2d"):
                return "undetermined", None
            ident, rest = ident + b"-", rest[4:]
        else:
            ident, rest = ident + rest[:1], rest[1:]
    if not valid_id(ident):
        return "undetermined", None
    return "read", ident.decode("ascii")


def scope_name(ident, instance):
    return PREFIX + ident.replace("-", "\\x2d").encode() + b"-" + str(instance).encode() + SUFFIX


def padded(head, tail, size, fill=b"a"):
    """head + fill * n + tail, exactly SIZE bytes."""
    return head + fill * (size - len(head) - len(tail)) + tail


def generate_names(rng):
    """[(label, name, state, id, marker)]: the callers that are not made by a plain systemd-run, with the answer the reader must give. A hostile name holds a
    marker of its own (unique to the run), which must be found nowhere in the journal. The cap callers are added by cap_setup."""
    def marker():
        return "Mk" + "".join(rng.choice("0123456789abcdef") for _ in range(10))

    rows = []
    maxid = padded(b"org.example.Max", b"", MAX_NAME - len(PREFIX) - len(SUFFIX) - 2).decode()  # the instance "1" and its "-"
    rows.append(("max", scope_name(maxid, 1), "read", maxid, "-"))
    hostile = {  # label -> function of the marker
        "h-two-hyphens": lambda m: b"app-flatpak-org.hostile.%s-1-2.scope" % m,
        "h-instance-text": lambda m: b"app-flatpak-org.hostile.%s-abc.scope" % m,
        "h-instance-long": lambda m: b"app-flatpak-org.hostile.%s-12345678901.scope" % m,
        "h-instance-overflow": lambda m: b"app-flatpak-org.hostile.%s-4294967296.scope" % m,
        "h-escape-other": lambda m: b"app-flatpak-org.hostile.%s\\x41-1.scope" % m,
        "h-escape-upper": lambda m: b"app-flatpak-org.hostile.%s\\x2Dx-1.scope" % m,
        "h-id-two-elements": lambda m: b"app-flatpak-hostile.%s-1.scope" % m,
        "h-id-digit-start": lambda m: b"app-flatpak-org.9hostile.%s-1.scope" % m,
        "h-id-hyphen-early": lambda m: b"app-flatpak-org.host\\x2dile.%s-1.scope" % m,
        "h-chars": lambda m: b"app-flatpak-org.hostile.%s ;$(x)'\"\xc3\xa9-1.scope" % m,
        "h-no-suffix": lambda m: b"app-flatpak-org.hostile.%s-1.scoop" % m,
        "h-256": lambda m: padded(b"app-flatpak-org.hostile.%s" % m, b"-1.scope", 256),
        "h-255-invalid": lambda m: padded(b"app-flatpak-org.9hostile.%s" % m, b"-1.scope", 255),
    }
    for label, make in hostile.items():
        m = marker()
        name = make(m.encode())
        rows.append((label, name, "undetermined", None, m))
    for label, name, state, ident, _m in rows:
        if reader_state(name) != (state, ident):
            raise ValueError(f"{label}: the reader's rules give {reader_state(name)}, expected {(state, ident)}: the name is not what its case needs")
    if len(rows[0][1]) != MAX_NAME:
        raise ValueError("the edge name is not exactly 255 bytes")
    return rows


def write_names(path, rows, append=False):
    with open(path, "a" if append else "w", encoding="ascii") as f:
        for label, name, state, ident, m in rows:
            f.write(f"{label}\t{name.hex()}\t{state}\t{ident or '-'}\t{m}\n")


def read_names(path):
    out = {}
    with open(path, encoding="ascii") as f:
        for line in f:
            if line.strip():
                label, hexname, state, ident, m = line.rstrip("\n").split("\t")
                out[label] = {"label": label, "name": bytes.fromhex(hexname), "state": state, "id": None if ident == "-" else ident, "marker": None if m == "-" else m}
    return out


# --- the cap: more children of app.slice than the reader walks
def cap_pick(order, candidates, cap):
    """(after, within) among CANDIDATES by their place in ORDER (the order of os.listdir, the order the scan walks): the one with the highest index
    and the one with the lowest, or None when the first is not past the cap or the second not inside it."""
    index = {name: i for i, name in enumerate(order)}
    placed = sorted((index[c], c) for c in candidates if c in index)
    if len(placed) < 2:
        return None
    return placed[-1][1], placed[0][1]


def cap_problems(order, after, within, cap):
    """The place of the two callers in the walk. The 4097th child is the first the scan refuses (scan.rs: seen > MAX_CHILDREN), i.e. index CAP counting from 0.
    Past the cap also means more children than the cap. A margin of 2 and 3: the scope of the systemd-run that starts a caller is one more child while the caller moves, and it goes away after."""
    problems = []
    if after not in order or within not in order:
        return problems + ["a cap caller is not a child of app.slice"]
    if order.index(after) < cap + 2:
        problems.append(f"the over-cap caller is child number {order.index(after)} (from 0), not after the cap {cap}")
    if order.index(within) > cap - 3:
        problems.append(f"the inside caller is child number {order.index(within)} (from 0), not within the first {cap}")
    return problems


def as_user(uid, gid, function):
    os.setegid(gid)
    os.seteuid(uid)
    try:
        return function()
    finally:
        os.seteuid(0)
        os.setegid(0)


def cap_setup(slice_path, cap, uid, gid, names_path, tries=30):
    sl = os.fsencode(slice_path)
    existing = os.listdir(sl)
    if any(n.startswith(FILL) for n in existing):
        raise ValueError("children of an earlier run are still in app.slice")
    for i in range(max(0, cap + 300 - len(existing))):
        os.mkdir(os.path.join(sl, FILL + str(i).encode()))  # root's own children: only the count matters
    for attempt in range(tries):
        base = 1000 + 100 * attempt
        names = [scope_name(CAP_ID, base + k) for k in range(40)]
        for n in names:  # alice's: she must be able to write their cgroup.procs
            as_user(uid, gid, lambda n=n: os.mkdir(os.path.join(sl, n)))
        picked = cap_pick(os.listdir(sl), names, cap)
        for n in names:
            if picked is None or n not in picked:
                os.rmdir(os.path.join(sl, n))
        if picked is not None and not cap_problems(os.listdir(sl), picked[0], picked[1], cap):
            write_names(names_path, [("cap-after", picked[0], "undetermined", None, "-"), ("cap-within", picked[1], "read", CAP_ID, "-")], append=True)
            return len(os.listdir(sl)), os.listdir(sl).index(picked[0]), os.listdir(sl).index(picked[1])
        for n in picked or ():
            os.rmdir(os.path.join(sl, n))
    raise ValueError("no pair of cap callers found: after the cap and inside it")


def cap_check(slice_path, cap, names_path):
    names = read_names(names_path)
    order = os.listdir(os.fsencode(slice_path))
    return cap_problems(order, names["cap-after"]["name"], names["cap-within"]["name"], cap)


def cap_teardown(slice_path, names_path):
    sl = os.fsencode(slice_path)
    names = read_names(names_path)
    gone = {names[k]["name"] for k in ("cap-after", "cap-within") if k in names}
    for n in os.listdir(sl):
        if n.startswith(FILL) or n in gone:
            os.rmdir(os.path.join(sl, n))
    left = [n for n in os.listdir(sl) if n.startswith(FILL) or n in gone]
    return [f"{len(left)} children of the cap step are still in app.slice"] if left else []


def cleanup(slice_path, names_path):
    sl = os.fsencode(slice_path)
    for row in read_names(names_path).values():
        try:
            os.rmdir(os.path.join(sl, row["name"]))
        except FileNotFoundError:
            pass
    left = {row["name"] for row in read_names(names_path).values()} & set(os.listdir(sl))
    return [f"{len(left)} scopes of the step are still in app.slice"] if left else []


def slice_path(mount, control_group, uid):
    """The tree the daemon walks (scan.rs tree_root and open_app_slice): everything in front of system.slice in the daemon's own cgroup."""
    parts = control_group.strip().strip("/").split("/")
    if "system.slice" not in parts:
        raise ValueError("the control group of the service has no system.slice")
    prefix = parts[:parts.index("system.slice")]
    return os.path.join(mount, *prefix, "user.slice", f"user-{uid}.slice", f"user@{uid}.service", "app.slice")


