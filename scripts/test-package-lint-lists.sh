#!/usr/bin/env bash
# Tests of the committed files of `just package-lint` (no stubs, no packages): the Containerfiles and the dev image take the pinned
# versions from packaging/lint/pins.txt, and the exception lists hold only justified entries and nothing on the path of the daemon
# beyond the entries a person decided. The gate itself is tested by scripts/test-package-lint.sh.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
bad() { echo "test-package-lint-lists: $*" >&2; fail=1; }

pin() { grep "^$1 " "$ROOT/packaging/lint/pins.txt" | sed 's/^[^=]*= *//'; }

# ---- the Containerfiles and the dev image -------------------------------------------------------------------------------------
CF=$ROOT/packaging/lint
has() { grep -qE -- "$2" "$1" || bad "$(basename "$1"): lacks /$2/"; }
lacks() { ! grep -qE -- "$2" "$1" || bad "$(basename "$1"): has /$2/"; }
has "$CF/lintian.Containerfile" 'ARG LINTIAN$'
has "$CF/lintian.Containerfile" 'ARG DEBIAN_SNAPSHOT$'
has "$CF/lintian.Containerfile" 'snapshot\.debian\.org/archive/debian/\$\{DEBIAN_SNAPSHOT\}/'
has "$CF/lintian.Containerfile" 'lintian=\$\{LINTIAN\}'
has "$CF/lintian.Containerfile" 'test "\$\(lintian --print-version\)" = "\$\{LINTIAN\}"'
has "$CF/rpmlint.Containerfile" 'ARG RPMLINT$'
has "$CF/rpmlint.Containerfile" 'sha256sum -c'
has "$CF/rpmlint.Containerfile" 'rm -f /etc/xdg/rpmlint/\*\.toml'
has "$CF/rpmlint.Containerfile" 'test .* = "\$\{RPMLINT\}"'
has "$CF/namcap.Containerfile" 'ARG NAMCAP$'
has "$CF/namcap.Containerfile" 'archive\.archlinux\.org/repos/\$\{ALA_DATE\}/'
has "$CF/namcap.Containerfile" 'namcap=\$\{NAMCAP\}'
has "$CF/namcap.Containerfile" 'test .* = "\$\{NAMCAP\}"'
for c in lintian rpmlint namcap; do lacks "$CF/$c.Containerfile" 'install[^=]*[ "]namcap( |$)|install -y --no-install-recommends lintian( |$)'; done
lacks "$CF/namcap.Containerfile" 'mirrors\.|geo\.mirror|archlinux\.org/[$]repo'
# The dev image installs lintian at the pinned version from the pinned snapshot, and no rpmlint.
HF=$ROOT/harness/Containerfile
has "$HF" "^ARG LINTIAN=$(pin lintian)\$"
has "$HF" "^ARG DEBIAN_SNAPSHOT=$(pin debian_snapshot)\$"
has "$HF" 'lintian=\$\{LINTIAN\}'
has "$HF" 'snapshot\.debian\.org/archive/debian/\$\{DEBIAN_SNAPSHOT\}/'
! grep -v '^#' "$HF" | grep -qE 'install[^&]*[ "]lintian( |$)' || bad "harness/Containerfile installs an unversioned lintian"
! grep -v '^#' "$HF" | grep -qE 'install[^&]* rpmlint' || bad "harness/Containerfile installs rpmlint"
for key in lintian lintian_profile lintian_sha256 rpmlint rpmlint_koji rpmlint_sha256 namcap namcap_ala_date debian_snapshot base_debian13 base_fedora44 base_arch; do
    [ -n "$(pin "$key")" ] || bad "pins.txt has no $key"
done

# ---- the committed lists ---------------------------------------------------------------------------------------------------
python3 -I -B - "$ROOT" <<'PY' || bad "the committed lists: $?"
import os, re, sys
sys.path.insert(0, os.path.join(sys.argv[1], "scripts"))
import package_lint as g
root = sys.argv[1]
lint = os.path.join(root, "packaging", "lint")
path = "usr/lib/custodio/custodiod"  # the Arch package (namcap)
libexec = "usr/libexec/custodio/custodiod"  # the .deb and the .rpm (lintian, rpmlint)
paths = (path, libexec)
files = "['usr/bin/custodio', 'usr/lib/custodio/custodiod', 'usr/lib/custodio/libcustodio_pkcs11.so']"
# The (linter, tag, subject) pairs decided for the daemon path (F38 contract, option 1 of the BLOCKED.md; F61 moved it to /usr/libexec in the .deb and
# the .rpm, where lintian no longer reports executable-in-usr-lib); subjects as the gate prints them.
decided = {
    ("lintian", "hardening-no-fortify-functions", libexec),
    ("lintian", "spelling-error-in-binary", f"onthe on the [{libexec}]"),
    ("namcap", "incorrect-owner", f"{path} (0:0)"),
    ("namcap", "unused-sodepend", f"/usr/lib64/ld-linux-x86-64.so.2 {path}"),
    ("namcap", "libdepends-missing-provides", f"ld-linux-x86-64.so=2-64 glibc ({files})"),
    ("namcap", "libdepends-missing-provides", f"libc.so=6-64 glibc ({files})"),
    ("namcap", "libdepends-detected-not-included", f"libgcc_s.so=1-64 libgcc ({files})"),
    ("namcap", "dependency-implicitly-satisfied", f"libgcc (libraries-needed ['usr/lib/libgcc_s.so.1'] {files})"),
    ("namcap", "dependency-detected-satisfied",
     f"glibc (libraries-needed ['usr/lib/ld-linux-x86-64.so.2', 'usr/lib/libc.so.6'] {files})"),
}
entries = {n: g.read_exceptions(os.path.join(lint, n + ".txt")) for n in ("lintian", "rpmlint", "namcap")}
for name, lst in entries.items():
    for tag, glob, reason, where in lst:
        assert reason, where
# Every finding of the real run whose subject names the path.
named = set()
with open(os.path.join(root, "reports", "package-lint-container.txt")) as f:
    for line in f:
        m = re.fullmatch(r"(lintian|rpmlint|namcap) \| (\S+) \| (.*?)  \((?:excepted: [^)]*|NOT excepted)\)\n?", line)
        if m and any(p in m[3] for p in paths):
            named.add((m[1], m[2], m[3]))
assert named == decided, f"findings naming the path differ from the decided pairs: extra {sorted(named - decided)}, missing {sorted(decided - named)}"
for linter, tag, subject in sorted(named):
    covering = [e for e in entries[linter] if g.covers(e, tag, subject)]
    assert len(covering) == 1, f"{linter} | {tag} | {subject}: covered by {len(covering)} entries"
    assert covering[0][1] == subject and not any(c in subject for c in "*?"), covering[0][3]
    for other, lst in entries.items():
        if other != linter:
            assert not any(g.covers(e, tag, subject) for e in lst), f"{other} covers {subject}"
# No entry covers the path beyond the decided pairs, whatever its glob, as the path or as a decided subject.
for linter, lst in entries.items():
    for entry in lst:
        tag, glob, reason, where = entry
        for p in [x for q in paths for x in (q, "/" + q, f"onthe on the [{q}]")]:
            if g.covers(entry, tag, p):
                assert (linter, tag, p) in decided and glob == p, f"{where} covers {p}"
        for l, t, subject in decided:
            if g.covers(entry, t, subject):
                assert l == linter and t == tag and glob == subject, f"{where} covers {subject}"
# A decided entry covers neither another tag, nor another path, nor a longer subject.
for linter, tag, subject in decided:
    entry = (tag, subject, "r", "t")
    assert not g.covers(entry, "some-other-tag", subject)
    assert not g.covers(entry, tag, subject + "x")
    for q in [x for x in paths if x in subject]:
        assert not g.covers(entry, tag, subject.replace(q, "usr/lib/custodio/libcustodio_pkcs11.so"))
assert not [e for e in entries["rpmlint"] if any(q in e[1] for q in paths)], "rpmlint.txt names the path"
# executable-in-usr-lib is gone with the move: the .deb has no executable under /usr/lib any more. Nothing may still excuse it.
assert not [e for e in entries["lintian"] if e[0] == "executable-in-usr-lib"], "lintian.txt still excuses executable-in-usr-lib"
PY
# No committed list holds a line without a reason (the parser also rejects it; this is the plain check).
for l in lintian rpmlint namcap; do
    while IFS= read -r line; do
        case $line in *" | "*" | "?*) ;; *) bad "$l.txt: a line without a reason: $line";; esac
    done < <(grep -v '^#' "$ROOT/packaging/lint/$l.txt" | grep -v '^$')
done

exit "$fail"
