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
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "scripts"))
import package_lint as g
lint = os.path.join(sys.argv[1], "packaging", "lint")
paths = ("usr/lib/custodio/custodiod", "/usr/lib/custodio/custodiod")
path = "usr/lib/custodio/custodiod"
allowed = ("executable-in-usr-lib", "hardening-no-fortify-functions")  # literal entries, at most one each (F38 amendments)
seen = []
for name in ("lintian", "rpmlint", "namcap"):
    for entry in g.read_exceptions(os.path.join(lint, name + ".txt")):
        tag, glob, reason, where = entry
        assert reason, where
        for p in (path, "/" + path):
            if g.covers(entry, tag, p):
                assert name == "lintian" and tag in allowed and glob == path, f"{where} covers {p}"
                assert not any(c in glob for c in "*?["), where
                if p == path:
                    seen.append(tag)
assert len(seen) == len(set(seen)), "a decided entry is listed more than once"
for tag in seen:
    entry = (tag, path, "r", "t")
    assert not g.covers(entry, "some-other-tag", path)
    assert not g.covers(entry, tag, path + "x")
    assert not g.covers(entry, tag, "usr/lib/custodio/libcustodio_pkcs11.so")
PY
# No committed list holds a line without a reason (the parser also rejects it; this is the plain check).
for l in lintian rpmlint namcap; do
    grep -v '^#' "$ROOT/packaging/lint/$l.txt" | grep -v '^$' | while IFS= read -r line; do
        case $line in *" | "*" | "?*) ;; *) bad "$l.txt: a line without a reason: $line";; esac
    done
done

exit "$fail"
