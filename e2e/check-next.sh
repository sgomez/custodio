#!/usr/bin/env bash
# Host check of the upgrade pair of F48: N+1 must be N with only the version raised. Usage: check-next.sh N N_PLUS_1 (package files of
# the same format). Checks what needs no version tool: the two are different files of the same format, the version strings differ,
# the sha256 of the daemon is the same and the sorted file lists are the same. That N+1 is GREATER than N is checked
# in the guest, with the target's own tool (upgrade-lib.sh), because the dev container has no vercmp.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null # upgrade-lib.sh is checked on its own
source "$here/upgrade-lib.sh"
die() { echo "check-next: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: N N_PLUS_1"
cur=$1 next=$2
[ -f "$cur" ] || die "$cur: no such file"
[ -f "$next" ] || die "$next: no such file"
[ "$(realpath "$cur")" != "$(realpath "$next")" ] || die "N and N+1 are the same file"
fmt=$(pkg_format "$cur")
[ "$(pkg_format "$next")" = "$fmt" ] || die "N and N+1 are not in the same format"

version() { # FILE
    case $fmt in
    arch) bsdtar -xOf "$1" .PKGINFO | sed -n 's/^pkgver = //p' ;;
    *) pkg_file_version "$fmt" "$1" ;;
    esac
}
files() { # FILE: sorted installed paths, without the metadata of the Arch package
    case $fmt in
    deb) dpkg-deb --fsys-tarfile "$1" | bsdtar -tf - ;;
    *) bsdtar -tf "$1" ;;
    esac | sed 's|^\./||; s|^/||; s|/$||' | grep -v '^\.\(PKGINFO\|MTREE\|BUILDINFO\|INSTALL\|CHANGELOG\)$' | grep -v '^$' | LC_ALL=C sort
}
binary_hash() { # FILE
    local name
    case $fmt in
    deb) dpkg-deb --fsys-tarfile "$1" | bsdtar -xOf - usr/libexec/custodio/custodiod | sha256sum | cut -d' ' -f1 ;;
    *)
        name=$(bsdtar -tf "$1" | grep -E '^(\./)?usr/(lib|libexec)/custodio/custodiod$' | head -n 1)
        [ -n "$name" ] || { echo none; return; }
        bsdtar -xOf "$1" "$name" | sha256sum | cut -d' ' -f1
        ;;
    esac
}

v0=$(version "$cur")
v1=$(version "$next")
if [ -z "$v0" ] || [ -z "$v1" ]; then die "no version read from $cur or $next"; fi
[ "$v0" != "$v1" ] || die "N+1 has the same version as N ($v0)"
h0=$(binary_hash "$cur")
h1=$(binary_hash "$next")
[ "$h0" != none ] || die "custodiod is not in $cur"
[ "$h0" = "$h1" ] || die "custodiod of N+1 differs from N's ($h0 and $h1)"
files "$cur" > /dev/null
if ! diff <(files "$cur") <(files "$next") > /dev/null; then die "the file lists of N and N+1 differ"; fi
[ -n "$(files "$cur")" ] || die "the file list of $cur is empty"
echo "check-next: $fmt N=$v0 N+1=$v1, same custodiod ($h0) and same file list"
