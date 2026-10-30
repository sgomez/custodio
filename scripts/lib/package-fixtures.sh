#!/usr/bin/env bash
# Fixture packages for the package gate tests: small .deb/.rpm/.pkg.tar.zst files built with nfpm from the real
# packaging/nfpm.yaml (edited by scripts/lib/nfpm_edit.py), real system ELF files for the three binaries, and the real
# packaging scripts and data files. Source this file; it needs ROOT (the repository) and sets FX_DIR.
set -euo pipefail

ROOT=${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
FORMATS=(deb rpm archlinux)

# fx_require: fail, naming the tool, when a tool the fixtures need is not installed.
fx_require() {
    local tool
    for tool in nfpm rpm bsdtar zstd python3; do
        command -v "$tool" >/dev/null || { echo "package-fixtures: required tool '$tool' is not installed" >&2; return 1; }
    done
}

fx_init() {
    fx_require || exit 1
    FX_DIR=$(mktemp -d)
    mkdir -p "$FX_DIR/target/release"
    cp /bin/true "$FX_DIR/target/release/custodiod"
    cp /bin/true "$FX_DIR/target/release/custodio-cli"
    cp /bin/true "$FX_DIR/target/release/libcustodio_pkcs11.so"
    cp -r "$ROOT/data" "$ROOT/packaging" "$FX_DIR/"
}

fx_cleanup() { rm -rf "${FX_DIR:?}"; }

# fx_build NAME VERSION PRERELEASE OP [ARG...]: the three packages of one case, in $FX_DIR/out/NAME.
# The Arch package takes the pre-release in its version (`0.2.0_rc.1`), as the `package` recipe does.
fx_build() {
    local name=$1 version=$2 pre=$3 fmt arch_version
    shift 3
    mkdir -p "$FX_DIR/out/$name"
    python3 -I "$ROOT/scripts/lib/nfpm_edit.py" "$ROOT/packaging/nfpm.yaml" "$FX_DIR/nfpm-$name.yaml" "$@"
    arch_version=$version
    [ -z "$pre" ] || arch_version="${version}_${pre}"
    for fmt in "${FORMATS[@]}"; do
        if [ "$fmt" = archlinux ]; then
            (cd "$FX_DIR" && NFPM_VERSION=$arch_version NFPM_PRERELEASE='' nfpm package -f "nfpm-$name.yaml" -p "$fmt" -t "out/$name" >/dev/null)
        else
            (cd "$FX_DIR" && NFPM_VERSION=$version NFPM_PRERELEASE=$pre nfpm package -f "nfpm-$name.yaml" -p "$fmt" -t "out/$name" >/dev/null)
        fi
    done
}

fx_file() { # NAME FORMAT: path of the package of that format
    case $2 in
    deb) ls "$FX_DIR/out/$1"/*.deb ;;
    rpm) ls "$FX_DIR/out/$1"/*.rpm ;;
    archlinux) ls "$FX_DIR/out/$1"/*.pkg.tar.zst ;;
    esac
}

# rpm reads its database from /var/lib/rpm by default, which a plain user cannot open.
fx_rpm() { rpm --dbpath "$FX_DIR/rpmdb" "$@"; }

# fx_script NAME FORMAT DIR: write the lifecycle script(s) of a package into DIR, as files: deb postinst, rpm post, arch .INSTALL.
fx_scripts() {
    local pkg
    pkg=$(fx_file "$1" "$2")
    mkdir -p "$3"
    case $2 in
    deb) dpkg-deb -e "$pkg" "$3/ctl" && cp "$3/ctl/postinst" "$3/postinst" ;;
    rpm) fx_rpm -qp --qf '%{POSTIN}' "$pkg" > "$3/post" ;;
    archlinux) bsdtar -xOf "$pkg" .INSTALL > "$3/INSTALL" ;;
    esac
}

# fx_mix NAME BASE FORMAT OTHER: the packages of case BASE, with the package of FORMAT taken from case OTHER.
fx_mix() {
    mkdir -p "$FX_DIR/out/$1"
    cp "$FX_DIR/out/$2"/* "$FX_DIR/out/$1/"
    rm -f "$(fx_file "$1" "$3")"
    cp "$(fx_file "$4" "$3")" "$FX_DIR/out/$1/"
}

# fx_elf_needed OLD NEW: replace a NEEDED soname (same length) in the fixture binary custodiod; fx_elf_restore undoes it.
fx_elf_needed() { sed -i "s/$1/$2/" "$FX_DIR/target/release/custodiod"; }
fx_elf_restore() { cp /bin/true "$FX_DIR/target/release/custodiod"; }
