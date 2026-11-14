# shellcheck shell=bash disable=SC2016,SC2153
# Fixtures for the docs tests that run `custodio register` on a documented page (F185, shared by F186). Sourced; the caller
# sets ROOT, LIB (scripts/lib/docs_check.py) and CLI (target/debug/custodio-cli). Nothing here changes the host: `custodio
# register` without --module uses /usr/lib/custodio/libcustodio_pkcs11.so, which is not here, so the commands run in a user and
# mount namespace where an overlay puts an empty module file there, and then in a nested user namespace mapped to the invoking
# uid (register refuses root). Without `unshare` the caller fails; it does not skip.

# A stub modutil: records its arguments and edits pkcs11.txt as `-add NAME -libfile LIB` and `-delete NAME` would.
reg_stub() { # reg_stub BINDIR
    mkdir -p "$1"
    cat > "$1/modutil" << 'STUB'
#!/bin/sh
echo "$*" >> "$STUB_LOG"
dir=${2#sql:}
case $3 in
    -add) printf 'library=%s\nname=%s\n\n' "$6" "$4" >> "$dir/pkcs11.txt" ;;
    -delete)
        touch "$dir/pkcs11.txt"
        awk -v n="$4" 'BEGIN { RS = ""; ORS = "\n\n" } $0 !~ "name=" n "(\n|$)"' "$dir/pkcs11.txt" > "$dir/pkcs11.new"
        mv "$dir/pkcs11.new" "$dir/pkcs11.txt"
        ;;
esac
STUB
    chmod +x "$1/modutil"
    ln -s "$CLI" "$1/custodio"
}

# The effect of the register commands, checked after the block that ran them. Argument: the first command of the block.
reg_check() { # reg_check FILE
    cat > "$1" << 'CHECK'
#!/bin/bash
set -u
log=$CHECK_DIR/checked
native=$HOME/.mozilla/firefox/abcd1234.default-release
snap=$HOME/snap/firefox/common/.mozilla/firefox/efgh5678.default
copy=$HOME/snap/firefox/common/libcustodio_pkcs11.so
case $1 in
    "custodio register")
        # A host whose NSS loads p11-kit skips native profiles (the code's rule); the effect is then checked on the snap profile only.
        if [ "${NATIVE_SKIPPED:-0}" = 0 ]; then
            grep -qxF -- "-dbdir sql:$native -add Custodio -libfile /usr/lib/custodio/libcustodio_pkcs11.so -force" "$STUB_LOG" || { echo "no -add of the installed module in the native profile" >&2; exit 1; }
            grep -qxF -- "library=/usr/lib/custodio/libcustodio_pkcs11.so" "$native/pkcs11.txt" 2> /dev/null || { echo "the native profile has no entry" >&2; exit 1; }
        fi
        [ -f "$copy" ] || { echo "no snap copy" >&2; exit 1; }
        grep -qxF -- "-dbdir sql:$snap -add Custodio -libfile $copy -force" "$STUB_LOG" || { echo "no -add of the copy in the snap profile" >&2; exit 1; }
        grep -qxF -- "library=$copy" "$snap/pkcs11.txt" || { echo "the snap profile has no entry" >&2; exit 1; }
        echo registered >> "$log"
        ;;
    "custodio register --remove")
        [ ! -e "$copy" ] || { echo "the snap copy is still there" >&2; exit 1; }
        ! grep -qs custodio "$snap/pkcs11.txt" "$native/pkcs11.txt" || { echo "an entry is still there" >&2; exit 1; }
        grep -q -- "-delete Custodio" "$STUB_LOG" || { echo "no -delete" >&2; exit 1; }
        echo removed >> "$log"
        ;;
esac
CHECK
    chmod +x "$1"
}


# reg_home DIR: a HOME with a native Firefox profile and the snap's, each with the index file the way Firefox writes it.
reg_home() {
    local root pair
    mkdir -p "$1/home"
    for pair in ".mozilla/firefox:abcd1234.default-release" "snap/firefox/common/.mozilla/firefox:efgh5678.default"; do
        root=$1/home/${pair%%:*}
        mkdir -p "$root/${pair##*:}"
        printf '[General]\nVersion=2\n\n[Profile0]\nName=default\nIsRelative=1\nPath=%s\nDefault=1\n' "${pair##*:}" > "$root/profiles.ini"
    done
}

# reg_uid: the uid the nested namespace maps to (never 0).
reg_uid() { local u; u=$(id -u); [ "$u" != 0 ] || u=1000; echo "$u"; }

# reg_skipped: 1 on a host whose NSS loads p11-kit (Fedora-like): native profiles are skipped, their lines are not compared.
reg_skipped() {
    if grep -qx '[[:space:]]*library=p11-kit-proxy.so[[:space:]]*' /etc/crypto-policies/back-ends/nss.config 2> /dev/null; then echo 1; else echo 0; fi
}

# reg_probe DIR: the namespace must work here; a failure says so (NAME is the test's name).
reg_probe() {
    mkdir -p "$1/ov" "$1/stage/custodio"
    : > "$1/stage/custodio/libcustodio_pkcs11.so"
    unshare -rm sh -c '
        mount -t tmpfs tmpfs "$1/ov" && mkdir "$1/ov/up" "$1/ov/wk" &&
        mount -t overlay overlay -o "lowerdir=$1/stage:/usr/lib,upperdir=$1/ov/up,workdir=$1/ov/wk" /usr/lib &&
        exec unshare --user --map-user="$2" --map-group="$2" test -e /usr/lib/custodio/libcustodio_pkcs11.so' \
        sh "$1" "$(reg_uid)" 2> "$1/err" || { echo "${NAME:-test}: unshare cannot give the test a module at /usr/lib/custodio: $(tail -n 2 "$1/err")" >&2; return 1; }
}

# reg_run DOC DIR WANT...: the console blocks of DOC on a fresh HOME and overlay, no bus, stub modutil first on PATH; then every
# effect word in WANT (registered, removed) must have been checked: a page without the command proves nothing.
reg_run() {
    local doc=$1 d=$2 rc=0 skipped ignore='' want
    shift 2
    mkdir -p "$d/ov" "$d/work" "$d/stage/custodio"
    : > "$d/stage/custodio/libcustodio_pkcs11.so"
    reg_stub "$d/bin"
    reg_check "$d/check.sh"
    reg_home "$d"
    skipped=$(reg_skipped)
    [ "$skipped" = 0 ] || ignore='^Firefox /'
    HOME=$d/home PATH=$d/bin:$PATH STUB_LOG=$d/modutil.log CHECK_DIR=$d NATIVE_SKIPPED=$skipped \
        DOCS_HOME_SHOWN=/home/ana DOCS_IGNORE_RE=$ignore DOCS_CHECK=$d/check.sh \
        timeout 300 unshare -rm sh -c '
            mount -t tmpfs tmpfs "$1/ov" && mkdir "$1/ov/up" "$1/ov/wk" &&
            mount -t overlay overlay -o "lowerdir=$1/stage:/usr/lib,upperdir=$1/ov/up,workdir=$1/ov/wk" /usr/lib &&
            exec unshare --user --map-user="$3" --map-group="$3" python3 -I "$4" run "$2" "$1/work"' \
        sh "$d" "$doc" "$(reg_uid)" "$ROOT/$LIB" 2> "$d/run.err" > "$d/run.out" || rc=$?
    for want in "$@"; do
        grep -qx "$want" "$d/checked" 2> /dev/null || { echo "the effect '$want' was never checked: the page lacks the command" >&2; rc=1; }
    done
    sed -n 's/^/    /p' "$d/run.out" "$d/run.err" | tail -n 30 >&2
    return "$rc"
}
