#!/usr/bin/env bash
# Makes the credential fixtures for the credential reader's self-test (F157) with the real systemd-creds against a
# software TPM: one swtpm session, a private mount namespace with a tmpfs on /var/lib/systemd (as F110 and F153), so
# nothing touches the host's credential secret. All files are named n (--name=n).
# Usage: e2e/vm/mkcreds.sh DIR   (DIR must exist and be empty). In a guest as root, run MKCREDS_INNER=1 with TPM2TOOLS_TCTI set.
# Files: scoped (user-scoped host+tpm2, mask 0), scoped-pcr7 (same, PCR 7), host, host-scoped, null, tpm2, host-tpm2.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [ -z "${MKCREDS_INNER:-}" ]; then
    dir=${1:?usage: mkcreds.sh DIR}
    for tool in systemd-creds unshare swtpm tpm2_startup; do
        command -v "$tool" > /dev/null 2>&1 || { echo "mkcreds: $tool is not installed" >&2; exit 127; }
    done
    root=$(cd "$here/../.." && pwd)
    exec env MKCREDS_INNER=1 "$root/scripts/with-swtpm.sh" unshare -m --map-root-user bash "$here/mkcreds.sh" "$dir"
fi

dir=$1
mount -t tmpfs t /var/lib/systemd
tpm=--tpm2-device=$TPM2TOOLS_TCTI
mk() {
    local out=$1
    shift
    printf 'hello-f157' | systemd-creds "$tpm" "$@" encrypt --name=n - "$dir/$out" 2> /dev/null
}
mk scoped --uid=1000 --with-key=host+tpm2 --tpm2-pcrs=
mk scoped-pcr7 --uid=1000 --with-key=host+tpm2 --tpm2-pcrs=7
mk host --with-key=host
mk host-scoped --uid=1000 --with-key=host
mk null --with-key=null
mk tpm2 --with-key=tpm2 --tpm2-pcrs=
mk host-tpm2 --with-key=host+tpm2 --tpm2-pcrs=
# The credentials are genuine: they decrypt (the scoped ones with the same --uid).
for f in scoped scoped-pcr7 host-scoped; do
    [ "$(systemd-creds "$tpm" --uid=1000 --name=n decrypt "$dir/$f" - 2> /dev/null)" = hello-f157 ] || { echo "mkcreds: $f does not decrypt" >&2; exit 1; }
done
for f in host null tpm2 host-tpm2; do
    [ "$(systemd-creds "$tpm" --name=n decrypt "$dir/$f" - 2> /dev/null)" = hello-f157 ] || { echo "mkcreds: $f does not decrypt" >&2; exit 1; }
done
