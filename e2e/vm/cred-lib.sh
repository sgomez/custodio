# shellcheck shell=bash
# Sourced by the case scripts of a VM run (F161, used again by F162 and F163): the reader of F157 on the stored credential of an encrypted-tpm key.
# vm_read_credential ID: as root in the guest, takes the credential of key ID out of the state directory and runs credread.py --expect-tpm-bound with the
# systemd version of the guest. Exit 0 only when the reader exits 0; else one line on stderr with the reader's reason, and exit 1.
# Overridable for the self-test: VM_STATE_DIR, VM_CRED_DIR (where credrec.py and credread.py are), VM_SYSTEMD_VERSION.
vm_read_credential() { # ID [UID]: UID when two users own a key of that id
    local id=$1 uid=${2:-} dir=${VM_CRED_DIR:-/e2e/vm} state=${VM_STATE_DIR:-/var/lib/custodio} ver tmp rc=0 msg
    ver=${VM_SYSTEMD_VERSION:-$(systemctl --version | awk 'NR==1 { print $2 }')}
    tmp=$(mktemp -d)
    if ! msg=$(python3 -I "$dir/credrec.py" "$(readlink -f "$state")" "$id" "$tmp/cred" ${uid:+"$uid"} 2>&1); then
        echo "reader: key $id: $msg" >&2
        rm -rf "$tmp"
        return 1
    fi
    msg=$(python3 -I "$dir/credread.py" "$tmp/cred" --expect-tpm-bound --systemd-version "$ver" 2>&1) || rc=$?
    rm -rf "$tmp"
    if [ "$rc" -ne 0 ]; then
        echo "reader: key $id: the stored credential is not bound to the TPM (reader exit $rc): $msg" >&2
        return 1
    fi
    echo "reader: key $id: $msg"
}
