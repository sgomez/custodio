# shellcheck shell=bash
# Sourced by tpmfail-run.sh (F139): how a TPM that is present and fails, and a credential service that is down, are made in the guest, and how they are undone.
# The service's TPM is the one named by the drop-in of tpm-lib.sh ($TPM_DROPIN). Each injection rewrites that drop-in to name another socket under $TPM_DIR (the unit binds
# the directory read-only, so the unit sees the path), then restarts the service:
#   stale     a socket file nobody listens on: connecting is refused (a missing path is "no TPM", which is another case)
#   broken    a listener in front of the real swtpm that answers the capability query with TPM_RC_FAILURE (tpmfail-stub.py fail-capability)
#   norsa     a listener in front of it for a TPM that lacks RSA, so the choice is encrypted-tpm (tpmfail-stub.py lack-rsa)
#   none      a path that is missing
#   mode      the socket of the run (tpm-lib.sh), the TPM that works
# tf_credentials_down stops the credential service's socket; tf_credentials_up starts it. tf_restore puts everything back.
TF_STALE=$TPM_DIR/stale.sock
TF_BROKEN=$TPM_DIR/broken.sock   # tpmfail-stub.py fail-capability
TF_NORSA=$TPM_DIR/norsa.sock     # tpmfail-stub.py lack-rsa
# shellcheck disable=SC2034 # read by tpmfail-run.sh, which sources this file
TF_MISSING=$TPM_DIR/missing.sock
TF_CREDS_SOCKET=systemd-creds.socket

# tf_stub_start SOCKET MODE: a stub in front of the TPM of the run; returns when it is ready
tf_stub_start() {
    local sock=$1 mode=$2 log=$1.log
    setsid python3 -I "$(dirname "${BASH_SOURCE[0]}")/tpmfail-stub.py" "$sock" "$TPM_SOCK" "$mode" > "$log" 2>&1 < /dev/null &
    echo $! > "$sock.pid"
    for _ in $(seq 50); do grep -q '^ready' "$log" 2> /dev/null && return 0; sleep 0.1; done
    tpm_fail "the stub $mode did not become ready"
}

# tf_prepare: the stale socket and the two stubs, made at once; all exist from now on, only the drop-in picks one
tf_prepare() {
    python3 -I - "$TF_STALE" << 'PY'
import os, socket, sys
path = sys.argv[1]
if os.path.exists(path):
    os.unlink(path)
s = socket.socket(socket.AF_UNIX)
s.bind(path)
s.close()  # the file stays, nobody listens
os.chmod(path, 0o666)
PY
    local rc=0
    tf_stub_start "$TF_BROKEN" fail-capability & local p1=$!
    tf_stub_start "$TF_NORSA" lack-rsa & local p2=$!
    wait "$p1" || rc=1
    wait "$p2" || rc=1
    return "$rc"
}

tf_cleanup() {
    local s pid
    for s in "$TF_BROKEN" "$TF_NORSA"; do
        pid=$(cat "$s.pid" 2> /dev/null || true)
        [ -z "$pid" ] || kill "$pid" 2> /dev/null || true
        rm -f "$s" "$s.ctrl" "$s.pid" "$s.log"
    done
    rm -f "$TF_STALE"
}

# tf_wait_ready OLDPID: a new MainPID, active, and the bus answers Ping
tf_wait_ready() {
    local old=$1 p
    for _ in $(seq 100); do
        p=$(systemctl show -p MainPID --value custodio)
        if [ "$p" != 0 ] && [ "$p" != "$old" ] && [ "$(systemctl show -p ActiveState --value custodio)" = active ] \
            && busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    tpm_fail "the service did not come back (old pid $old, now $p)"
}

# tf_point SOCKET: the drop-in names SOCKET, and the service restarts on it
tf_point() {
    local old
    old=$(systemctl show -p MainPID --value custodio)
    printf '[Service]\nEnvironment=CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=%s\nBindReadOnlyPaths=%s\n' "$1" "$TPM_DIR" > "$TPM_DROPIN"
    systemctl daemon-reload
    systemctl restart custodio
    tf_wait_ready "$old"
}

tf_credentials_down() { systemctl stop "$TF_CREDS_SOCKET" 'systemd-creds@*.service' 2> /dev/null || systemctl stop "$TF_CREDS_SOCKET"; }
tf_credentials_up() { systemctl start "$TF_CREDS_SOCKET"; }

# tf_restore: the TPM of the run, the credential socket and the service as they were; safe to call twice
tf_restore() {
    tf_credentials_up || true
    tf_point "$TPM_SOCK" || return 1
}
