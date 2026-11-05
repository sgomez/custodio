# shellcheck shell=bash
# Sourced by guest.sh (F131): the TPM the service sees in an end-to-end run, and the check that the test drop-in that gives it exists only here.
# docs/findings/F108.md (route 2): swtpm on a unix socket under /tmp (state under /var/tmp, where a host AppArmor profile lets swtpm write), and a
# drop-in in /run/systemd/system/custodio.service.d/ (tmpfs, owned by no package) that sets CUSTODIOD_TEST_SWTPM_TCTI and BindReadOnlyPaths=. ExecStart stays as shipped.
#   swtpm    swtpm runs and the drop-in points at its socket
#   none     the drop-in points at the same socket and nothing listens there: the service sees no TPM
#   lacking  swtpm listens on upstream.sock and the filter program (/e2e-bin/tpm-filter, an example of custodio-it) in front of it on the socket the drop-in
#            names, with RSAPSS (0x0016) removed, as docs/findings/F108.md did
# tpm_setup MODE starts it, tpm_observe MODE shows with tpm2-tools, under the sandbox of the installed unit, that the TPM is what MODE says (it fails the run
# otherwise), tpm_teardown undoes everything, tpm_unit_problems says what the installed unit has of it.
TPM_DIR=/tmp/custodio-e2e-tpm
TPM_STATE=/var/tmp/custodio-e2e-tpm-state
TPM_SOCK=$TPM_DIR/swtpm.sock
TPM_UPSTREAM=$TPM_DIR/upstream.sock # lacking: the real swtpm, behind the filter
TPM_FILTER=/e2e-bin/tpm-filter
TPM_LACKING_ALG=0x16 # RSAPSS
TPM_LACKING_PARMS=rsa2048:rsapss:null # what TestParms must refuse in lacking mode
TPM_HAVING_PARMS=rsa2048:rsassa:null  # and what it must still accept
TPM_DROPIN_DIR=/run/systemd/system/custodio.service.d
TPM_DROPIN=$TPM_DROPIN_DIR/zz-e2e-test-tpm.conf
TPM_SETUP_DONE='' # read by tpm-selftest.sh (which sources this file)

tpm_fail() { echo "e2e: FAIL: tpm: $*" >&2; return 1; }

# tpm_swtpm_start [SOCKET]: swtpm on SOCKET (default $TPM_SOCK); both sockets world-writable because the unit's dynamic user connects (test only)
tpm_swtpm_start() {
    local sock=${1:-$TPM_SOCK}
    mkdir -p "$TPM_STATE"
    swtpm_setup --tpm2 --tpmstate "$TPM_STATE" --createek --not-overwrite > "$TPM_STATE/setup.log" 2>&1 || { tail -n 5 "$TPM_STATE/setup.log" >&2; tpm_fail "swtpm_setup failed"; return 1; }
    swtpm socket --tpm2 --tpmstate "dir=$TPM_STATE" --server "type=unixio,path=$sock,mode=0666" \
        --ctrl "type=unixio,path=$sock.ctrl,mode=0666" --flags not-need-init,startup-clear --daemon > "$TPM_STATE/socket.log" 2>&1 \
        || { tail -n 5 "$TPM_STATE/socket.log" >&2; tpm_fail "swtpm socket failed"; return 1; }
    for _ in $(seq 50); do [ -S "$sock" ] && [ -S "$sock.ctrl" ] && return 0; sleep 0.1; done
    tpm_fail "swtpm made no socket"
}

# tpm_filter_start: the filter program on $TPM_SOCK in front of $TPM_UPSTREAM, lacking $TPM_LACKING_ALG; waits for its "ready"
tpm_filter_start() {
    [ -x "$TPM_FILTER" ] || { tpm_fail "$TPM_FILTER is not mounted (lacking mode)"; return 1; }
    setsid "$TPM_FILTER" "$TPM_UPSTREAM" "$TPM_SOCK" "alg=$TPM_LACKING_ALG" > "$TPM_STATE/filter.log" 2>&1 < /dev/null &
    echo $! > "$TPM_STATE/filter.pid"
    for _ in $(seq 50); do grep -q '^ready ' "$TPM_STATE/filter.log" 2> /dev/null && return 0; sleep 0.1; done
    tail -n 5 "$TPM_STATE/filter.log" >&2
    tpm_fail "the filter did not become ready"
}

tpm_filter_stop() {
    local pid
    pid=$(cat "$TPM_STATE/filter.pid" 2> /dev/null || true)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null || true
}

# tpm_swtpm_stop: asks swtpm to shut down through its control socket (a host AppArmor profile may forbid kill) and waits for it
tpm_swtpm_stop() {
    local ctrl
    for ctrl in "$TPM_UPSTREAM.ctrl" "$TPM_SOCK.ctrl"; do # lacking: the real swtpm is behind the filter
        if [ -S "$ctrl" ]; then swtpm_ioctl --unix "$ctrl" -s > /dev/null 2>&1 || true; fi
    done
    for _ in $(seq 50); do pgrep -x swtpm > /dev/null || return 0; sleep 0.1; done
    tpm_fail "swtpm did not stop"
}

# tpm_setup MODE: before the service starts. The directory exists in every mode: the unit binds it, and a missing source would stop the unit.
tpm_setup() {
    local mode=$1
    case $mode in
    swtpm | none | lacking) ;;
    *) tpm_fail "the mode '$mode' is not set up by this harness"; return 1 ;;
    esac
    mkdir -p "$TPM_DIR" "$TPM_DROPIN_DIR"
    TPM_SETUP_DONE=1
    case $mode in
    swtpm) tpm_swtpm_start || return 1 ;;
    lacking) tpm_swtpm_start "$TPM_UPSTREAM" && tpm_filter_start || return 1 ;;
    esac
    printf '[Service]\nEnvironment=CUSTODIOD_TEST_SWTPM_TCTI=swtpm:path=%s\nBindReadOnlyPaths=%s\n' "$TPM_SOCK" "$TPM_DIR" > "$TPM_DROPIN"
    systemctl daemon-reload
}

# tpm_teardown: everything tpm_setup made, safe to call twice
tpm_teardown() {
    rm -f "$TPM_DROPIN"
    rmdir "$TPM_DROPIN_DIR" 2> /dev/null || true
    tpm_filter_stop
    tpm_swtpm_stop || true
    rm -rf "$TPM_DIR" "$TPM_STATE"
    systemctl daemon-reload
    # shellcheck disable=SC2034 # read by tpm-selftest.sh
    TPM_SETUP_DONE=''
}

# tpm_in_unit CMD...: runs CMD under the sandbox of the installed custodio.service, with the TCTI the unit carries. The service keeps its ExecStart, so
# the sandbox is rebuilt as a transient unit from the properties the unit reports (the drop-in's BindReadOnlyPaths among them), and the TCTI is read from
# the unit's Environment: a misspelt variable or path in the drop-in is seen here.
tpm_in_unit() {
    local props=() p v tcti=''
    for p in PrivateTmp DynamicUser ProtectSystem PrivateDevices PrivateUsers RestrictAddressFamilies NoNewPrivileges BindReadOnlyPaths; do
        v=$(systemctl show -p "$p" --value custodio.service)
        [ -z "$v" ] || props+=(-p "$p=$v")
    done
    for v in $(systemctl show -p Environment --value custodio.service); do
        case $v in CUSTODIOD_TEST_SWTPM_TCTI=*) tcti=${v#CUSTODIOD_TEST_SWTPM_TCTI=} ;; esac
    done
    [ -n "$tcti" ] || { echo "tpm: custodio.service has no CUSTODIOD_TEST_SWTPM_TCTI" >&2; return 3; }
    systemd-run --quiet --pipe --wait --collect "${props[@]}" env "TPM2TOOLS_TCTI=$tcti" "$@"
}

# tpm_observe MODE: the TPM is what MODE says, seen from the unit's sandbox; fails the run otherwise
tpm_observe() {
    local mode=$1 out rc=0 n
    out=$(tpm_in_unit tpm2_getcap algorithms 2>&1) || rc=$?
    case $mode in
    swtpm)
        [ "$rc" -eq 0 ] || { echo "$out" | tail -n 5 >&2; tpm_fail "mode swtpm: tpm2_getcap algorithms failed (status $rc) in the unit's sandbox"; return 1; }
        n=$(grep -c '^[a-z0-9_-]*:$' <<< "$out" || true)
        [ "$n" -ge 10 ] || tpm_fail "mode swtpm: tpm2_getcap listed only $n algorithms" || return 1
        ;;
    none)
        [ "$rc" -ne 0 ] || { tpm_fail "mode none: tpm2_getcap succeeded, so a TPM is reachable"; return 1; }
        grep -q 'Cannot connect to swtpm TPM socket' <<< "$out" || { echo "$out" | tail -n 5 >&2; tpm_fail "mode none: tpm2_getcap failed, but not for the missing socket"; return 1; }
        ;;
    lacking)
        # the TPM answers, and lacks the scheme: TestParms of it fails with TPM_RC_SCHEME (0x1D2: scheme, parameter 1), one it has succeeds, and the algorithm is
        # not listed; swtpm behind the filter does have it (asked on its own socket, which only the filter and this check use)
        [ "$rc" -eq 0 ] || { echo "$out" | tail -n 5 >&2; tpm_fail "mode lacking: tpm2_getcap algorithms failed (status $rc)"; return 1; }
        ! grep -q '^rsapss:' <<< "$out" || { tpm_fail "mode lacking: rsapss is still listed"; return 1; }
        grep -q '^rsa:' <<< "$out" || { tpm_fail "mode lacking: rsa is no longer listed"; return 1; }
        out=$(tpm_in_unit tpm2_testparms "$TPM_LACKING_PARMS" 2>&1) && { tpm_fail "mode lacking: TestParms $TPM_LACKING_PARMS succeeded"; return 1; }
        grep -qiE '0x0*1d2' <<< "$out" || { echo "$out" | tail -n 3 >&2; tpm_fail "mode lacking: TestParms $TPM_LACKING_PARMS did not fail with TPM_RC_SCHEME (0x1D2)"; return 1; }
        tpm_in_unit tpm2_testparms "$TPM_HAVING_PARMS" > /dev/null 2>&1 || { tpm_fail "mode lacking: TestParms $TPM_HAVING_PARMS failed"; return 1; }
        TPM2TOOLS_TCTI="swtpm:path=$TPM_UPSTREAM" tpm2_testparms "$TPM_LACKING_PARMS" > /dev/null 2>&1 || { tpm_fail "mode lacking: swtpm itself refuses $TPM_LACKING_PARMS, so nothing is lacking by the filter"; return 1; }
        ;;
    *) tpm_fail "no observation for the mode '$mode'"; return 1 ;;
    esac
}

# tpm_unit_problems: what the INSTALLED unit has of the test drop-in; no output means nothing. Only meaningful with no TPM setup in place.
tpm_unit_problems() {
    local dropins files hdr n=0
    dropins=$(systemctl show -p DropInPaths --value custodio.service)
    [ -z "$dropins" ] || echo "DropInPaths of custodio.service is not empty: $dropins"
    files=$(bash /e2e-target/files.sh) || { echo "the package file list could not be read"; return 0; }
    [ -n "$files" ] || echo "the package file list is empty"
    ! grep -q 'custodio\.service\.d' <<< "$files" || echo "the package file list names custodio.service.d"
    grep -q '/custodio\.service$' <<< "$files" || echo "the package file list has no custodio.service"
    # systemctl cat prints one "# /path" header per file it shows
    while IFS= read -r hdr; do
        n=$((n + 1))
        grep -qxF -- "${hdr#\# }" <<< "$files" || echo "systemctl cat shows a file the package does not own: ${hdr#\# }"
    done < <(systemctl cat custodio.service | grep '^# /')
    [ "$n" -eq 1 ] || echo "systemctl cat shows $n files, expected only the packaged unit"
}
