#!/usr/bin/env bash
# Root side of the tpm-clear-* cases (F140, acceptance 8 of SPEC.md). Needs WORK, MODULE and E2E_TPM. Mode none has no TPM to clear: the cases are reported skipped.
# Isolation: clearing the TPM of the run would make every key of the other steps unusable, so the step starts a second, independent swtpm ($TC_SOCK, state in $TC_STATE; in mode lacking
# behind /e2e-bin/tpm-filter, alg=0x16, as the TPM of the run), points the e2e drop-in at it (tpmfail-lib.sh: tf_point) and clears that one. A trap puts the drop-in back at the TPM of the
# run, restarts the service and stops the second swtpm, also when a case fails; the main TPM is never touched.
# Flow (alice's calls in tpmclear-user.sh): import an RSA 2048 and a P-256 key (kind tpm); round `pre` signs with both over D-Bus and over pkcs11-tool; a primary under the owner hierarchy
# (fixed template) is made and its name kept; `tpm2_clear` on the second swtpm's socket (lockout hierarchy, empty auth); the primary is made again (its name must differ: the seed changed);
# rounds a1 and a2 try to sign again; the lists and the state directory; the deletes; a re-import of tc-rsa signs (the rig and the new seed work); it is deleted.
#   tpm-clear-sign-fails  both keys signed before; after the clear every attempt (D-Bus Sign, pkcs11-tool; twice) fails: KeyLost with the documented text, CKR_DEVICE_ERROR; the journal has
#                         one sign / signing_failed / key_lost entry per Sign call (the agent's approvals are the count, so a tool that calls twice is not judged wrong) with key, kind tpm, uid, no secret, no
#                         entry of another operation; the controls: the owner primary's name changed, and the re-imported key signs
#   tpm-clear-keys-listed same ids with kind tpm in ListKeys and `custodio list` after as before; state directory identical to the one taken after the signing before the clear (the signing
#                         before it leaves the directory as it was: a control) and records still there
#   tpm-clear-delete      both deletes succeed, records and ListKeys entries gone, one `delete` entry per key; a re-import of tc-rsa has kind tpm, signs, and is deleted
# Placement: guest.sh runs this after the tpmfail step and before the upgrade.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
: "${WORK:?}" "${MODULE:?}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e/tpmclear-cases.sh
source "$here/tpmclear-cases.sh"
mode=${E2E_TPM:-swtpm}
# F163: in a VM run (E2E_VM=1) the TPM is the guest's own (kernel resource manager, $TC_VM_TCTI) and is the one cleared (route A of docs/findings/F163.md): no second swtpm, no
# drop-in, no filter. swtpm is the full mode (kind tpm), lacking the lacking mode (kind encrypted-tpm; root reads each credential with the reader of F157 after every import).
kind=tpm
vm=${E2E_VM:-}
if [ -n "$vm" ]; then
    case $mode in
    swtpm) ;;
    lacking) kind=encrypted-tpm ;;
    *) echo "e2e: FAIL: a VM run has the TPM mode swtpm or lacking, not '$mode'" >&2; exit 1 ;;
    esac
fi
if [ "$mode" = none ]; then
    tpmclear_skip_all "$mode"
    exit 0
fi
# shellcheck source=e2e/tpmkind-lib.sh
source "$here/tpmkind-lib.sh"
# shellcheck source=e2e/tpm-lib.sh
source "$here/tpm-lib.sh"
if [ -z "$vm" ]; then
    # shellcheck source=e2e/tpmfail-lib.sh
    source "$here/tpmfail-lib.sh"
fi
tools="tpm2_clear tpm2_createprimary tpm2_readpublic tpm2_flushcontext openssl python3 busctl journalctl find sha256sum pkcs11-tool"
[ -n "$vm" ] || tools="$tools tpm2_getcap tpm2_testparms swtpm swtpm_setup swtpm_ioctl"
for tool in $tools; do
    command -v "$tool" > /dev/null || fail "$tool is not installed"
done
TC=$WORK/tpmclear
rm -rf "${TC:?}"
mkdir -p "$TC/in" "$TC/out"
tk_make "$TC" tpmclear
rm -f "${TC:?}"/*.crt
chmod 644 "$TC"/*.p12
fx="$(fixture_problems "$TC/rsa.p12" rsa)
$(fixture_problems "$TC/ec.p12" ec)"
[ "$(printf '%s' "$fx" | tr -d '[:space:]')" = '' ] || fail "the fixtures are not what the cases need: $fx"
head -c 1000 /dev/urandom > "$TC/in/msg.bin"
chmod -R a+rX "$TC"
chmod 1777 "$TC" "$TC/in" "$TC/out"
tcj() { python3 -I "$here/tpmclear.py" "$@"; }
state=$(readlink -f "${TC_STATE_DIR:-/var/lib/custodio}") # TC_STATE_DIR, TC_SCAN: the host test points them at fixtures
[ -d "$state" ] || fail "the state directory $state does not exist"
uid=$(id -u alice)
KEYS=(tc-rsa tc-ec)
IDS=tc-rsa,tc-ec
# what must not be in a journal entry: the password and bytes of the file that holds the key (raw, hex and base64)
secret_hex=$(dd if="$TC/rsa.p12" bs=1 skip=200 count=24 2> /dev/null | od -An -tx1 | tr -d ' \n')
secret_b64=$(dd if="$TC/rsa.p12" bs=1 skip=201 count=24 2> /dev/null | base64 -w0)
SECRETS=(e2e-password "$secret_hex" "$secret_b64")

# the second TPM: its socket is under $TPM_DIR, which the unit binds read-only; in lacking the filter is on the socket and swtpm on the upstream one
TC_SOCK=$TPM_DIR/clear.sock
TC_UP=$TPM_DIR/clear-up.sock
TC_STATE=/var/tmp/custodio-e2e-tpmclear-state
TC_TCTI=swtpm:path=$TC_SOCK
[ -z "$vm" ] || TC_TCTI=${TC_VM_TCTI:-device:/dev/tpmrm0}
second_stop() {
    local pid ctrl
    pid=$(cat "$TC_STATE/filter.pid" 2> /dev/null || true)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null || true
    for ctrl in "$TC_UP.ctrl" "$TC_SOCK.ctrl"; do
        if [ -S "$ctrl" ]; then swtpm_ioctl --unix "$ctrl" -s > /dev/null 2>&1 || true; fi
    done
    for _ in $(seq 50); do pgrep -f "dir=$TC_STATE" > /dev/null || break; sleep 0.1; done
    rm -rf "${TC_STATE:?}" "$TC_SOCK" "$TC_SOCK.ctrl" "$TC_UP" "$TC_UP.ctrl"
}
second_start() {
    if [ "$mode" = lacking ]; then
        tpm_swtpm_start "$TC_UP" "$TC_STATE" || return 1
        setsid "$TPM_FILTER" "$TC_UP" "$TC_SOCK" "alg=$TPM_LACKING_ALG" > "$TC_STATE/filter.log" 2>&1 < /dev/null &
        echo $! > "$TC_STATE/filter.pid"
        for _ in $(seq 50); do grep -q '^ready ' "$TC_STATE/filter.log" 2> /dev/null && return 0; sleep 0.1; done
        tail -n 5 "$TC_STATE/filter.log" >&2
        tpm_fail "the filter of the second TPM did not become ready"
    else
        tpm_swtpm_start "$TC_SOCK" "$TC_STATE"
    fi
}
second_observe() { # the second TPM is what the mode says (swtpm: it answers; lacking: it answers and lacks RSAPSS while its own swtpm has it), the way tpm_observe checks the first
    local out n
    out=$(TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_getcap algorithms 2>&1) || { echo "$out" | tail -n 3 >&2; tpm_fail "the second TPM does not answer tpm2_getcap"; return 1; }
    n=$(grep -c '^[a-z0-9_-]*:$' <<< "$out" || true)
    [ "$n" -ge 10 ] || { tpm_fail "the second TPM lists only $n algorithms"; return 1; }
    [ "$mode" = lacking ] || return 0
    ! grep -q '^rsapss:' <<< "$out" || { tpm_fail "mode lacking: the second TPM still lists rsapss"; return 1; }
    out=$(TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_testparms "$TPM_LACKING_PARMS" 2>&1) && { tpm_fail "mode lacking: the second TPM accepts $TPM_LACKING_PARMS"; return 1; }
    grep -qiE '0x0*1d2' <<< "$out" || { tpm_fail "mode lacking: TestParms on the second TPM did not fail with TPM_RC_SCHEME"; return 1; }
    TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_testparms "$TPM_HAVING_PARMS" > /dev/null 2>&1 || { tpm_fail "mode lacking: the second TPM refuses $TPM_HAVING_PARMS"; return 1; }
    TPM2TOOLS_TCTI="swtpm:path=$TC_UP" timeout 60 tpm2_testparms "$TPM_LACKING_PARMS" > /dev/null 2>&1 || { tpm_fail "mode lacking: the real swtpm of the second TPM refuses $TPM_LACKING_PARMS, so nothing is lacking by the filter"; return 1; }
}

dirty=''
on_exit() {
    local rc=$?
    if [ -n "$dirty" ]; then tf_point "$TPM_SOCK" > /dev/null 2>&1 || true; fi
    [ -n "$vm" ] || second_stop
    exit "$rc"
}
trap on_exit EXIT
if [ -z "$vm" ]; then
    mkdir -p "$TC_STATE"
    second_start || fail "the second TPM did not start"
    second_observe
    echo "tpmclear: second TPM up ($mode), observed"
fi
read_creds() { # ID...: the reader (F157) on the credential of each key, in lacking of a VM run only; prints the problems
    [ "$kind" = encrypted-tpm ] || return 0
    # shellcheck source=e2e/vm/cred-lib.sh
    source "$here/vm/cred-lib.sh"
    local id
    for id in "$@"; do vm_read_credential "$id" >&2 || echo "reader: $id: the credential of an encrypted-tpm key did not pass the reader"; done
}

SRK_ATTRS='fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt'
primary_name() { # FILE: the name (hex) of a primary under the owner hierarchy made with one fixed template and no unique data, on the second TPM; only the seed can change it
    local d=$TC/prim rc=0
    mkdir -p "$d"
    ( cd "$d" && TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_createprimary -C o -G ecc256:aes128cfb -a "$SRK_ATTRS" -c p.ctx > createprimary.out 2>&1 \
        && TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_readpublic -c p.ctx -n p.name > readpublic.out 2>&1 ) < /dev/null || rc=$?
    TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_flushcontext -t > /dev/null 2>&1 < /dev/null || true
    [ "$rc" = 0 ] || { cat "$d"/*.out >&2; fail "the owner-hierarchy primary could not be made on the second TPM"; }
    od -An -tx1 -v "$d/p.name" | tr -d ' \n' > "$1"
}
alice() { # NAME ACTION ARGS...: alice's session; its output in $TC/alice-NAME.out
    local name=$1
    shift
    timeout 300 su -l alice -c "WORK=$WORK MODULE=$MODULE bash /e2e/tpmclear-user.sh $*" > "$TC/alice-$name.out" 2>&1 || { cat "$TC/alice-$name.out" >&2; fail "alice's session ($*) failed"; }
}
state_listing() { # FILE: names, types, modes, sizes and checksums of everything the service keeps
    { find "$state/" -printf '%y %p %m %s\n' | sort; find "$state/" -type f -exec sha256sum {} + | sort -k2; } > "$1"
}
scan() { # FILE: the stored records (uid, id, kind, parent name)
    mkdir -p "$TC/rec"
    ${TC_SCAN:-python3 -I "$here/tpmdup.py" scan} "$state" "$TC/rec" > "$1" || fail "the records could not be read"
}
cursor() { journalctl --sync; journalctl -n1 --show-cursor | sed -n 's/^-- cursor: //p'; }
journal_since() { # CURSOR FILE
    journalctl --sync
    journalctl --after-cursor="$1" _SYSTEMD_UNIT=custodio.service -o json --no-pager > "$2"
}
problems=''
add_reader() { # PROBLEMS of the reader (they belong to no case)
    [ -z "$(printf '%s' "$1" | tr -d '[:space:]')" ] || problems="$problems
reader:
$1"
}
judge() { # CASE PROBLEMS: the case is reported when it has no problem
    local p
    p=$(printf '%s\n' "$2" | sed '/^$/d')
    if [ -z "$p" ]; then case_run "$1"; else problems="$problems
$1:
$p"; fi
}

# the service uses the second TPM from here on; both keys are imported and sign
if [ -z "$vm" ]; then
    dirty=1
    tf_point "$TC_SOCK"
fi
alice import import "$TC/imp" rsa ec
add_reader "$(read_creds "${KEYS[@]}")"
state_listing "$TC/state-imported"
alice pre sign pre rsa ec
state_listing "$TC/state-signed"
scan "$TC/scan-before"
primary_name "$TC/name-before"
echo "tpmclear: before the clear: owner primary name $(cat "$TC/name-before")"

# the clear: the lockout hierarchy with its empty auth, on the second TPM's socket (in lacking: through the filter)
( TPM2TOOLS_TCTI=$TC_TCTI timeout 60 tpm2_clear > "$TC/clear.out" 2>&1 < /dev/null; echo $? > "$TC/clear.rc" ) || true
echo "tpmclear: tpm2_clear exit $(cat "$TC/clear.rc") (${mode}): $(head -n 2 "$TC/clear.out" | tr '\n' ' ')"
primary_name "$TC/name-after"
echo "tpmclear: after the clear: owner primary name $(cat "$TC/name-after")"

# two rounds of attempts: each a D-Bus Sign and a pkcs11-tool signature per key, at once; the journal entries of each
for r in a1 a2; do
    cur=$(cursor)
    alice "$r" sign "$r" rsa ec
    journal_since "$cur" "$TC/journal-$r.json"
done
state_listing "$TC/state-after-sign"
alice list list "$TC/after-clear"
scan "$TC/scan-after"
echo "tpmclear: Sign calls per round: a1 $(cat "$TC/out/a1.count"), a2 $(cat "$TC/out/a2.count"); journal entries: a1 $(grep -c CUSTODIO_OPERATION "$TC/journal-a1.json" || true), a2 $(grep -c CUSTODIO_OPERATION "$TC/journal-a2.json" || true)"

# the deletes
cur=$(cursor)
alice delete delete "$TC/del" "${KEYS[@]}"
journal_since "$cur" "$TC/journal-delete.json"
state_listing "$TC/state-deleted"
scan "$TC/scan-deleted"

# the recovery: the same id imported again works on the new seed, signs, and is deleted
alice reimport import "$TC/reimp" rsa
add_reader "$(read_creds tc-rsa)"
alice reimp-sign sign reimp rsa
scan "$TC/scan-reimp"
alice end delete "$TC/end" tc-rsa
scan "$TC/scan-end"

# the end: the TPM of the run is back, the service on it
ready=''
if [ -z "$vm" ]; then
    tf_point "$TPM_SOCK"
    dirty=''
    second_stop
    tpm_observe "$mode" > /dev/null 2> "$TC/observe.err" || ready="the unit's TPM is not the mode's: $(head -n 2 "$TC/observe.err")"
fi
systemctl is-active --quiet custodio || ready="$ready
the service is not active after the restore"
busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 org.freedesktop.DBus.Peer Ping > /dev/null 2>&1 || ready="$ready
the service does not answer Ping after the restore"
if [ -z "$vm" ]; then
    ! pgrep -f "dir=$TC_STATE" > /dev/null || ready="$ready
the second swtpm is still running"
fi

# judgements
O=$TC/out
sign_ok() { # TAG ID TYPE
    tcj dbus "$O/$1-$2.dbus" ok
    tcj p11ok "$O/$1-$2.rc" "$O/$1-$2.log" "$TC/in/$2.pub.pem" "$TC/in/msg.bin" "$O/$1-$2.sig"
}
common="$(tcj rc "$TC/clear.rc" tpm2_clear)
$(tcj owner "$TC/name-before" "$TC/name-after")
$(tcj listed "$TC/imp/list.out" "$kind" "${KEYS[@]}")"
fails=''
for r in a1 a2; do
    for id in "${KEYS[@]}"; do
        fails="$fails
$(tcj dbus "$O/$r-$id.dbus" KeyLost)
$(tcj p11fail "$O/$r-$id.rc" "$O/$r-$id.log")"
    done
    fails="$fails
$(tcj journal "$TC/journal-$r.json" "$uid" "$kind" "$(cat "$O/$r.count")" "$IDS" "${SECRETS[@]}")"
done
pre=''
for id in "${KEYS[@]}"; do pre="$pre
$(sign_ok pre "$id")"; done
reimp="$(sign_ok reimp tc-rsa)
$(tcj listed "$TC/reimp/list.out" "$kind" tc-rsa)"
judge tpm-clear-sign-fails "$common
$pre
$fails
$reimp
$(tcj state "$TC/state-imported" "$TC/state-signed")"
judge tpm-clear-keys-listed "$common
$(tcj listed "$TC/after-clear/list.out" "$kind" "${KEYS[@]}")
$(tcj samelist "$TC/imp/list.out" "$TC/after-clear/list.out" "${KEYS[@]}")
$(tcj clilist "$TC/after-clear/cli.out" "$kind" "${KEYS[@]}")
$(tcj state "$TC/state-signed" "$TC/state-after-sign")
$(tcj records "$TC/scan-before" present "$kind" "${KEYS[@]}")
$(tcj records "$TC/scan-after" present "$kind" "${KEYS[@]}")"
dels=''
for id in "${KEYS[@]}"; do dels="$dels
$(tcj rc "$TC/del/delete-$id.rc" "delete $id")"; done
judge tpm-clear-delete "$common
$dels
$(tcj gone "$TC/del/list.out" "${KEYS[@]}")
$(tcj records "$TC/scan-deleted" absent "$kind" "${KEYS[@]}")
$(tcj deljournal "$TC/journal-delete.json" "$uid" "${KEYS[@]}")
$reimp
$(tcj records "$TC/scan-reimp" present "$kind" tc-rsa)
$(tcj rc "$TC/end/delete-tc-rsa.rc" "delete of the re-imported tc-rsa")
$(tcj gone "$TC/end/list.out" "${KEYS[@]}")
$(tcj records "$TC/scan-end" absent "$kind" "${KEYS[@]}")"
[ -z "$ready" ] || problems="$problems
end:
$ready"
[ -z "$(printf '%s' "$problems" | tr -d '[:space:]')" ] || fail "tpm-clear cases:$problems"
echo "tpmclear-run: passed"
