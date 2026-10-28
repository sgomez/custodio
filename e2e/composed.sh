# shellcheck shell=bash
# Sourced by user.sh after the M0 checks: composed mechanisms (acceptance 1), the multi-part client
# OpenSSL + pkcs11-provider (acceptance 2) and C_Login before signing (acceptance 6).
# Uses WORK, MODULE, E2E_DIR and the helpers fail and requests of user.sh.
# shellcheck disable=SC2154 # WORK, MODULE, E2E_DIR and sig are set by user.sh, which sources this file

pub_rsa=$WORK/rsa.pub
pub_ec=$WORK/ec.pub
spy_log=$WORK/spy.log

# OpenSC's spy module; it is never replaced by $MODULE, a missing spy fails the run.
spy=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so
[ -f "$spy" ] || spy=$(find /usr/lib -name pkcs11-spy.so 2>/dev/null | head -n 1)
if [ -z "$spy" ] || [ ! -f "$spy" ]; then fail "pkcs11-spy.so (OpenSC) not found"; fi

# p11sign_composed key mechanism [extra pkcs11-tool args]: signs data.bin into $sig.
p11sign_composed() {
    local key=$1 mech=$2
    shift 2
    rm -f "$sig"
    pkcs11-tool --module "$MODULE" --token-label "$key" --label "$key" --type privkey --sign \
        --mechanism "$mech" --input-file "$WORK/data.bin" --output-file "$sig" "$@" >"$WORK/p11.log" 2>&1
}

# verify_openssl pubkey digest sig [message]: succeeds when OpenSSL verifies the signature.
verify_openssl() {
    openssl dgst "-$2" -verify "$1" -signature "$3" "${4:-$WORK/data.bin}" 2>&1 | grep -q "Verified OK"
}

# --- Acceptance 1: the six composed mechanisms ---------------------------------------------------
for m in SHA256-RSA-PKCS SHA384-RSA-PKCS SHA512-RSA-PKCS; do
    h=${m#SHA}
    h=${h%%-*}
    echo approve > "$E2E_DIR/mode"
    before=$(requests)
    p11sign_composed rsa1 "$m" || { cat "$WORK/p11.log" >&2; fail "SHA$h-RSA-PKCS signature failed"; }
    [ "$(stat -c %s "$sig")" -eq 256 ] || fail "SHA$h-RSA-PKCS signature is not 256 bytes"
    [ "$(requests)" -eq $((before + 1)) ] || fail "SHA$h-RSA-PKCS: expected exactly one request"
    verify_openssl "$pub_rsa" "sha$h" "$sig" || fail "OpenSSL did not verify the SHA$h-RSA-PKCS signature"
    other=sha256
    [ "$h" = 256 ] && other=sha384
    if verify_openssl "$pub_rsa" "$other" "$sig"; then fail "SHA$h-RSA-PKCS signature verified with $other"; fi
    echo "ok: SHA$h-RSA-PKCS"
done
echo deny > "$E2E_DIR/mode"
before=$(requests)
if p11sign_composed rsa1 SHA256-RSA-PKCS; then fail "a denied SHA256-RSA-PKCS signature succeeded"; fi
[ ! -s "$sig" ] || fail "a denied SHA256-RSA-PKCS signature produced output"
[ "$(requests)" -eq $((before + 1)) ] || fail "SHA256-RSA-PKCS deny: expected exactly one request"
echo "ok: SHA256-RSA-PKCS deny"

for m in ECDSA-SHA256 ECDSA-SHA384 ECDSA-SHA512; do
    h=${m#ECDSA-SHA}
    echo approve > "$E2E_DIR/mode"
    before=$(requests)
    p11sign_composed ec1 "$m" --signature-format openssl || { cat "$WORK/p11.log" >&2; fail "ECDSA-SHA$h signature failed"; }
    [ -s "$sig" ] || fail "ECDSA-SHA$h signature is empty"
    [ "$(requests)" -eq $((before + 1)) ] || fail "ECDSA-SHA$h: expected exactly one request"
    verify_openssl "$pub_ec" "sha$h" "$sig" || fail "OpenSSL did not verify the ECDSA-SHA$h signature"
    other=sha256
    [ "$h" = 256 ] && other=sha384
    if verify_openssl "$pub_ec" "$other" "$sig"; then fail "ECDSA-SHA$h signature verified with $other"; fi
    echo "ok: ECDSA-SHA$h"
done
echo deny > "$E2E_DIR/mode"
before=$(requests)
if p11sign_composed ec1 ECDSA-SHA256 --signature-format openssl; then fail "a denied ECDSA-SHA256 signature succeeded"; fi
[ ! -s "$sig" ] || fail "a denied ECDSA-SHA256 signature produced output"
[ "$(requests)" -eq $((before + 1)) ] || fail "ECDSA-SHA256 deny: expected exactly one request"
echo "ok: ECDSA-SHA256 deny"

# --- Acceptance 2: OpenSSL with pkcs11-provider (C_SignUpdate / C_SignFinal) ---------------------
export PKCS11_PROVIDER_MODULE=$spy
export PKCS11SPY=$MODULE
export PKCS11SPY_OUTPUT=$spy_log

# spy_calls NAME: how many times the spy log shows a call to NAME (a whole function name).
spy_calls() { grep -cE "^[0-9]+: $1\$" "$spy_log" || true; }
# spy_last_final_ok: the last C_SignFinal in the spy log returned CKR_OK.
spy_last_final_ok() {
    awk '/^[0-9]+: C_SignFinal$/ { ok = 0; seen = 1; next }
         seen && /^Returned:/ { ok = ($0 ~ /CKR_OK/); seen = 0 }
         END { exit ok ? 0 : 1 }' "$spy_log"
}
check_multipart_log() { # label, minimum number of C_SignUpdate
    [ -s "$spy_log" ] || fail "$1: the spy log is empty"
    [ "$(spy_calls C_Initialize)" -ge 1 ] || fail "$1: the module was not loaded through the spy"
    [ "$(spy_calls C_SignInit)" -ge 1 ] || fail "$1: no C_SignInit"
    [ "$(spy_calls C_SignUpdate)" -ge "$2" ] || fail "$1: fewer than $2 C_SignUpdate"
    [ "$(spy_calls C_SignFinal)" -ge 1 ] || fail "$1: no C_SignFinal"
    spy_last_final_ok || fail "$1: the last C_SignFinal did not return CKR_OK"
    if grep -qwE "C_Sign" "$spy_log"; then fail "$1: the client used one-shot C_Sign"; fi
}
provider_sign() { # key, input file; output in $sig
    rm -f "$sig" "$spy_log"
    openssl dgst -sha256 -provider pkcs11 -provider default \
        -sign "pkcs11:token=$1;object=$1;type=private" -out "$sig" "$2" >"$WORK/provider.log" 2>&1
}

head -c 1100000 /dev/urandom > "$WORK/big.bin"
echo approve > "$E2E_DIR/mode"
for k in rsa ec; do
    before=$(requests)
    provider_sign "${k}1" "$WORK/data.bin" || { cat "$WORK/provider.log" >&2; fail "pkcs11-provider ${k}1 signature failed"; }
    [ "$(requests)" -eq $((before + 1)) ] || fail "pkcs11-provider ${k}1: expected exactly one request"
    check_multipart_log "pkcs11-provider ${k}1" 1
    verify_openssl "$WORK/$k.pub" sha256 "$sig" || fail "OpenSSL did not verify the pkcs11-provider ${k}1 signature"
    echo "ok: pkcs11-provider ${k}1 (C_SignUpdate/C_SignFinal)"
done

before=$(requests)
provider_sign rsa1 "$WORK/big.bin" || { cat "$WORK/provider.log" >&2; fail "pkcs11-provider signature of a large file failed"; }
[ "$(requests)" -eq $((before + 1)) ] || fail "pkcs11-provider large file: expected exactly one request"
check_multipart_log "pkcs11-provider large file" 2
verify_openssl "$pub_rsa" sha256 "$sig" "$WORK/big.bin" || fail "OpenSSL did not verify the large-file signature"
echo "ok: pkcs11-provider several C_SignUpdate"

echo deny > "$E2E_DIR/mode"
before=$(requests)
if provider_sign rsa1 "$WORK/data.bin"; then fail "a denied pkcs11-provider signature succeeded"; fi
[ ! -s "$sig" ] || fail "a denied pkcs11-provider signature produced output"
[ "$(requests)" -eq $((before + 1)) ] || fail "pkcs11-provider deny: expected exactly one request"
echo "ok: pkcs11-provider deny"
unset PKCS11_PROVIDER_MODULE

# --- Acceptance 6: C_Login before signing still asks polkit --------------------------------------
# spy_line PATTERN: number of the first spy-log line that matches the extended regex.
spy_line() { grep -nE -m1 "$1" "$spy_log" | cut -d: -f1; }
# login_sign key mechanism login-type-args...: pkcs11-tool through the spy, with --login and a PIN.
login_sign() {
    local key=$1 mech=$2
    shift 2
    rm -f "$sig" "$spy_log"
    pkcs11-tool --module "$spy" --token-label "$key" --label "$key" --type privkey --sign \
        --mechanism "$mech" --input-file "$WORK/data.bin" --output-file "$sig" --login --pin 1234 "$@" \
        >"$WORK/p11.log" 2>&1
}
# check_login_log USERTYPE: C_Login with that user type returned CKR_OK, ahead of C_Sign.
check_login_log() {
    local login_at init_at sign_at
    login_at=$(spy_line '^[0-9]+: C_Login$')
    [ -n "$login_at" ] || fail "login case: pkcs11-tool never called C_Login"
    sed -n "$((login_at + 1)),\$p" "$spy_log" | grep -m1 -E '^\[in\] userType' | grep -q "$1" \
        || fail "login case: C_Login was not called with $1"
    sed -n "$((login_at + 1)),\$p" "$spy_log" | grep -m1 '^Returned:' | grep -q CKR_OK \
        || fail "login case: C_Login did not return CKR_OK"
    init_at=$(spy_line '^[0-9]+: C_SignInit$')
    sign_at=$(spy_line '^[0-9]+: C_Sign$')
    if [ -z "$init_at" ] || [ -z "$sign_at" ]; then fail "login case: no C_SignInit/C_Sign in the spy log"; fi
    [ "$init_at" -lt "$sign_at" ] || fail "login case: C_Sign before C_SignInit"
    [ "$login_at" -lt "$sign_at" ] || fail "login case: C_Login after C_Sign"
}

export PKCS11SPY=$MODULE
export PKCS11SPY_OUTPUT=$spy_log

echo approve > "$E2E_DIR/mode"
before=$(requests)
login_sign rsa1 SHA256-RSA-PKCS || { cat "$WORK/p11.log" >&2; fail "login + SHA256-RSA-PKCS failed"; }
[ "$(requests)" -eq $((before + 1)) ] || fail "login + SHA256-RSA-PKCS: expected exactly one request"
verify_openssl "$pub_rsa" sha256 "$sig" || fail "OpenSSL did not verify the signature made after --login"
check_login_log CKU_USER
[ "$(spy_line '^[0-9]+: C_Login$')" -lt "$(spy_line '^[0-9]+: C_SignInit$')" ] || fail "login case: C_Login after C_SignInit"
echo "ok: --login approve (RSA)"

before=$(requests)
login_sign ec1 ECDSA-SHA256 --signature-format openssl || { cat "$WORK/p11.log" >&2; fail "login + ECDSA-SHA256 failed"; }
[ "$(requests)" -eq $((before + 1)) ] || fail "login + ECDSA-SHA256: expected exactly one request"
verify_openssl "$pub_ec" sha256 "$sig" || fail "OpenSSL did not verify the ECDSA signature made after --login"
echo "ok: --login approve (ECDSA)"

before=$(requests)
login_sign rsa1 SHA256-RSA-PKCS || fail "second --login signature failed"
[ "$(requests)" -eq $((before + 1)) ] || fail "a second --login signature did not ask again"
check_login_log CKU_USER
echo "ok: --login, second signature asks again"

echo deny > "$E2E_DIR/mode"
before=$(requests)
if login_sign rsa1 SHA256-RSA-PKCS; then fail "a denied signature after --login succeeded"; fi
[ ! -s "$sig" ] || fail "a denied signature after --login produced output"
[ "$(requests)" -eq $((before + 1)) ] || fail "--login deny: expected exactly one request, the login authorized nothing"
check_login_log CKU_USER
echo "ok: --login deny"

echo approve > "$E2E_DIR/mode"
before=$(requests)
login_sign rsa1 SHA256-RSA-PKCS --login-type context-specific || { cat "$WORK/p11.log" >&2; fail "context-specific login + SHA256-RSA-PKCS failed"; }
[ "$(requests)" -eq $((before + 1)) ] || fail "context-specific login: expected exactly one request"
verify_openssl "$pub_rsa" sha256 "$sig" || fail "OpenSSL did not verify the signature made after a context-specific login"
check_login_log CKU_CONTEXT_SPECIFIC
echo "ok: --login --login-type context-specific approve"
unset PKCS11SPY PKCS11SPY_OUTPUT
