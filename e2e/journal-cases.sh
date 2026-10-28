# shellcheck shell=bash
# Sourced by user.sh after composed.sh, as the ordinary user with the agent running: the signatures whose
# journal entries journal-check.sh looks for (acceptance 7). Each case is one signature by its own process;
# the wrapper writes its pid, which is the pid the bus reports to the service, and the case appends
# "<expected outcome> <key id> <pid> <uid>" to the ledger. Uses WORK, MODULE, E2E_DIR, fail and requests.
evidence=$WORK/evidence
ledger=$WORK/journal.cases
mkdir -p "$evidence"
: > "$ledger"
journal_n=0

# journal_case NAME OUTCOME KEY MECHANISM-OR-provider SIZE: one signature of SIZE random bytes. Every case, a
# denied one included, ends within a minute: a hung call fails with its own message.
journal_case() {
    local name=$1 outcome=$2 key=$3 how=$4 size=$5
    local in=$evidence/$name.in out=$evidence/$name.sig pidfile=$WORK/$name.pid status=0 before
    head -c "$size" /dev/urandom > "$in"
    case $outcome in signed) echo approve > "$E2E_DIR/mode" ;; *) echo deny > "$E2E_DIR/mode" ;; esac
    before=$(requests)
    # shellcheck disable=SC2016 # the script is for the inner sh: $$ is its pid, which exec keeps
    if [ "$how" = provider ]; then
        PKCS11_PROVIDER_MODULE=$MODULE timeout 60 sh -c 'echo $$ > "$1"; shift; exec "$@"' wrapper "$pidfile" \
            openssl dgst -sha256 -provider pkcs11 -provider default \
            -sign "pkcs11:token=$key;object=$key;type=private" -out "$out" "$in" >"$WORK/$name.log" 2>&1 || status=$?
    else
        timeout 60 sh -c 'echo $$ > "$1"; shift; exec "$@"' wrapper "$pidfile" \
            pkcs11-tool --module "$MODULE" --token-label "$key" --label "$key" --type privkey --sign \
            --mechanism "$how" --input-file "$in" --output-file "$out" >"$WORK/$name.log" 2>&1 || status=$?
    fi
    [ "$status" -ne 124 ] || fail "journal case $name: signature hung"
    if [ "$outcome" = signed ]; then
        [ "$status" -eq 0 ] || { cat "$WORK/$name.log" >&2; fail "journal case $name: approved signature failed"; }
        [ -s "$out" ] || fail "journal case $name: no signature written"
    else
        [ "$status" -ne 0 ] || fail "journal case $name: a denied signature succeeded"
        [ ! -s "$out" ] || fail "journal case $name: a denied signature produced output"
    fi
    [ "$(requests)" -eq $((before + 1)) ] || fail "journal case $name: expected exactly one request"
    [ -s "$pidfile" ] || fail "journal case $name: the wrapper wrote no pid"
    echo "$outcome $key $(cat "$pidfile") $(id -u)" >> "$ledger"
    journal_n=$((journal_n + 1))
}

# Over 1024 bytes for the denied cases, so pkcs11-tool does not retry a failed one-shot C_Sign as a second signature.
journal_case rsa-approve signed rsa1 SHA256-RSA-PKCS 1500
journal_case rsa-deny denied rsa1 SHA256-RSA-PKCS 2000
journal_case ec-approve signed ec1 ECDSA-SHA256 1500
journal_case ec-deny denied ec1 ECDSA-SHA256 2000
journal_case provider-approve signed rsa1 provider 3000
[ "$(sort -k3,3 -u "$ledger" | wc -l)" -eq "$journal_n" ] || fail "two journal cases share a pid"
echo "ok: $journal_n signatures for the journal checks"
