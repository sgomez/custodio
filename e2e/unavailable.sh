#!/usr/bin/env bash
# Runs as "alice" (su -l) while polkit is stopped and masked: one signature that must fail with
# authorization_unavailable and write nothing. Appends its ledger line for journal-check.sh.
# Needs WORK and MODULE. The input is over 1024 bytes so pkcs11-tool does not retry a failed one-shot signature.
set -euo pipefail
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
in=$WORK/evidence/unavailable.in
out=$WORK/evidence/unavailable.sig
pidfile=$WORK/unavailable.pid
status=0
head -c 2000 /dev/urandom > "$in"
# shellcheck disable=SC2016 # the script is for the inner sh: $$ is its pid, which exec keeps
timeout 60 sh -c 'echo $$ > "$1"; shift; exec "$@"' wrapper "$pidfile" \
    pkcs11-tool --module "$MODULE" --token-label rsa1 --label rsa1 --type privkey --sign \
    --mechanism SHA256-RSA-PKCS --input-file "$in" --output-file "$out" >"$WORK/unavailable.log" 2>&1 || status=$?
[ "$status" -ne 124 ] || fail "signature hung while polkit was unavailable"
[ "$status" -ne 0 ] || fail "a signature succeeded while polkit was unavailable"
[ ! -s "$out" ] || fail "a signature was written while polkit was unavailable"
[ -s "$pidfile" ] || fail "the wrapper wrote no pid"
echo "authorization_unavailable rsa1 $(cat "$pidfile") $(id -u)" >> "$WORK/journal.cases"
echo "ok: no signature while polkit is unavailable"
