#!/bin/bash
# User side of vm-fingerprint-sign (F200): one signature through the PKCS#11 module, approved by polkit with the text agent `pkttyagent` registered for the signing process itself
# (no logind session here, so the agent is found by the process). Usage: fingerprint-sign.sh MODULE KEY_ID DATA SIG
module=$1 key=$2 data=$3 sig=$4
fifo=$(mktemp -u /tmp/fp-sign-fifo.XXXXXX)
mkfifo "$fifo"
trap 'rm -f "$fifo"' EXIT
( read -r _ < "$fifo"; exec pkcs11-tool --module "$module" --token-label "$key" --label "$key" --type privkey --sign --mechanism SHA256-RSA-PKCS --input-file "$data" --output-file "$sig" > /dev/null 2>&1 ) &
signer=$!
exec 3< <(pkttyagent --process "$signer" --notify-fd 1 --fallback)
read -r -n1 -u3 _ # the agent is registered
echo go > "$fifo"
wait "$signer"
