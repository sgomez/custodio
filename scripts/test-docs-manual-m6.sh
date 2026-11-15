#!/usr/bin/env bash
# Test of section 25 of docs/manual-acceptance.md (F186, M6 acceptance 19: Firefox snap, TLS client authentication). It RUNS what
# the page says that can run in the dev container, through scripts/lib/docs-manual-m6-check.py (its header lists everything it
# does): the `openssl` commands that make the test CA, the server certificate and the RSA 2048 and P-256 client certificates, the
# key types read with `openssl pkey -text`, the page's `openssl s_server -Verify` once per `s_client` line (the only
# substitutions: `-accept 4433` becomes `-accept 127.0.0.1:0` with the port read from the ACCEPT line, and `localhost:4433` in the
# client line that port; judged by the server's own output, never by `s_client`'s exit status), a client with no certificate and
# one of another CA are refused, and the page's `journalctl` query is checked on its matches (unit, service uid, the sign
# operation, the full Firefox label), its field names against docs/audit.md and its syntax by `journalctl --directory` over an empty
# directory (no fixture journal can be written in the dev container: no systemd-journal-remote, no python systemd). What only the
# VM can run is in `sh vm` blocks, counted and listed, never skipped silently. Only section 25 is read.
# Negative controls: a copy of the page with one claim broken must differ from the page and must fail; they run in parallel.
# Usage: scripts/test-docs-manual-m6.sh   (CONTROL_WHY=1 also prints the failures of each broken page)
# SC2016: the sed expressions hold literal backticks and dollars.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PAGE=docs/manual-acceptance.md
CHECK=scripts/lib/docs-manual-m6-check.py

for tool in python3 openssl journalctl bash; do
    command -v "$tool" > /dev/null 2>&1 || { echo "test-docs-manual-m6: $tool is not installed" >&2; exit 127; }
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

python3 -I "$CHECK" "$PAGE" "$ROOT" || { echo "test-docs-manual-m6: the page fails its checks" >&2; exit 1; }
echo "test-docs-manual-m6: the page passes"

pids=()
control() { # label sed-expression
    (
        f=$tmp/page.$BASHPID
        sed -E -e "/^## 25\\./,\$ { $2 }" "$PAGE" > "$f"
        if cmp -s "$PAGE" "$f"; then echo "control '$1': the copy equals the page, the control is void" >&2; exit 1; fi
        if python3 -I "$CHECK" "$f" "$ROOT" > /dev/null 2> "$f.err"; then echo "control '$1': a broken page passed" >&2; exit 1; fi
        [ -z "${CONTROL_WHY:-}" ] || { echo "== $1"; cut -c1-150 "$f.err"; } >&2
    ) &
    pids+=($!)
}
control '-Verify dropped from the server' 's/ -Verify 1//'
control '-verify_return_error dropped (a certificate of another CA passes)' 's/ -verify_return_error//'
control 'server trusts another CA' 's/(openssl s_server .*-CAfile )ca\.crt/\1server.crt/'
control 'P-256 curve altered to P-384' 's/ec_paramgen_curve:P-256/ec_paramgen_curve:P-384/'
control 'RSA size altered to 3072' 's/rsa_keygen_bits:2048/rsa_keygen_bits:3072/'
control 'journal label of another snap' 's/snap\.firefox\.firefox \(enforce\)/snap.chromium.chromium (enforce)/'
control 'journal field misspelled' 's/CUSTODIO_PEER_LABEL/CUSTODIO_PEER_LABL/'
control 'journal sign selector dropped' 's/ CUSTODIO_OPERATION=sign//'
control 'journal pid not printed' 's/CUSTODIO_PEER_LABEL,CUSTODIO_PID,/CUSTODIO_PEER_LABEL,/'
control 'journal label as a prefix' 's/"CUSTODIO_PEER_LABEL=snap\.firefox\.firefox \(enforce\)"/"CUSTODIO_PEER_LABEL=snap.firefox"/'
control 'the table loses its expected column' 's/^(\| [0-9]+ \| [^|]+\|)[^|]+\|/\1/'
control 'a block of an unknown kind' '0,/^   ```text$/s//   ```yaml/'
control 'the no-certificate client line removed' '/s_client .* -CAfile ca\.crt$/d'

rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" = 0 ] || { echo "test-docs-manual-m6: a control failed" >&2; exit 1; }
echo "test-docs-manual-m6: ok (${#pids[@]} controls)"
