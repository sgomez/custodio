#!/usr/bin/env bash
# Test of section 24 of docs/manual-acceptance.md (F165, M5 acceptance 17: reading the PCR mask on Debian 13). It RUNS what the
# page says: the has-tpm2 command (format and library names only: the dev container reports `partial`, so no "full" verdict is
# checked, the page's quote is compared with the real format), the page's `varlinkctl call` against a stub unix socket that
# records the request (compared as JSON with the request vector of the service's unit test, name k and data foo, no test hook) and
# answers with a real credential, the blob extraction and the reader (F157) on it, the reader on the fixtures of e2e/vm/mkcreds.sh
# (made under swtpm) judged by the page's table, and the hand-read equivalent against the reader. Only section 24 is read.
# Negative controls: a copy of the page with one claim broken must differ from the real page and must fail; they run in parallel.
# Cost: ~1.5 s wall measured (19 controls in parallel, one swtpm session for the fixtures). A missing tool fails naming it, never skips.
# Usage: scripts/test-docs-manual-m5.sh   (CONTROL_WHY=1 also prints the failures of each broken page)
# SC2016: the sed expressions hold literal backticks and dollars.
# shellcheck disable=SC2016
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PAGE=docs/manual-acceptance.md
CHECK=scripts/lib/docs-manual-m5-check.py

for tool in python3 varlinkctl systemd-analyze systemd-creds swtpm unshare tpm2_startup; do
    command -v "$tool" > /dev/null 2>&1 || { echo "test-docs-manual-m5: $tool is not installed" >&2; exit 127; }
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# the recipe lists this script (the recipe itself runs at the checkpoint)
grep -qx '    scripts/test-docs-manual-m5.sh' justfile || { echo "test-docs-manual-m5: just test-scripts does not list this script" >&2; exit 1; }

mkdir "$tmp/c"
e2e/vm/mkcreds.sh "$tmp/c" || { echo "test-docs-manual-m5: mkcreds.sh failed" >&2; exit 1; }
check() { python3 -I "$CHECK" "$1" "$tmp/c" "$ROOT"; }

check "$PAGE" || { echo "test-docs-manual-m5: the page fails its checks" >&2; exit 1; }
echo "test-docs-manual-m5: the page passes"

# ---- negative controls: each is a sed over section 24 only
pids=()
control() { # label sed-expression
    (
        f=$tmp/page.$BASHPID
        sed -E -e "/^## 24\\./,\$ { $2 }" "$PAGE" > "$f"
        if cmp -s "$PAGE" "$f"; then echo "control '$1': the copy equals the page, the control is void" >&2; exit 1; fi
        if python3 -I "$CHECK" "$f" "$tmp/c" "$ROOT" 2> "$f.err"; then echo "control '$1': a broken page passed" >&2; exit 1; fi
        # CONTROL_WHY=1: show what each broken page failed on
        [ -z "${CONTROL_WHY:-}" ] || { echo "== $1"; cut -c1-150 "$f.err"; } >&2
    ) &
    pids+=($!)
}
control 'has-tpm2 step removed' 's/systemd-analyze has-tpm2; echo/true; echo/'
control 'libtss2-rc dropped from the quote' '/^ +\+libtss2-rc\.so\.0$/d'
control 'libtss2-rc marked missing' 's/^( +)\+libtss2-rc\.so\.0$/\1-libtss2-rc.so.0/'
control 'partial accepted (no stop rule)' 's/first line is not `yes`/first line may be `yes`/'
control 'quote says partial' '0,/^ +yes$/ s/^ +yes$/   partial/'
control 'withKey added' 's/\\"scope\\":\\"user\\"/\\"scope\\":\\"user\\",\\"withKey\\":\\"host\\"/'
control 'scope system' 's/\\"scope\\":\\"user\\"/\\"scope\\":\\"system\\"/'
control 'socket path altered' 's#unix:/run/systemd/io\.systemd\.Credentials#unix:/run/systemd/io.systemd.Credential#'
control 'method altered' 's/io\.systemd\.Credentials\.Encrypt "/io.systemd.Credentials.Decrypt "/'
control 'reader path misspelled' 's#e2e/vm/credread\.py pcr\.cred#e2e/vm/credreed.py pcr.cred#'
control 'confirmed and refuted swapped' 's/\| PCR 7 confirmed \|/| PCR 7 TMP |/; s/\| PCR 7 refuted \|/| PCR 7 confirmed |/; s/\| PCR 7 TMP \|/| PCR 7 refuted |/'
control '0x80 called invalid' 's/^( *\| `host\+tpm2-scoped mask 0x80` \| ).*$/\1invalid reading, repeat |/'
control 'other mask row removed' '/with any other value/d'
control 'not TPM-bound rule removed' '/^ *\| anything else /d'
control 'not TPM-bound called refuted' 's/^( *\| anything else .* \| ).*$/\1PCR 7 refuted |/'
control 'hand read wrong offset' 's/struct\.unpack_from\("<Q", d, 48\)/struct.unpack_from("<Q", d, 44)/'
control 'blob extraction broken' 's/"blob":/"blub":/'
control 'hardware or virtual removed' 's/whether the TPM is hardware or virtual, //'
control 'unverified mark removed' 's/unverified/verified/'

rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" = 0 ] || { echo "test-docs-manual-m5: a control failed" >&2; exit 1; }
echo "test-docs-manual-m5: ok (${#pids[@]} controls)"
