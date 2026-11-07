#!/usr/bin/env bash
# The swtpm part: the page's commands run under scripts/with-swtpm.sh. Sourced by scripts/test-docs-manual-m4.sh (F145); not run alone.
# shellcheck disable=SC2016,SC2013,SC2034,SC2154,SC2015 # variables come from the sourcing script; the regexes hold literal backticks; "A && B || report" is meant: the report runs when either fails
# ---------------------------------------------------------------- the swtpm part
swtpm_part() {
    local w=$tmp/sw s=$tmp/sw/state rc line out
    mkdir -p "$w" "$s/1000"
    local srk='fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt'
    t() { ( cd "$w" && "$@" > t.out 2>&1 ) || { cat "$w/t.out" >&2; echo "swtpm part: '$1 ${2:-}' failed" >&2; return 1; }; tpm2_flushcontext -t > /dev/null 2>&1 || true; }
    t tpm2_createprimary -C o -G ecc256:aes128cfb -a "$srk" -c p.ctx
    t tpm2_readpublic -c p.ctx -n p.name
    t tpm2_create -C p.ctx -g sha256 -G ecc256 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -u good.pub -r good.priv
    t tpm2_startauthsession -S trial.ctx
    t tpm2_policycommandcode -S trial.ctx -L pol.dat TPM2_CC_Duplicate
    t tpm2_flushcontext trial.ctx
    t tpm2_create -C p.ctx -g sha256 -G ecc256 -L pol.dat -a 'sensitivedataorigin|userwithauth|sign' -u dup.pub -r dup.priv
    cp "$w/good.priv" "$w/bad.priv"
    printf '\xff' | dd of="$w/bad.priv" bs=1 seek=$(($(stat -c %s "$w/bad.priv") - 1)) conv=notrunc 2> /dev/null
    cmp -s "$w/good.priv" "$w/bad.priv" && { echo "swtpm part: the altered private area equals the good one" >&2; return 1; }
    mkrec() { # ID PUB PRIV
        python3 -I - "$s/1000/$1" "$1" "$w/p.name" "$w/$2" "$w/$3" <<'PY'
import sys
out, rid, namef, pubf, privf = sys.argv[1:6]
name, pub, priv = (open(f, "rb").read() for f in (namef, pubf, privf))
prot = len(name).to_bytes(2, "big") + name + pub + priv
data = b"CUSTODIO" + bytes([1, 1]) + (1000).to_bytes(4, "big") + bytes([len(rid)]) + rid.encode() + (4).to_bytes(4, "big") + b"cert" + len(prot).to_bytes(4, "big") + prot
open(out, "wb").write(data)
PY
    }
    mkrec k-good good.pub good.priv
    mkrec k-dup dup.pub dup.priv
    mkrec k-altered good.pub bad.priv
    # the page's own helper line, with the state directory and the key id substituted
    line=$(fenced <<< "$(msection "$D_DOC" "$H20")" | grep -E '^scripts/tpm-record-check\.sh ' | head -n 1)
    [ -n "$line" ] || { echo "swtpm part: no helper line on the page" >&2; return 1; }
    run_line() { # ID [transform]: the line with the real state directory and the id; output in $w/run.out, status in rc
        local l=${line/\/var\/lib\/private\/custodio/$s}
        l=${l% *}" $1"
        [ -z "${2:-}" ] || l=$(eval "$2" <<< "$l")
        rc=0
        ( cd "$ROOT" && bash -c "$l" ) > "$w/run.out" 2>&1 || rc=$?
    }
    run_line k-good
    [ "$rc" = 0 ] || { cat "$w/run.out" >&2; echo "swtpm part: (i) the helper line failed on a key without policy" >&2; return 1; }
    grep -q 'authPolicy: empty' "$w/run.out" && grep -q 'TPM_RC_POLICY_FAIL' "$w/run.out" || { cat "$w/run.out" >&2; echo "swtpm part: (i) the output lacks the expected lines" >&2; return 1; }
    run_line k-dup
    [ "$rc" = 1 ] || { cat "$w/run.out" >&2; echo "swtpm part: (ii) a duplicable key must give exit 1, got $rc" >&2; return 1; }
    grep -q 'authPolicy: NOT empty' "$w/run.out" && grep -q '^tpm2_duplicate: succeeded' "$w/run.out" || { cat "$w/run.out" >&2; echo "swtpm part: (ii) the output does not report a non-empty authPolicy and a duplicate that succeeds" >&2; return 1; }
    run_line k-altered
    [ "$rc" = 1 ] || { cat "$w/run.out" >&2; echo "swtpm part: (iii) an altered record must give exit 1, got $rc" >&2; return 1; }
    grep -q 'tpm2_load failed' "$w/run.out" && ! grep -q 'POLICY_FAIL' "$w/run.out" || { cat "$w/run.out" >&2; echo "swtpm part: (iii) the load failure is not reported as a load failure" >&2; return 1; }
    run_line k-missing
    [ "$rc" = 2 ] || { cat "$w/run.out" >&2; echo "swtpm part: (iv) an unknown key id must give exit 2, got $rc" >&2; return 1; }
    run_line k-good 'sed "s#^\([^ ]*\) #\1 --bogus #"'
    [ "$rc" = 2 ] && grep -q '^usage:' "$w/run.out" && ! grep -q 'pass' "$w/run.out" || { cat "$w/run.out" >&2; echo "swtpm part: (iv) a wrong option must give usage and exit 2" >&2; return 1; }
    out=$( cd "$ROOT" && bash -c "${line% *}" 2>&1 ) && { echo "swtpm part: (iv) a missing key id passed" >&2; return 1; }
    grep -q '^usage:' <<< "$out" || { echo "swtpm part: (iv) a missing key id gave no usage" >&2; return 1; }
    # PCR 7: the page's own lines
    local rd ex before after eq
    rd=$(fenced <<< "$(msection "$D_DOC" "$H20")" | grep -E '^tpm2_pcrread sha256:7$' | head -n 1)
    ex=$(fenced <<< "$(msection "$D_DOC" "$H20")" | grep -E '^tpm2_pcrextend 7:' | head -n 1)
    [ -n "$rd" ] && [ -n "$ex" ] || { echo "swtpm part: no PCR lines on the page" >&2; return 1; }
    before=$(bash -c "$rd" 2>&1)
    bash -c "$ex" > /dev/null 2>&1 || { echo "swtpm part: the page's tpm2_pcrextend line failed" >&2; return 1; }
    after=$(bash -c "$rd" 2>&1)
    [ "$before" != "$after" ] || { echo "swtpm part: PCR 7 did not change after the page's pcrextend line" >&2; return 1; }
    # control: the same line on PCR 8 leaves PCR 7 as it is
    before=$after
    bash -c "${ex/ 7:/ 8:}" > /dev/null 2>&1 || { echo "swtpm part: the PCR 8 control failed to run" >&2; return 1; }
    eq=$(bash -c "$rd" 2>&1)
    [ "$before" = "$eq" ] || { echo "swtpm part: the control on PCR 8 changed PCR 7" >&2; return 1; }
    echo "swtpm part ok: helper (i)-(iv), pcrextend on PCR 7"
}
