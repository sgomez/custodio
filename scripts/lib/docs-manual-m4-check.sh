#!/usr/bin/env bash
# The checks of the M4 part of docs/manual-acceptance.md. Sourced by scripts/test-docs-manual-m4.sh (F145); not run alone.
# shellcheck disable=SC2016,SC2013,SC2034,SC2154,SC2015 # variables come from the sourcing script; the regexes hold literal backticks; "A && B || report" is meant: the report runs when either fails
D_DOC=docs/manual-acceptance.md
D_API=docs/api.md
D_AUDIT=docs/audit.md
D_INST=docs/install.md
D_LIB=crates/custodio-cli/src/lib.rs
D_LIST=crates/custodio-cli/src/list.rs
D_CNP=scripts/check-no-plaintext.sh
D_REC=scripts/tpm-record-check.sh

H20='## 20. M4 acceptance 13: hardware TPM'
H21='## 21. M4 acceptance 14: a VM without a TPM'
H22='## 22. M4 acceptance 15: a copy of the state directory'
H23='## 23. M4 result form'

count_heading() { awk -v h="$2" '/^```/ { fence = !fence } !fence && $0 == h { n++ } END { print n + 0 }' "$1"; }
msection() { awk -v h="$2" '/^```/ { fence = !fence } !fence && /^## / { on = ($0 == h) } on' "$1"; }
fenced() { awk '/^[ \t]*```/ { f = !f; next } f { sub(/^[ \t]+/, ""); print }'; }
flat() { tr '\n' ' ' | tr -s ' '; }
audit_query() { grep -E '^journalctl _SYSTEMD_UNIT=custodio.service _UID=\$\(id -u custodio\) MESSAGE_ID=[0-9a-f]+$' "$1" | head -n 1; }
tuples() { grep -oE 'busctl --system call [^ ]+ [^ ]+ [^ ]+ [^ ]+( [a-z]+)?( |$)' | sed -E 's/ +$//' | sort -u; }
# The text of a Rust string literal arm of kind_text: the quoted pieces joined, a `\` at the end of a line eating the newline and the indent.
kind_literal() { # FILE ARM
    python3 -I - "$1" "$2" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r"Kind::" + sys.argv[2] + r' => "(.*?)"\s*\.to_owned\(\)', src, re.S)
if not m:
    sys.exit("no arm " + sys.argv[2])
print(re.sub(r"\\\n\s*", "", m.group(1)))
PY
}
exit_codes() { grep -oiE '\bexit [0-9]+' | grep -oE '[0-9]+' | sort -u | tr '\n' ' '; } # the codes a text names ("exit N")
header_codes() { # FILE: the codes of the "Exit 0: ... 1: ... 2: ..." header lines, as a sorted list
    awk '/^# Exit [0-9]+:/ { on = 1 } on && /^#/ { print; next } { on = 0 }' "$1" | grep -oE '(Exit |[ .;,] ?)[0-9]+:' | grep -oE '[0-9]+' | sort -u | tr '\n' ' '
}

check() {
    local fail=0 h doc=$D_DOC
    bad() { echo "manual-m4: $*" >&2; fail=1; }
    for h in "$H20" "$H21" "$H22" "$H23"; do
        [ "$(count_heading "$doc" "$h")" -eq 1 ] || { bad "the heading '$h' must appear exactly once"; return 1; }
    done
    local p20 p21 p22 p23 part m
    p20=$(msection "$doc" "$H20"); p21=$(msection "$doc" "$H21"); p22=$(msection "$doc" "$H22"); p23=$(msection "$doc" "$H23")
    need() { grep -Eq -- "$1" <<< "$(flat <<< "$part")" || bad "$m: $2"; }
    needf() { fenced <<< "$part" | grep -Eq -- "$1" || bad "$m: $2"; } # in a fenced block
    local paths
    paths=$(grep -oE '/var/lib/[A-Za-z0-9_/.-]+' "$D_INST" | sort -u)
    local pt

    # ---- Acceptance 13 (section 20)
    m=20; part=$p20
    needf '^custodio import --id rsa2048 rsa2048\.p12$' "no import of the RSA 2048 key"
    needf '^custodio import --id p256 p256\.p12$' "no import of the P-256 key"
    needf '^custodio list$' "no custodio list"
    need 'kind: tpm' "no expected kind tpm"
    local tpmtext
    tpmtext=$(kind_literal "$D_LIB" Tpm) || bad "$m: no Tpm arm in kind_text"
    fenced <<< "$part" | grep -qxF -- "$tpmtext" || bad "$m: the storage line of a TPM key is not the one of kind_text"
    local hl
    hl=$(fenced <<< "$part" | grep -E '^scripts/tpm-record-check\.sh ' || true)
    [ "$(wc -l <<< "$hl")" -eq 2 ] || bad "$m: expected two helper lines"
    for pt in rsa2048 p256; do
        grep -qxF "scripts/tpm-record-check.sh /var/lib/private/custodio $pt" <<< "$hl" || bad "$m: no helper line for $pt with the state directory /var/lib/private/custodio"
    done
    grep -qE '^# Usage: scripts/tpm-record-check\.sh STATE_DIR KEY_ID ' "$D_REC" || bad "$m: the header of the helper has another usage"
    [ "$(grep -c . <<< "$hl")" -eq 0 ] || while read -r _ a b c; do [ -n "$a" ] && [ -n "$b" ] && [ -z "$c" ] || bad "$m: a helper line without exactly two arguments"; done <<< "$hl"
    need 'authPolicy: empty' "the expected line authPolicy: empty is missing"
    need 'tpm2_duplicate: failed with TPM_RC_POLICY_FAIL' "the expected duplicate line is missing"
    grep -qF 'authPolicy: empty' "$D_REC" && grep -qF 'tpm2_duplicate: failed with TPM_RC_POLICY_FAIL' "$D_REC" || bad "$m: the helper does not print the lines the page expects"
    local pc hc
    pc=$(grep -oiE 'exit [0-9]+' <<< "$(flat <<< "$part")" | grep -oE '[0-9]+' | sort -u | tr '\n' ' ')
    hc=$(header_codes "$D_REC")
    [ "$pc" = "$hc" ] || bad "$m: the exit codes of the page ($pc) are not those of the header of the helper ($hc)"
    need 'Any other error' "no sentence that any other error is a failed step"
    need 'tpm2_readpublic' "no tpm2_readpublic"
    need 'TPM2_CC_Duplicate' "no policy session on Duplicate"
    # the events, in this order
    local l_re l_up l_db l_pc
    l_re=$(grep -n 'Event 1, reboot' <<< "$part" | head -n 1 | cut -d: -f1 || true)
    l_up=$(grep -n 'Event 2, upgrade' <<< "$part" | head -n 1 | cut -d: -f1 || true)
    l_db=$(grep -n 'Event 3, a `fwupd` `dbx` update' <<< "$part" | head -n 1 | cut -d: -f1 || true)
    l_pc=$(grep -n 'tpm2_pcrextend 7:' <<< "$part" | head -n 1 | cut -d: -f1 || true)
    if [ -z "$l_re" ] || [ -z "$l_up" ] || [ -z "$l_db" ] || [ -z "$l_pc" ]; then bad "$m: an event or the substitute is missing (reboot '$l_re', upgrade '$l_up', dbx '$l_db', substitute '$l_pc')"
    else { [ "$l_re" -lt "$l_up" ] && [ "$l_up" -lt "$l_db" ] && [ "$l_db" -lt "$l_pc" ]; } || bad "$m: the events must come in the order reboot ($l_re), upgrade ($l_up), dbx ($l_db), substitute ($l_pc)"; fi
    needf '^sudo systemctl reboot$|^tpm2_pcrread sha256:7$' "no PCR 7 read"
    needf '^tpm2_pcrread sha256:7$' "PCR 7 is not read with tpm2_pcrread sha256:7"
    needf '^tpm2_pcrextend 7:sha256=[0-9a-f]{64}$' "no tpm2_pcrextend on PCR 7 (substitute)"
    need 'sudo systemctl reboot' "no reboot command"
    for pt in refresh get-updates update; do needf "^fwupdmgr $pt\$" "no fwupdmgr $pt"; done
    need 'proved nothing' "no sentence that an event which leaves PCR 7 equal proved nothing"
    need 'docs/install\.md' "no pointer to docs/install.md for the upgrade"
    grep -qx '## Upgrading' "$D_INST" || bad "$m: docs/install.md has no heading '## Upgrading' to point at"
    need 'Upgrading' "the upgrade does not name the Upgrading section of docs/install.md"
    local ref refs=0 lo=0 ff=0
    while IFS= read -r ref; do
        [ -n "$ref" ] || continue
        refs=$((refs + 1))
        [ "$(count_heading "$doc" "$ref")" -eq 1 ] || bad "$m: the referenced heading '$ref' is not on the page exactly once"
        [[ $ref == *LibreOffice* ]] && lo=1
        [[ $ref == *fedora44* ]] && ff=1
    done < <(grep -oE '`## [0-9]+\. [^`]+`' <<< "$part" | sed 's/^`//;s/`$//')
    [ "$lo" -eq 1 ] || bad "$m: no referenced LibreOffice heading"
    [ "$ff" -eq 1 ] || bad "$m: no referenced Firefox heading (fedora44)"
    local ev ck
    for ev in reboot upgrade 'dbx or substitute'; do
        for ck in 'PCR 7' '`custodio list`' 'Firefox' 'LibreOffice'; do
            grep -qF -- "| $ev | $ck" <<< "$part" || bad "$m: no table row for the event '$ev' and the check '$ck'"
        done
    done

    # ---- Acceptance 14 (section 21)
    m=21; part=$p21
    local host
    host=$(kind_literal "$D_LIB" EncryptedHost) || bad "$m: no EncryptedHost arm in kind_text"
    fenced <<< "$part" | grep -qxF -- "$host" || bad "$m: the notice quoted on the page is not the text of kind_text (EncryptedHost)"
    [ -n "$host" ] && [[ $host == *"weaker"* && $host == *"no TPM"* && $host == *"host key"* ]] || bad "$m: kind_text no longer says weaker, no TPM, host key"
    needf '^custodio import --id rsa2048 rsa2048\.p12$' "no import"
    needf '^custodio list$' "no custodio list"
    grep -qF 'writeln!(out, "  kind: {}", escape(kind.wire()))' "$D_LIST" || bad "$m: list.rs prints the kind in another form than the page expects"
    ! grep -qi 'weaker' "$D_LIST" || bad "$m: list.rs now prints a weaker sentence, the page must be revised"
    local kl
    kl=$(fenced <<< "$part" | grep -E '^kind:' || true)
    [ "$kl" = 'kind: encrypted-host' ] || bad "$m: the custodio list expectation must be exactly 'kind: encrypted-host', not '$kl'"
    need 'no sentence about a weaker key' "no statement that custodio list prints no weaker sentence"
    need 'approver decides' "no sentence that the approver decides on acceptance 14"
    need 'ls /dev/tpm' "no check that the VM has no TPM"
    need 'systemctl reboot' "no reboot step"
    need 'After the reboot' "no step after the reboot"
    need 'Firefox' "no Firefox signing step"
    need 'LibreOffice' "no LibreOffice signing step"
    while IFS= read -r ref; do
        [ "$(count_heading "$doc" "$ref")" -eq 1 ] || bad "$m: the referenced heading '$ref' is not on the page exactly once"
    done < <(grep -oE '`## [0-9]+\. [^`]+`' <<< "$part" | sed 's/^`//;s/`$//')

    # ---- Acceptance 15 (section 22)
    m=22; part=$p22
    local cl
    cl=$(fenced <<< "$part" | grep -E 'check-no-plaintext' || true)
    [ -n "$cl" ] || bad "$m: no check-no-plaintext command"
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        grep -qE '^(printf .%s\\n. "\$pw" \| )?scripts/check-no-plaintext\.sh "\$copy" [A-Za-z0-9_.-]+\.p12$' <<< "$c" || bad "$m: '$c' is not 'scripts/check-no-plaintext.sh \"\$copy\" <p12>' with the password on stdin"
    done <<< "$cl"
    local usage
    usage=$(grep -E '^# usage: ' "$D_CNP" | sed 's/^# usage: //')
    [ "$usage" = 'scripts/check-no-plaintext.sh STATE_DIR P12 < password' ] || bad "$m: the usage in the header of check-no-plaintext.sh is '$usage'"
    need 'usage of the check is `scripts/check-no-plaintext\.sh STATE_DIR P12 < password`' "the usage quoted is not the one of the header"
    pc=$(grep -oiE 'exit [0-9]+' <<< "$(flat <<< "$part")" | grep -oE '[0-9]+' | sort -u | tr '\n' ' ')
    hc=$(header_codes "$D_CNP")
    for c in $pc; do grep -qw "$c" <<< "$hc" || bad "$m: the page names the exit code $c, the header of the check has ($hc)"; done
    for c in 0 1 3; do grep -qw "$c" <<< "$pc" || bad "$m: the page does not name the exit code $c"; done
    need 'never a pass' "no sentence that exit 3 is never a pass"
    needf '^cp -a /var/lib/private/custodio/\. "\$copy"/$' "no copy of the whole state directory preserving everything"
    needf '^rm -rf "\$copy"$' "the copy is not removed"
    needf '^sudo -s$' "not run as root"
    need 'hardware TPM' "the hardware TPM machine is not covered"
    need 'VM without a TPM' "the VM without a TPM is not covered"
    need 'not reach a log' "no sentence that the copy and the password stay out of logs"
    grep -qE 'read -rs' <<< "$part" || bad "$m: the password is not read without echo"

    # ---- state directory paths of the part against docs/install.md
    for pt in $(grep -oE '/var/lib/[A-Za-z0-9_/.-]+' <<< "$p20
$p21
$p22" | sed 's#/\.$##; s#/*$##' | sort -u); do
        grep -qxF -- "$pt" <<< "$paths" || [ "$pt" = /var/lib ] || bad "the path '$pt' is not one docs/install.md names"
    done
    grep -qF '/var/lib/private/custodio' "$D_INST" || bad "docs/install.md does not name /var/lib/private/custodio"

    # ---- scripts the part names
    local all_m4 s n=0
    all_m4=$(printf '%s\n%s\n%s\n%s\n' "$p20" "$p21" "$p22" "$p23")
    for s in $(grep -oE 'scripts/[A-Za-z0-9_./-]+\.sh' <<< "$all_m4" | sort -u); do
        n=$((n + 1))
        [ -x "$s" ] || bad "the script '$s' named by the page does not exist or is not executable"
    done
    [ "$n" -ge 3 ] || bad "fewer than 3 scripts named (found $n)"

    # ---- commands and names against docs/api.md and docs/audit.md (zero is a stated result)
    local nb nj t a f q
    nb=$(fenced <<< "$all_m4" | grep -c 'busctl' || true)
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        fenced < "$D_API" | tuples | grep -qxF -- "$t" || bad "the command '$t' is not an example of docs/api.md"
    done < <(fenced <<< "$all_m4" | grep busctl | tuples)
    if fenced <<< "$all_m4" | grep busctl | grep -vq -- '--system call'; then bad "a busctl command of the M4 part is not 'busctl --system call'"; fi
    for a in $(grep -oE 'com\.rfirma\.custodio\.[a-z-]+' <<< "$all_m4" | sort -u); do
        grep -qF -- "$a" "$D_API" || bad "the action id '$a' is not in docs/api.md"
    done
    for a in $(grep -oE 'com\.rfirma\.Custodio1\.Error\.[A-Za-z0-9]+' <<< "$all_m4" | sort -u); do
        grep -qF -- "$a\`" "$D_API" || bad "the error name '$a' is not in docs/api.md"
    done
    nj=$(fenced <<< "$all_m4" | grep -c 'journalctl' || true)
    q=$(audit_query "$D_AUDIT"); [ -n "$q" ] || bad "no base query in $D_AUDIT"
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        t=$(sed -E 's/ CUSTODIO_[A-Z_]+=[A-Za-z0-9_-]*//g; s/ \\$//' <<< "$t")
        [ "$t" = "$q" ] || bad "the journal query '$t' is not the base query of docs/audit.md"
    done < <(fenced <<< "$all_m4" | grep journalctl)
    for f in $(grep -oE 'CUSTODIO_[A-Z_]+' <<< "$all_m4" | sort -u); do
        grep -qE -- "(^|[^A-Z_])$f([^A-Z_]|\$)" "$D_AUDIT" || bad "the journal field '$f' is not in docs/audit.md"
    done
    for f in $(grep -oE 'CUSTODIO_STORAGE_KIND=[A-Za-z-]+' <<< "$all_m4" | sed 's/.*=//' | sort -u); do
        grep -qE -- "CUSTODIO_STORAGE_KIND.*\`$f\`" "$D_AUDIT" || bad "the kind '$f' is not one of docs/audit.md"
    done
    CHECK_COUNTS="busctl commands: $nb, journalctl queries: $nj"

    # ---- Result form (section 23)
    m=23; part=$p23
    for a in 13 14 15; do grep -qF "| M4 $a " <<< "$part" || bad "$m: no row for acceptance $a"; done
    return $fail
}
CHECK_COUNTS=''
