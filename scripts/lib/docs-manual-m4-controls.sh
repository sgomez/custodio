#!/usr/bin/env bash
# The negative controls of the M4 part. Sourced by scripts/test-docs-manual-m4.sh (F145); not run alone.
# shellcheck disable=SC2016,SC2013,SC2034,SC2154,SC2015,SC2030,SC2031 # variables come from the sourcing script; the regexes hold literal backticks; "A && B || report" is meant: the report runs when either fails
# ---------------------------------------------------------------- the controls
fixture() { if cmp -s "$2" "$fx"; then echo "control '$1': the fixture equals the real file, the control is void" >&2; exit 1; fi; }
fails() { if check 2> /dev/null; then echo "control '$1': a broken file passed" >&2; exit 1; fi; }
passes() { check 2> "$fx.err" || { cat "$fx.err" >&2; echo "control '$1': a good file was refused" >&2; exit 1; }; }
reset() { D_DOC=docs/manual-acceptance.md D_API=docs/api.md D_AUDIT=docs/audit.md D_INST=docs/install.md D_LIB=crates/custodio-cli/src/lib.rs D_LIST=crates/custodio-cli/src/list.rs D_CNP=scripts/check-no-plaintext.sh D_REC=scripts/tpm-record-check.sh; }
page() { sed -E -e "$2" docs/manual-acceptance.md > "$fx"; fixture "$1" docs/manual-acceptance.md; D_DOC=$fx; fails "$1"; reset; }
in20() { page "$1" "/^## 20\\./,/^## 21\\./ { $2 }"; }
in21() { page "$1" "/^## 21\\./,/^## 22\\./ { $2 }"; }
in22() { page "$1" "/^## 22\\./,/^## 23\\./ { $2 }"; }
in23() { page "$1" "/^## 23\\./,\$ { $2 }"; }
file() { # NAME VARIABLE REAL SED: a fixture of a file the page is checked against
    sed -E -e "$4" "$3" > "$fx"; fixture "$1" "$3"; printf -v "$2" '%s' "$fx"; fails "$1"; reset
}

# every control is independent: it runs in its own subshell with its own fixture file ($fx), a few at a time
bg() {
    while [ "$(jobs -rp | wc -l)" -ge "$(nproc)" ]; do wait -n || true; done
    ( fx=$tmp/fix.$BASHPID; "$@" ) &
    pids+=($!)
}
pids=()
# section finder
bg page 'heading 20 duplicated' 's/^## 21\. M4 acceptance 14: a VM without a TPM$/## 20. M4 acceptance 13: hardware TPM/'
bg page 'heading 21 renamed' 's/^## 21\. M4 acceptance 14:/## 21. M4 acceptance 14 (renamed):/'
bg page 'heading 23 renamed' 's/^## 23\. M4 result form/## 23. M4 results/'
bg page 'an M3 section holds the M4 item only' '/^## 18\./,/^## 19\./ { s/$/\nAcceptance 13 ok/ }; /^## 20\./,/^## 21\./ { s/Event 1, reboot/Event 1, restart/ }'

# acceptance 13
bg in20 'RSA import removed' 's/^( *)custodio import --id rsa2048 rsa2048\.p12$/\1true/'
bg in20 'P-256 import removed' 's/^( *)custodio import --id p256 p256\.p12$/\1true/'
bg in20 'list removed' 's/^( *)custodio list$/\1true/'
bg in20 'kind tpm removed' 's/kind: tpm/kind: x/g'
bg in20 'storage line altered' 's/^( *)Storage: tpm\. The key is in the TPM and cannot be copied out of it\./\1Storage: tpm. The key is in the TPM./'
bg in20 'helper line removed' 's#^( *)scripts/tpm-record-check\.sh /var/lib/private/custodio p256$#\1true#'
bg in20 'helper state directory altered' 's#tpm-record-check\.sh /var/lib/private/custodio rsa2048#tpm-record-check.sh /var/lib/private/custodi0 rsa2048#'
bg in20 'helper path altered' 's#scripts/tpm-record-check\.sh#scripts/tpm-record-chec.sh#g'
bg in20 'helper third argument' 's#(tpm-record-check\.sh /var/lib/private/custodio rsa2048)$#\1 hunter2#'
bg in20 'authPolicy line removed' 's/authPolicy: empty/authPolicy: fine/'
bg in20 'duplicate line removed' 's/tpm2_duplicate: failed with TPM_RC_POLICY_FAIL/tpm2_duplicate: failed/'
bg in20 'exit code changed' 's/exit 2 means/exit 5 means/'
bg in20 'exit code dropped' 's/exit 0/exit ok/g'
bg in20 'any other error removed' 's/Any other error/Some error/'
bg in20 'order reboot/upgrade swapped' 's/Event 1, reboot/@@A/; s/Event 2, upgrade/Event 1, reboot/; s/@@A/Event 2, upgrade/'
bg in20 'order upgrade/dbx swapped' 's/Event 2, upgrade/@@A/; s/Event 3, a `fwupd` `dbx` update/Event 2, upgrade/; s/@@A/Event 3, a `fwupd` `dbx` update/'
bg in20 'reboot event removed' 's/Event 1, reboot/Event 1, power cycle/'
bg in20 'upgrade event removed' 's/Event 2, upgrade/Event 2, patch/'
bg in20 'dbx event removed' 's/Event 3, a `fwupd` `dbx` update/Event 3, a firmware update/'
bg in20 'substitute removed' 's/^( *)tpm2_pcrextend 7:/\1tpm2_pcrextend 8:/'
bg in20 'substitute hex altered' 's/^( *)(tpm2_pcrextend 7:sha256=)[0-9a-f]+$/\1\2zz/'
bg in20 'PCR 7 read removed' 's/^( *)tpm2_pcrread sha256:7$/\1tpm2_pcrread sha256:8/'
bg in20 'fwupdmgr update removed' 's/^( *)fwupdmgr update$/\1true/'
bg in20 'fwupdmgr get-updates removed' 's/^( *)fwupdmgr get-updates$/\1true/'
bg in20 'reboot command removed' 's/sudo systemctl reboot/the reboot/'
bg in20 'proved nothing removed' 's/proved nothing/was fine/'
bg in20 'install.md pointer removed' 's#docs/install\.md#the install page#g'
bg in20 'Upgrading section not named' 's/"Upgrading"/"Installing"/'
bg in20 'Firefox pointer renamed' 's/`## 11\. fedora44, SELinux enforcing \(acceptance 12\)`/`## 11. fedora44`/'
bg in20 'LibreOffice pointer renamed' 's/`## 6\. LibreOffice run`/`## 6. LibreOffice`/'
for ev in 'reboot' 'upgrade' 'dbx or substitute'; do
    for ck in 'PCR 7' '`custodio list`' 'Firefox' 'LibreOffice'; do
        bg in20 "table row $ev/$ck removed" "s/^\\| $ev \\| $ck/| x | $ck/"
    done
done
bg file 'install.md without Upgrading' D_INST docs/install.md 's/^## Upgrading$/## Upgrades/'
bg file 'install.md without the state directory' D_INST docs/install.md 's#/var/lib/private/custodio#/var/lib/private/x#g'
bg file 'helper prints other lines' D_REC scripts/tpm-record-check.sh 's/authPolicy: empty/authPolicy ok/'
bg file 'helper has another usage' D_REC scripts/tpm-record-check.sh 's/^# Usage: scripts\/tpm-record-check\.sh STATE_DIR KEY_ID/# Usage: scripts\/tpm-record-check.sh KEY_ID STATE_DIR/'
bg file 'helper header with another exit code' D_REC scripts/tpm-record-check.sh 's/^# 2: bad usage/# 7: bad usage/'
bg file 'kind_text of tpm altered' D_LIB crates/custodio-cli/src/lib.rs 's/cannot be copied out of it/can be copied/'

# acceptance 14
bg in21 'notice altered' 's/Root, and anyone with a copy of \/var\/lib, can use it\./Root can use it./'
bg in21 'notice: first piece altered' 's/so the key is a file encrypted with the host key/so the key is a file/'
bg in21 'notice removed' 's/^( *)Storage: encrypted-host\..*$/\1Storage: encrypted-host./'
bg file 'code notice: first piece altered' D_LIB crates/custodio-cli/src/lib.rs 's/this machine has no TPM, so the key is \\$/this machine has no TPM, so the key is  \\/; s/^a file encrypted with the host key\./a file encrypted with the machine key./'
bg file 'code notice: second piece altered' D_LIB crates/custodio-cli/src/lib.rs 's/Root, and anyone with a copy of \/var\/lib, can use it\./Anyone can use it./'
bg in21 'note altered' 's/^( *)note: This key is weaker/\1note: This key is fine/'
bg in21 'note removed' '/^ *note: /d'
bg in21 'list kind altered' 's/^( *)kind: encrypted-host$/\1kind: encrypted-tpm/'
bg file 'list.rs prints another note form' D_LIST crates/custodio-cli/src/list.rs 's/"  note: \{note\}"/"  remark: {note}"/'
bg file 'list.rs prints another form' D_LIST crates/custodio-cli/src/list.rs 's/"  kind: \{\}"/"  storage: {}"/'
bg in21 'reboot removed' 's/systemctl reboot/the reboot/g'
bg in21 'after the reboot removed' 's/After the reboot/Later/g'
bg in21 'Firefox removed' 's/Firefox/the browser/g; s/^\| 4 \| .*$/| 4 | x |/'
bg in21 'LibreOffice removed' 's/LibreOffice/the office suite/g'
bg in21 'no-TPM check removed' 's#ls /dev/tpm#ls /dev/null#'
bg in21 'import removed' 's/^( *)custodio import --id rsa2048 rsa2048\.p12$/\1true/'

# acceptance 15
bg in22 'argument order swapped' 's#scripts/check-no-plaintext\.sh "\$copy" rsa2048\.p12#scripts/check-no-plaintext.sh rsa2048.p12 "$copy"#'
bg in22 'password as an argument' 's#scripts/check-no-plaintext\.sh "\$copy" rsa2048\.p12$#scripts/check-no-plaintext.sh "$copy" rsa2048.p12 "$pw"#'
bg in22 'password as an argument (no pipe)' 's#^printf .*scripts/check-no-plaintext\.sh "\$copy" p256\.p12$#scripts/check-no-plaintext.sh "$copy" p256.p12 test-password#'
bg in22 'usage altered' 's#STATE_DIR P12 < password`#P12 STATE_DIR < password`#'
bg in22 'exit 3 changed' 's/Exit 3 means/Exit 4 means/'
bg in22 'exit 1 changed' 's/Exit 1 means/Exit 9 means/'
bg in22 'exit 0 changed' 's/exit 0 for each/exit 8 for each/; s/exit 0$/exit 8/'
bg in22 'never a pass removed' 's/never a pass/fine/'
bg in22 'copy path altered' 's#cp -a /var/lib/private/custodio/\.#cp -a /var/lib/private/custodi0/.#'
bg in22 'copy without -a' 's#^cp -a #cp -r #'
bg in22 'copy not removed' 's#^rm -rf "\$copy"$#true#'
bg in22 'not root' 's#^sudo -s$#true#'
bg in22 'hardware machine dropped' 's/hardware TPM/first/g'
bg in22 'VM dropped' 's/VM without a TPM/second/g'
bg in22 'log sentence dropped' 's/not reach a log/be kept/'
bg in22 'password echoed' 's/read -rs/read -r/'
bg in22 'script path altered' 's#scripts/check-no-plaintext\.sh#scripts/check-no-plaintex.sh#g'
bg file 'check usage altered' D_CNP scripts/check-no-plaintext.sh 's/^# usage: scripts\/check-no-plaintext\.sh STATE_DIR P12 < password/# usage: scripts\/check-no-plaintext.sh P12 STATE_DIR < password/'
bg file 'check header with an extra code' D_CNP scripts/check-no-plaintext.sh 's/^# input\. 3: a derivation failed/# input. 7: a derivation failed/'
bg in22 'unknown path on the page' 's#/var/lib/private/custodio#/var/lib/private/custodio2#g'

# result form
for n in 13 14 15; do bg in23 "form row $n removed" "s/^\\| M4 $n /| X $n /"; done

# api / audit: the part holds none of these, and says so; a fixture that adds one must be judged (one sequence, in one subshell)
api_audit_controls() {
passes 'no busctl or journal in the real part'
cp docs/manual-acceptance.md "$tmp/base"
addfence() { # NAME LINE: LINE added in a fenced block at the end of section 20
    awk -v add="$2" '/^## 21\./ && !d { print "```sh\n" add "\n```\n"; d = 1 } { print }' "$tmp/base" > "$fx"; fixture "$1" "$tmp/base"; D_DOC=$fx
}
BC='busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys'
addfence 'busctl ok' "$BC"; passes 'a busctl command of docs/api.md'; reset
addfence 'busctl method altered' "${BC/ListKeys/ListKey}"; fails 'busctl method altered'; reset
addfence 'busctl signature altered' 'busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 DeleteKey zz x'; fails 'busctl signature altered'; reset
addfence 'busctl not call' "${BC/call/introspect}"; fails 'busctl introspect'; reset
awk '/^## 21\./ && !d { print "The dialog shows com.rfirma.custodio.sign.\n"; d = 1 } { print }' "$tmp/base" > "$fx"; fixture 'action ok' "$tmp/base"; D_DOC=$fx; passes 'a polkit action id of docs/api.md'; reset
awk '/^## 21\./ && !d { print "The dialog shows com.rfirma.custodio.signs.\n"; d = 1 } { print }' "$tmp/base" > "$fx"; fixture 'action altered' "$tmp/base"; D_DOC=$fx; fails 'action id altered'; reset
awk '/^## 21\./ && !d { print "The error is com.rfirma.Custodio1.Error.NoSuchKey.\n"; d = 1 } { print }' "$tmp/base" > "$fx"; fixture 'error ok' "$tmp/base"; D_DOC=$fx; passes 'an error name of docs/api.md'; reset
awk '/^## 21\./ && !d { print "The error is com.rfirma.Custodio1.Error.NoKey.\n"; d = 1 } { print }' "$tmp/base" > "$fx"; fixture 'error altered' "$tmp/base"; D_DOC=$fx; fails 'error name invented'; reset
JQ=$(audit_query docs/audit.md)
addfence 'journal ok' "$JQ CUSTODIO_STORAGE_KIND=encrypted-host CUSTODIO_OPERATION=import"; passes 'the base journal query of docs/audit.md'; reset
addfence 'journal query changed' "${JQ/MESSAGE_ID=/MESSAGE_ID=0}"; fails 'journal query changed'; reset
addfence 'journal field invented' "$JQ CUSTODIO_BOGUS=1"; fails 'journal field invented'; reset
addfence 'journal kind invented' "$JQ CUSTODIO_STORAGE_KIND=encrypted-cloud"; fails 'journal kind invented'; reset
sed -E 's/Error\.NoSuchKey`/Error.NoSuchKeyX`/' docs/api.md > "$fx"; fixture 'api lacks the error name' docs/api.md
awk '/^## 21\./ && !d { print "The error is com.rfirma.Custodio1.Error.NoSuchKey.\n"; d = 1 } { print }' "$tmp/base" > "$fx.2"; D_DOC=$fx.2 D_API=$fx; fails 'api without the error name'; reset
sed -E 's/CUSTODIO_STORAGE_KIND.*`encrypted-host`/CUSTODIO_STORAGE_KIND x/' docs/audit.md > "$fx"; fixture 'audit lacks the kind' docs/audit.md
addfence 'journal kind ok' "$JQ CUSTODIO_STORAGE_KIND=encrypted-host"; D_AUDIT=$fx; fails 'audit without the kind'; reset
}
bg api_audit_controls
ctl_rc=0
for pid in "${pids[@]}"; do wait "$pid" || ctl_rc=1; done
[ "$ctl_rc" = 0 ] || { echo "test-docs-manual-m4: a control failed" >&2; exit 1; }
echo "test-docs-manual-m4: controls ok"

rc=0
wait "$swtpm_job" || rc=$?
if [ "$rc" != 0 ]; then cat "$tmp/swtpm.out" >&2; echo "test-docs-manual-m4: the swtpm part failed (exit $rc)" >&2; exit 1; fi
tail -n 1 "$tmp/swtpm.out"
echo "test-docs-manual-m4: ok"

