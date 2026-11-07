#!/usr/bin/env bash
# Test of the M3 part of docs/manual-acceptance.md (F99): sections 16 to 19 hold the items of M3 acceptance 14, 15 and 16, their
# busctl commands equal those of docs/api.md, their journal text equals docs/audit.md, and the test flatpak manifest parses and
# grants only the talk permission. Every kind of check has a negative control: a fixture copy with the claim broken must differ
# from the real file and must fail. The M1/M2 sections are never searched for an M3 item (only for the things M3 points to).
# Usage: scripts/test-docs-manual-m3.sh   (DOC, API, AUDIT, MANIFEST override the real files; CHECK_ONLY=1 only
# checks the real files).
# SC2016: the regexes and sed expressions hold literal backticks and dollars. SC2013: the words looped over (action ids, error names,
# field names) contain no spaces.
# shellcheck disable=SC2016,SC2013
set -euo pipefail
cd "$(dirname "$0")/.."
DOC=${DOC:-docs/manual-acceptance.md}
API=${API:-docs/api.md}
AUDIT=${AUDIT:-docs/audit.md}
MANIFEST=${MANIFEST:-packaging/flatpak/com.rfirma.CustodioTest.json}

H16='## 16. M3 acceptance 14: the client API by hand'
H17='## 17. M3 acceptance 15: a flatpak calls Custodio'
H18='## 18. M3 acceptance 16: Firefox, LibreOffice and a second account'
H19='## 19. M3 result form'

count_heading() { # FILE EXACT_HEADING: how many headings (outside fences) equal the text
    awk -v h="$2" '/^```/ { fence = !fence } !fence && $0 == h { n++ } END { print n + 0 }' "$1"
}
msection() { # FILE EXACT_HEADING: that heading up to the next "## " heading, fences respected, nothing else
    awk -v h="$2" '
        /^```/ { fence = !fence }
        !fence && /^## / { on = ($0 == h) }
        on' "$1"
}
fenced() { awk '/^[ \t]*```/ { f = !f; next } f { sub(/^[ \t]+/, ""); print }'; } # the lines inside code fences (indent removed), from stdin
# Pipelines into grep use >/dev/null, not -q: an early exit SIGPIPEs the writer and pipefail fails the check.
# The base query of docs/audit.md, as docs/audit.md writes it.
audit_query() { grep -E '^journalctl _SYSTEMD_UNIT=custodio.service _UID=\$\(id -u custodio\) MESSAGE_ID=[0-9a-f]+$' "$1" | head -n 1; }
# The part of a busctl command that docs/api.md fixes: destination, path, interface, method and the signature.
tuples() { grep -oE 'busctl --system call [^ ]+ [^ ]+ [^ ]+ [^ ]+( [a-z]+)?( |$)' | sed -E 's/ +$//' | sort -u; }
# The error names of the "Examples" fences of docs/api.md.
example_errors() { awk '/^## Examples/ { on = 1 } on && /^```console/' "$1" | grep -oE 'error=[A-Za-z0-9]+' | sed 's/^error=//' | sort -u; }
manifest_info() { # FILE: "id=<app-id>" and "arg=<finish arg>" lines; non-zero when the file is not a JSON object
    python3 -I -c '
import json, sys
m = json.load(open(sys.argv[1]))
if not isinstance(m, dict):
    sys.exit("not a JSON object")
print("id=" + str(m.get("app-id", m.get("id", ""))))
for a in m.get("finish-args", []):
    print("arg=" + str(a))
' "$1"
}

check() { # DOC API AUDIT MANIFEST
    local doc=$1 api=$2 audit=$3 manifest=$4 fail=0 h
    bad() { echo "manual-m3: $*" >&2; fail=1; }
    local p16 p17 p18 p19 part
    # The section finder: each M3 heading exactly once.
    for h in "$H16" "$H17" "$H18" "$H19"; do
        [ "$(count_heading "$doc" "$h")" -eq 1 ] || { bad "the heading '$h' must appear exactly once"; return 1; }
    done
    p16=$(msection "$doc" "$H16"); p17=$(msection "$doc" "$H17"); p18=$(msection "$doc" "$H18"); p19=$(msection "$doc" "$H19")
    need() { grep -Eq -- "$1" <<< "$part" || bad "$m: $2"; }
    local m

    # ---- Acceptance 14 (section 16)
    m=16; part=$p16
    local op
    for op in ListKeys ImportP12 ReplaceCertificate Sign DeleteKey; do
        fenced <<< "$part" | grep -Eq "^(\\$ )?busctl .* $op( |\$)" || bad "$m: no busctl command for $op"
    done
    fenced <<< "$part" | grep -Eq 'busctl .* NameHasOwner ' || bad "$m: no detection command (NameHasOwner)"
    need 'docs/api\.md.*Detection|Detection.*docs/api\.md' "no reference to the docs/api.md 'Detection' steps"
    need '[Uu]se only .?docs/api\.md|only .?docs/api\.md' "no sentence that only docs/api.md is followed"
    need '^\| #.*Result' "no table to record the dialogs and errors"
    local a
    for a in import-certificate replace-certificate sign delete-certificate; do
        need "^.*[Dd]ialog.*com\\.rfirma\\.custodio\\.$a|com\\.rfirma\\.custodio\\.$a.*[Dd]ialog" "no dialog line for the action $a"
    done
    # Every error that an example of docs/api.md names is covered (a trigger step, or a "not reproduced manually, because" line).
    local errs e
    errs=$(example_errors "$api")
    [ "$(wc -l <<< "$errs")" -ge 7 ] && [ -n "$errs" ] || bad "$m: fewer than 7 error names read from the examples of docs/api.md"
    grep -qxF WrongPasswordOrBadP12 <<< "$errs" || bad "$m: the error list lacks WrongPasswordOrBadP12 (digits lost?)"
    while IFS= read -r e; do
        [ -n "$e" ] || continue
        grep -qF -- "Error.$e\`" "$api" || bad "$m: '$e' of an example is not an error of docs/api.md"
        grep -qF -- "$e" <<< "$part" || bad "$m: the error $e is not covered"
    done <<< "$errs"

    # ---- Acceptance 15 (section 17)
    m=17; part=$p17
    local lines_det lines_call lines_dlg lines_jr
    lines_det=$(grep -nE 'docs/api\.md.*Detection|Detection.*docs/api\.md' <<< "$part" | head -n 1 | cut -d: -f1 || true)
    lines_call=$(fenced_n "$part" | grep -E '(busctl|gdbus) .*[ .](Sign|ImportP12)( |$)' | head -n 1 | cut -d: -f1 || true)
    lines_dlg=""
    if [ -n "$lines_call" ]; then
        lines_dlg=$(awk -v c="$lines_call" 'NR > c && /com\.rfirma\.custodio\.(sign|import-certificate)/ { print NR; exit }' <<< "$part")
    fi
    lines_jr=$(grep -nE 'journalctl|CUSTODIO_APP_ID' <<< "$part" | head -n 1 | cut -d: -f1 || true)
    [ -n "$lines_det" ] || bad "$m: no reference to the docs/api.md 'Detection' steps"
    [ -n "$lines_call" ] || bad "$m: no busctl or gdbus Sign or ImportP12 step"
    [ -n "$lines_dlg" ] || bad "$m: no polkit dialog/action line after the call"
    [ -n "$lines_jr" ] || bad "$m: no journal step"
    if [ -n "$lines_det$lines_call$lines_dlg$lines_jr" ] && [ -n "$lines_det" ] && [ -n "$lines_call" ] && [ -n "$lines_dlg" ] && [ -n "$lines_jr" ]; then
        { [ "$lines_det" -lt "$lines_call" ] && [ "$lines_call" -lt "$lines_dlg" ] && [ "$lines_dlg" -lt "$lines_jr" ]; } ||
            bad "$m: the order must be detection ($lines_det), call ($lines_call), dialog ($lines_dlg), journal ($lines_jr)"
    fi
    fenced <<< "$part" | grep 'busctl' >/dev/null && bad "$m: busctl (the runtime lacks it)"
    need 'CUSTODIO_APP_ID_STATE=read' "no CUSTODIO_APP_ID_STATE=read"
    need 'CUSTODIO_UID' "no CUSTODIO_UID"
    need 'id -u' "no id -u for the person's uid"
    need 'undetermined' "no record for an undetermined app-id"
    need '(^|[^a-z])none([^a-z]|$)' "no record for the app-id state none"
    need 'failure of acceptance 15' "an undetermined or missing app-id is not recorded as a failure of acceptance 15"
    need 'proxy' "no note that the pid is the proxy's"
    need '^\| #.*Result' "no table to record the observations"
    # The manifest: named by the section, exists, parses, grants only the talk permission, runs gdbus and not busctl, same app-id.
    local mpath
    mpath=$(grep -oE 'packaging/flatpak/[A-Za-z0-9_.-]+\.json' <<< "$part" | head -n 1 || true)
    [ -n "$mpath" ] || bad "$m: the section names no manifest path"
    [ -z "$mpath" ] || [ "$mpath" = "$MANIFEST_NAMED" ] || bad "$m: the section names '$mpath', the test checks '$MANIFEST_NAMED'"
    [ -f "$manifest" ] || bad "$m: the manifest '$manifest' does not exist"
    if [ -f "$manifest" ]; then
        local info mid
        if ! info=$(manifest_info "$manifest" 2> /dev/null); then
            bad "$m: the manifest does not parse as a JSON object"
        else
            grep -qxF -- 'arg=--system-talk-name=com.rfirma.Custodio1' <<< "$info" || bad "$m: the manifest lacks --system-talk-name=com.rfirma.Custodio1"
            ! grep -E '^arg=--(talk-name|own-name|socket=system-bus|socket=session-bus|filesystem=host|share=network|system-own-name)' <<< "$info" | grep . >/dev/null ||
                bad "$m: the manifest has a wider permission than the talk name"
            [ "$(grep -c '^arg=--system-talk-name=' <<< "$info")" -eq 1 ] || bad "$m: the manifest must have exactly one --system-talk-name"
            mid=$(sed -n 's/^id=//p' <<< "$info")
            [ -n "$mid" ] || bad "$m: the manifest has no id or app-id"
            local ids
            ids=$(grep -oE 'CUSTODIO_APP_ID=[A-Za-z0-9_.-]+' <<< "$part" | sed 's/^CUSTODIO_APP_ID=//' | sort -u || true)
            [ -n "$ids" ] || bad "$m: the section gives no CUSTODIO_APP_ID=<app-id> to look for"
            [ "$ids" = "$mid" ] || bad "$m: the app-id to look for ('$ids') is not the manifest's ('$mid')"
        fi
        grep -q 'gdbus' "$manifest" || bad "$m: the manifest does not run gdbus"
        grep -q 'busctl' "$manifest" && bad "$m: the manifest runs busctl"
    fi
    need 'CUSTODIO_APP_ID=' "the page does not demand the app-id"

    # ---- The journal text of section 17 against docs/audit.md
    local q f
    q=$(audit_query "$audit"); [ -n "$q" ] || bad "no base query in $audit"
    fenced <<< "$p17" | awk '{ sub(/ \\$/, "") } 1' | grep -xF -- "$q" >/dev/null || bad "17: the base journalctl query is not the one of docs/audit.md"

    # ---- Acceptance 16 (section 18)
    m=18; part=$p18
    need 'ListKeys' "no ListKeys for the second account"
    need 'a\(sssay\) 0' "no expected empty ListKeys"
    local ref refs=0 lo=0 ff=0
    while IFS= read -r ref; do
        [ -n "$ref" ] || continue
        refs=$((refs + 1))
        grep -qxF -- "$ref" "$doc" || bad "$m: the referenced heading '$ref' is not on the page"
        [[ $ref == *LibreOffice* ]] && lo=1
        [[ $ref == *fedora44* || $ref == *omarchy* ]] && ff=1
    done < <(grep -oE '`## [0-9]+\. [^`]+`' <<< "$part" | sed 's/^`//;s/`$//')
    [ "$refs" -ge 2 ] || bad "$m: fewer than 2 referenced headings of the page"
    [ "$lo" -eq 1 ] || bad "$m: no referenced LibreOffice heading"
    [ "$ff" -eq 1 ] || bad "$m: no referenced heading with the Firefox steps (fedora44 or omarchy)"
    # The token-listing command is one of the page outside the M3 sections, whole.
    local first outside listed=0 c
    first=$(grep -nxF -- "$H16" "$doc" | head -n 1 | cut -d: -f1)
    outside=$(head -n "$((first - 1))" "$doc")
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        listed=$((listed + 1))
        fenced <<< "$outside" | grep -xF -- "$c" >/dev/null || bad "$m: the listing command '$c' is not a command of another section of the page"
    done < <(fenced <<< "$part" | grep -E '^(modutil|certutil|pkcs11-tool) ' || true)
    [ "$listed" -ge 1 ] || bad "$m: no token-listing command"

    # ---- All M3 commands and names against docs/api.md and docs/audit.md
    local all_api all_m3 t
    all_api=$(fenced < "$api" | tuples)
    all_m3=$(printf '%s\n%s\n%s\n' "$p16" "$p17" "$p18")
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        grep -qxF -- "$t" <<< "$all_api" || bad "the command '$t' is not an example of docs/api.md"
    done < <(fenced <<< "$all_m3" | grep busctl | tuples)
    fenced <<< "$all_m3" | grep busctl | grep -vq -- '--system call' && bad "a busctl command of the M3 part is not 'busctl --system call'"
    if fenced <<< "$all_m3" | grep gdbus >/dev/null; then
        local g
        while IFS= read -r g; do
            g=$(sed -E 's/^\$ //' <<< "$g")
            grep -qF -- "$g" "$api" || bad "the gdbus command '$g' is not in docs/api.md"
        done < <(fenced <<< "$all_m3" | grep gdbus)
    fi
    for a in $(grep -oE 'com\.rfirma\.custodio\.[a-z-]+' <<< "$all_m3" | sort -u); do
        grep -qF -- "$a" "$api" || bad "the action id '$a' is not in docs/api.md"
    done
    for a in $(grep -oE 'com\.rfirma\.Custodio1\.Error\.[A-Za-z0-9]+' <<< "$all_m3" | sort -u); do
        grep -qF -- "$a\`" "$api" || bad "the error name '$a' is not in docs/api.md"
    done
    for f in $(grep -oE 'CUSTODIO_[A-Z_]+' <<< "$all_m3" | sort -u); do
        grep -qE -- "(^|[^A-Z_])$f([^A-Z_]|\$)" "$audit" || bad "the journal field '$f' is not in docs/audit.md"
    done
    for f in read undetermined none; do
        grep -qF -- "\`$f\`" "$audit" || bad "docs/audit.md has no app-id state '$f'"
    done

    # ---- Result form (section 19)
    m=19; part=$p19
    for a in 14 15 16; do need "^\\| M3 $a " "no row for acceptance $a"; done
    return $fail
}
# The same lines of a block with their line numbers (relative to the block), fenced lines only.
fenced_n() { awk '/^[ \t]*```/ { f = !f; next } f { sub(/^[ \t]+/, ""); print NR ":" $0 }' <<< "$1"; }
MANIFEST_NAMED=packaging/flatpak/com.rfirma.CustodioTest.json

check "$DOC" "$API" "$AUDIT" "$MANIFEST" || { echo "test-docs-manual-m3: the page fails its checks" >&2; exit 1; }
[ -z "${CHECK_ONLY:-}" ] || exit 0

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fixture() { # fixture NAME FILE: the fixture in $tmp/fix must differ from FILE
    if cmp -s "$2" "$tmp/fix"; then echo "control '$1': the fixture equals the real file, the control is void" >&2; exit 1; fi
}
fails() { # fails NAME: the check with the fixture(s) of $tmp must fail
    if check "$d" "$a" "$u" "$mf" 2> /dev/null; then echo "control '$1': a broken file passed" >&2; exit 1; fi
}
d=$DOC a=$API u=$AUDIT mf=$MANIFEST
control() { # control NAME SED_EXPR: on the whole page
    sed -E -e "$2" "$DOC" > "$tmp/fix"; fixture "$1" "$DOC"; d=$tmp/fix; fails "$1"; d=$DOC
}
in16() { control "$1" "/^## 16\\./,/^## 17\\./ { $2 }"; }
in17() { control "$1" "/^## 17\\./,/^## 18\\./ { $2 }"; }
in18() { control "$1" "/^## 18\\./,/^## 19\\./ { $2 }"; }
in19() { control "$1" "/^## 19\\./,\$ { $2 }"; }
ctl_api() { sed -E -e "$2" "$API" > "$tmp/fix"; fixture "$1" "$API"; a=$tmp/fix; fails "$1"; a=$API; }
ctl_audit() { sed -E -e "$2" "$AUDIT" > "$tmp/fix"; fixture "$1" "$AUDIT"; u=$tmp/fix; fails "$1"; u=$AUDIT; }
ctl_manifest() { sed -E -e "$2" "$MANIFEST" > "$tmp/fix"; fixture "$1" "$MANIFEST"; mf=$tmp/fix; fails "$1"; mf=$MANIFEST; }

# The section finder: a duplicated and a missing heading; an item removed from M3 while an M2 section still has the word.
control 'M3 heading 16 duplicated' "s/^## 17\\. M3 acceptance 15: a flatpak calls Custodio\$/## 16. M3 acceptance 14: the client API by hand/"
control 'M3 heading 17 missing' 's/^## 17\. M3 acceptance 15:/## 17. M3 acceptance 15 (renamed):/'
control 'M3 heading 19 missing' 's/^## 19\. M3 result form/## 19. M3 results/'
in18 'LibreOffice removed' 's/LibreOffice/the office suite/g'
in17 'journal removed from M3, M2 has the journal' 's/journalctl/true/g; s/CUSTODIO_APP_ID/CUSTODIO_X/g'

# Acceptance 14.
for op in ListKeys ImportP12 ReplaceCertificate Sign DeleteKey; do in16 "no $op command" "s/ $op( |\$)/ X$op\\1/"; done
in16 'no detection command' 's/ NameHasOwner / HasOwner /'
in16 'no Detection reference' 's/docs\/api\.md/the API page/g'
in16 'no "only docs/api.md" sentence' 's/only `docs\/api\.md`/the API page/g; s/only docs\/api\.md/the API page/g'
in16 'no record table' 's/^\| #/| No/'
for act in import-certificate replace-certificate sign delete-certificate; do
    in16 "no dialog line for $act" "s/com\\.rfirma\\.custodio\\.$act/com.rfirma.custodio.none/g"
done
for e in KeyIdTaken InvalidArgs NoSuchKey CertificateMismatch PolkitDenied WrongPasswordOrBadP12 AuthorizationUnavailable; do
    in16 "error $e removed" "s/$e/Gone/g"
done
in16 'method name altered in 16' 's/ ReplaceCertificate say / ReplaceCertificat say /'
in16 'signature altered in 16' 's/ ReplaceCertificate say / ReplaceCertificate sat /'
in16 'action id altered in 16' 's/com\.rfirma\.custodio\.sign/com.rfirma.custodio.signs/g'
in16 'invented error name' 's/com\.rfirma\.Custodio1\.Error\.NoSuchKey/com.rfirma.Custodio1.Error.NoKey/g'
ctl_api 'no error= in the examples' 's/ error=[A-Za-z0-9]+//'
ctl_api 'trailing digits lost in the error list' 's/error=WrongPasswordOrBadP12/error=WrongPasswordOrBadP/'

# Acceptance 15: the commands, the order, the journal text, the F67 branch.
in17 'method name altered in 17' 's/\.Custodio1\.Sign /.Custodio1.Sig /'
in17 'arguments altered in 17' 's/\.Sign p256 4161 0 0 /.Sign p256 4161 0 /'
in17 'destination altered in 17' 's/gdbus call --system --dest com\.rfirma\.Custodio1 /gdbus call --system --dest com.rfirma.Custodio2 /'
in17 'busctl Sign in 17' 's/gdbus (call --system --dest com\.rfirma)/busctl \1/'
in17 'action id altered in 17' 's/com\.rfirma\.custodio\.sign/com.rfirma.custodio.sing/g'
in17 'no dialog line' 's/com\.rfirma\.custodio\.(sign|import-certificate)/the action/g'
in17 'no Sign step' 's/\.Custodio1\.Sign /.Custodio1.ListKeys /'
in17 'journal before the dialog' '/Detection.*docs\/api\.md/ s/$/\njournalctl x CUSTODIO_APP_ID=com.rfirma.CustodioTest/'
in17 'no CUSTODIO_APP_ID_STATE=read' 's/CUSTODIO_APP_ID_STATE=read/CUSTODIO_APP_ID_STATE=seen/g'
in17 'invented field' 's/CUSTODIO_UID/CUSTODIO_USER/g'
in17 'changed query' 's/MESSAGE_ID=/MESSAGE_ID=0/'
in17 'no undetermined' 's/undetermined/unknown/g'
in17 'no proxy note' 's/proxy/relay/g'
in17 'no failure record' 's/failure of acceptance 15/note/g'
in17 'no manifest path' 's#packaging/flatpak/com\.rfirma\.CustodioTest\.json#packaging/flatpak/none.json#g'
in17 'other app-id on the page' 's/CUSTODIO_APP_ID=com\.rfirma\.CustodioTest/CUSTODIO_APP_ID=org.example.Other/g'
ctl_audit 'audit lacks CUSTODIO_UID' 's/CUSTODIO_UID/CUSTODIO_UIDX/g'
ctl_audit 'audit lacks the query' 's/MESSAGE_ID=/MESSAGE_ID=1/'

# The manifest.
ctl_manifest 'permission removed' 's/--system-talk-name=com\.rfirma\.Custodio1/--filesystem=xdg-download/'
ctl_manifest 'talk-name instead' 's/--system-talk-name=/--talk-name=/'
ctl_manifest 'wide permission added' 's/("--system-talk-name=com\.rfirma\.Custodio1")/\1, "--socket=system-bus"/'
ctl_manifest 'invalid JSON' 's/^\{/{{/'
ctl_manifest 'no gdbus' 's/gdbus/true/g'
ctl_manifest 'busctl in the manifest' 's/gdbus call/busctl call/'
ctl_manifest 'other app-id (id key only)' 's/^( *"(app-)?id": *")[^"]*/\1org.example.Other/'

# Acceptance 16.
in18 'no empty ListKeys' 's/a\(sssay\) 0/a(sssay) 1/g'
in18 'no ListKeys' 's/ListKeys/List/g'
in18 'listing command invented' 's/-list$/-show/'
in18 'listing command invented (tool)' 's/^( *)(modutil|pkcs11-tool) /\1\2x /'
control 'referenced heading renamed' 's/^## 6\. LibreOffice run$/## 6. LibreOffice runs/'
control 'referenced heading renamed (fedora44)' 's/^## 11\. fedora44, SELinux enforcing \(acceptance 12\)$/## 11. fedora44/'
in18 'no referenced headings' 's/`## [0-9]+\. [^`]+`/the sections/g'

# Result form.
for n in 14 15 16; do in19 "form row $n removed" "s/^\\| M3 $n /| X $n /"; done

echo "test-docs-manual-m3: ok"
