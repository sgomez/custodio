#!/usr/bin/env bash
# Test of docs/install.md (F51). Every claim of the document that the repository can prove is checked against the repository:
# the install command of each target against e2e/targets/<t>/install.sh, the bus-check messages against packaging/bus-check.sh,
# the paths against packaging/deb/postrm. Each kind of check has a negative control: a fixture copy of the document with the
# claim broken must fail. Usage: scripts/test-docs-install.sh   (DOC and README override the real files, for the controls).
set -euo pipefail
cd "$(dirname "$0")/.."

# section DOC HEADING_REGEX: the heading line that matches (any level) up to the next heading of the same or a higher level.
# Fenced code blocks are not scanned for headings.
section() {
    awk -v re="$2" '
        /^```/ { fence = !fence }
        !fence && /^#+ / {
            match($0, /^#+/); lvl = RLENGTH
            if (on && lvl <= on) on = 0
            if (!on && $0 ~ re) { on = lvl }
        }
        on { print }
    ' "$1"
}

# fenced DOC HEADING_REGEX: the fenced code blocks of a section, one block per paragraph.
fenced() {
    section "$1" "$2" | awk '/^```/ { f = !f; if (!f) print ""; next } f { print }'
}

# install_cmd SCRIPT: "tool subcommand" of the install command of an e2e install.sh: the first command line that is not a
# comment, set or shebang; leading VAR=value words dropped; the subcommand is the first later word before "$1" that is not an
# option and not an assignment, else the first option (dpkg -i, pacman -U).
install_cmd() {
    awk '
        /^[[:space:]]*(#|$)/ || /^set / { next }
        /"\$1"/ {
            n = split($0, w, /[[:space:]]+/); i = 1
            while (i <= n && (w[i] == "" || w[i] ~ /^[A-Za-z_]+=/)) i++
            tool = w[i]; sub_ = ""; first = ""
            for (j = i + 1; j <= n; j++) {
                if (w[j] ~ /^"\$1"/) break
                if (w[j] ~ /^-/) { if (first == "") first = w[j]; continue }
                if (w[j] ~ /=/) continue
                sub_ = w[j]; break
            }
            if (sub_ == "") sub_ = first
            print tool " " sub_; exit
        }' "$1"
}

# has_cmd TEXT TOOL SUB: some line holds TOOL and, later on the same line, SUB as a word.
has_cmd() {
    printf '%s\n' "$1" | grep -Eq -- "(^|[^[:alnum:]_-])$2( .*)? $3([^[:alnum:]_-]|$)"
}

check() {
    local doc=$1 readme=$2 fail=0 t cmd tool sub text
    bad() { echo "docs/install.md: $*" >&2; fail=1; }
    need() { # need TEXT REGEX WHAT
        printf '%s\n' "$1" | grep -Eq -- "$2" || bad "$3"
    }
    [ -s "$doc" ] || { bad "missing or empty"; return 1; }

    # Installation per target: the command that the e2e script really ran, in the section of that system.
    local -A heading=(
        [debian13]='^#+ .*Debian 13' [ubuntu2604]='^#+ .*Ubuntu 26\.04' [fedora44]='^#+ .*Fedora 44'
        [alma10]='^#+ .*(Alma|RHEL)' [arch]='^#+ .*Arch'
    )
    for t in e2e/targets/*/; do
        t=$(basename "$t")
        [ -n "${heading[$t]:-}" ] || { bad "no section is known for e2e target $t"; continue; }
        cmd=$(install_cmd "e2e/targets/$t/install.sh")
        tool=${cmd% *}; sub=${cmd#* }
        if [ -z "$tool" ] || [ -z "$sub" ]; then bad "cannot derive the install command of target $t"; continue; fi
        text=$(section "$doc" "${heading[$t]}")
        [ -n "$text" ] || { bad "no section for $t"; continue; }
        has_cmd "$text" "$tool" "$sub" || bad "section for $t lacks '$tool ... $sub'"
    done
    text=$(section "$doc" '^#+ .*rpm-ostree')
    [ -n "$text" ] || bad "no rpm-ostree section"
    has_cmd "$text" rpm-ostree install || bad "rpm-ostree section lacks 'rpm-ostree install'"
    need "$text" 'uninstall' "rpm-ostree section does not mention uninstall"
    need "$(section "$doc" '^#+ .*Debian 13')" 'apt-get -f install' "Debian section lacks the 'apt-get -f install' answer to missing dependencies"

    # Why a bus without ProcessFD is refused.
    text=$(section "$doc" '^#+ .*ProcessFD')
    [ -n "$text" ] || bad "no section on ProcessFD"

    # Every bus-check message that points here is answered. The phrases are looked up in the script, so they track its text.
    local phrases=('no system bus is running' 'neither busctl nor dbus-send' 'could not be queried' 'does not provide ProcessFD') p n
    for p in "${phrases[@]}"; do
        grep -qF -- "$p" packaging/bus-check.sh || bad "phrase '$p' is no longer in packaging/bus-check.sh; update this test"
        grep -qF -- "$p" "$doc" || bad "the doc does not answer the bus-check message '$p'"
    done
    n=$(grep -c 'docs/install.md' packaging/bus-check.sh || true)
    [ "$n" -le "${#phrases[@]}" ] || bad "packaging/bus-check.sh has $n lines pointing to docs/install.md, this test knows ${#phrases[@]} messages"

    # The systemd floor: read from the packaging, stated in "Supported systems" with the words for unsupported and refused. No system is
    # documented below it, so there is no heading for Ubuntu 24.04 and no section on switching the bus.
    local floor flat
    floor=$(sed -n 's/^[[:space:]]*- systemd (>= \([0-9][0-9]*\))[[:space:]]*$/\1/p' packaging/nfpm.yaml | head -n 1)
    [ -n "$floor" ] || bad "cannot read the systemd floor (Pre-Depends) from packaging/nfpm.yaml"
    text=$(section "$doc" '^#+ .*Supported systems')
    [ -n "$text" ] || bad "no Supported systems section"
    flat=$(printf '%s\n' "$text" | tr '\n' ' ' | tr -s ' ')
    printf '%s\n' "$flat" | grep -Eqi -- "every package requires systemd $floor or later" || bad "Supported systems does not say that every package requires systemd $floor or later"
    printf '%s\n' "$flat" | grep -Eq -- 'Ubuntu 24\.04[^.]* not supported|not supported[^.]*Ubuntu 24\.04' || bad "Supported systems does not say that Ubuntu 24.04 is not supported"
    printf '%s\n' "$flat" | grep -Eq -- 'refused by the package manager' || bad "Supported systems does not say that older systems are refused by the package manager"
    printf '%s\n' "$flat" | grep -Eq -- 'Ubuntu 24\.04[^.]* is supported' && bad "Supported systems lists Ubuntu 24.04 as supported"
    [ -z "$(section "$doc" '^#+ .*Ubuntu 24\.04')" ] || bad "a section for Ubuntu 24.04 remains"
    ! grep -qi 'switching to dbus-broker' "$doc" || bad "the dbus-broker switching section remains"

    # Removal and purge.
    text=$(section "$doc" '^#+ .*(Remov|Purg)')
    [ -n "$text" ] || bad "no removal section"
    need "$text" 'purge' "removal section does not mention purge"
    need "$text" 'secure erasure' "removal section lacks the warning about secure erasure"
    need "$text" 'irreversible' "removal section does not say the deletion is irreversible"
    while IFS= read -r p; do
        grep -qF -- "$p" <<< "$text" || bad "removal section lacks the path $p that packaging/deb/postrm prints"
    done < <(grep -o '/var/lib/[a-z/]*custodio' packaging/deb/postrm | sort -u)
    fenced "$doc" '^#+ .*(Remov|Purg)' | grep -q '/var/lib/private/custodio' || bad "no fenced command that names the state directory"

    # TPM2 Software Stack (F125): each format's line holds the names the table and packaging/nfpm.yaml declare, no more and no fewer.
    text=$(section "$doc" '^#+ .*TPM2 Software Stack')
    [ -n "$text" ] || bad "no TPM2 Software Stack section"
    local fmt want got bt=\`
    for fmt in deb rpm arch; do
        want=$(python3 -I scripts/lib/tss_names.py "$fmt" packaging/nfpm.yaml) || { bad "cannot derive the $fmt TPM2 names"; continue; }
        got=$(printf '%s\n' "$text" | grep -E "^- $fmt: " | grep -o "${bt}[^${bt}]*${bt}" | tr -d "$bt" | sort || true)
        [ "$got" = "$want" ] || bad "the $fmt line of the TPM2 Software Stack section is [${got//$'\n'/ }], the packaging declares [${want//$'\n'/ }]"
    done
    # why the .deb lists libtss2-rc0t64 (the dlopen reason is in the paragraph that names it, outside the lists)
    local rc
    rc=$(python3 -I scripts/lib/tss_names.py deb packaging/nfpm.yaml | grep -- '^libtss2-rc' || true)
    [ -n "$rc" ] || bad "packaging/nfpm.yaml no longer lists libtss2-rc in the .deb Depends; update this test"
    printf '%s\n' "$text" | awk -v RS= -v n="$rc" 'index($0, n) && $0 !~ /(^|\n)- / { print }' | tr '\n' ' ' | grep -Eq -- 'dlopen' || bad "the TPM2 Software Stack section does not say, next to $rc, that systemd loads it by dlopen"
    printf '%s\n' "$text" | awk -v RS= -v n="$rc" 'index($0, n) && $0 !~ /(^|\n)- / { print }' | tr '\n' ' ' | grep -Eqi -- 'recommend' || bad "the TPM2 Software Stack section does not say, next to $rc, that an install without recommends lacks it"

    # Upgrade.
    text=$(section "$doc" '^#+ .*Upgrad')
    [ -n "$text" ] || bad "no upgrade section"

    # Journal.
    text=$(section "$doc" '^#+ .*[Jj]ournal')
    [ -n "$text" ] || bad "no journal section"
    need "$text" '/var/log/journal' "journal section lacks /var/log/journal"
    need "$text" 'Storage=persistent' "journal section lacks Storage=persistent"
    need "$text" 'journalctl --disk-usage' "journal section lacks 'journalctl --disk-usage'"
    need "$text" 'docs/audit\.md|audit\.md' "journal section does not link to the audit queries"
    journalctl --help 2> /dev/null | grep -q -- '--disk-usage' || bad "journalctl has no --disk-usage here"

    # README.
    grep -q 'docs/install\.md' "$readme" || bad "README.md does not link to docs/install.md"
    [ -f docs/install.md ] || bad "the README link target docs/install.md does not exist"
    return $fail
}

DOC=${DOC:-docs/install.md}
README=${README:-README.md}

if [ "${1:-}" = "--check-only" ]; then
    check "$DOC" "$README"
    exit
fi

# Self-test of the helpers: the derived commands.
[ "$(install_cmd e2e/targets/debian13/install.sh)" = "dpkg -i" ] || { echo "install_cmd debian13" >&2; exit 1; }
[ "$(install_cmd e2e/targets/arch/install.sh)" = "pacman -U" ] || { echo "install_cmd arch" >&2; exit 1; }
[ "$(install_cmd e2e/targets/ubuntu2604/install.sh)" = "apt-get install" ] || { echo "install_cmd ubuntu2604" >&2; exit 1; }
[ "$(install_cmd e2e/targets/fedora44/install.sh)" = "dnf install" ] || { echo "install_cmd fedora44" >&2; exit 1; }

check "$DOC" "$README" || { echo "test-docs-install: the document fails its checks" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# control NAME SED_EXPR: the fixture doc with the claim broken must fail, and must differ from the real one.
control() {
    sed -E -e "$2" "$DOC" > "$tmp/doc.md"
    if cmp -s "$DOC" "$tmp/doc.md"; then echo "control '$1': the fixture equals the document, the control is void" >&2; exit 1; fi
    if check "$tmp/doc.md" "$README" 2> /dev/null; then echo "control '$1': a broken document passed" >&2; exit 1; fi
}
drop_section() { # drop_section NAME HEADING_REGEX
    awk -v re="$2" '
        /^```/ { fence = !fence }
        !fence && /^#+ / { match($0, /^#+/); lvl = RLENGTH; if (skip && lvl <= skip) skip = 0; if (!skip && $0 ~ re) skip = lvl }
        !skip { print }' "$DOC" > "$tmp/doc.md"
    if cmp -s "$DOC" "$tmp/doc.md"; then echo "control '$1': nothing dropped" >&2; exit 1; fi
    if check "$tmp/doc.md" "$README" 2> /dev/null; then echo "control '$1': a broken document passed" >&2; exit 1; fi
}

control 'wrong tool for Debian' 's/dpkg -i/rpm -i/g'
control 'wrong tool for Arch' 's/pacman -U/pacman -S/g'
control 'wrong tool for Fedora' 's/dnf install/yum remove/g'
control 'no apt-get -f install' 's/apt-get -f install/apt-get update/g'
control 'rpm-ostree layering missing' 's/rpm-ostree install/rpm-ostree status/g'
control 'TPM2 deb name changed' 's/libtss2-mu-4\.0\.1-0t64/libtss2-mu0/'
control 'TPM2 rpm package changed' 's/^- rpm: \x60tpm2-tss\x60/- rpm: \x60tpm2-tss-libs\x60/'
control 'TPM2 arch bound changed' 's/systemd>=257/systemd>=255/'
control 'TPM2 deb libtss2-rc0t64 dropped' 's/^(- deb:.*)\x60libtss2-rc0t64\x60, /\1/'
control 'TPM2 deb systemd bound changed' 's/systemd \(>= 257\)/systemd (>= 255)/'
control 'dlopen reason removed' 's/dlopen/loads/g'
control 'recommends reason removed' 's/[Rr]ecommends/suggestions/g'
control 'floor stated as 255' 's/requires systemd 257 or later/requires systemd 255 or later/'
control 'floor sentence removed' 's/systemd 257 or later, for/systemd, for/'
control 'refusal sentence removed' 's/are refused by/are ignored by/'
control 'Ubuntu 24.04 listed as supported' 's/^Debian 13, Ubuntu 26.04,/Ubuntu 24.04 is supported. Debian 13, Ubuntu 26.04,/'
control 'TPM2 deb group package dropped' 's/, \x60tpm-udev\x60//'
{ cat "$DOC"; printf '\n## Ubuntu 24.04: switching to dbus-broker\n\nsudo apt-get install dbus-broker\n'; } > "$tmp/doc.md"
if check "$tmp/doc.md" "$README" 2> /dev/null; then echo "control 'dbus-broker section back': a broken document passed" >&2; exit 1; fi
drop_section 'TPM2 section removed' '^#+ .*TPM2 Software Stack'
drop_section 'ProcessFD section removed' '^#+ .*ProcessFD'
control 'bus-check answer lacking' 's/could not be queried/failed/g'
control 'bus-check answer lacking (no bus)' 's/no system bus is running/there is no bus/g'
control 'path changed' 's#/var/lib/private/custodio#/var/lib/other#g'
control 'no secure erasure warning' 's/secure erasure/shredding/g'
control 'no irreversibility' 's/irreversible/final/g'
control 'no persistent storage' 's/Storage=persistent/Storage=auto/g'
control 'no disk usage check' 's/journalctl --disk-usage/journalctl --header/g'

# README control.
echo "No link here." > "$tmp/README.md"
if check "$DOC" "$tmp/README.md" 2> /dev/null; then echo "control 'README without link': passed" >&2; exit 1; fi

echo "test-docs-install: ok"
