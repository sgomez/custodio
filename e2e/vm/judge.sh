# shellcheck shell=bash
# The VM-only cases (F160), sourced by the guest of a VM run (guest.sh with E2E_VM=1) and by scripts/test-e2e-vm-host.sh, which runs the judging
# functions on fixtures. A judge prints its problems, one per line, and nothing when the case holds; vm_report prints the E2E-CASE line or fails.
# Every path is a variable so that a test can point it at a fixture:
#   VM_TPMRM        the resource-manager device (default /dev/tpmrm0)
#   VM_UNIT         the installed unit; VM_UNIT_DIRS the directories whose custodio.service.d must not exist or must be empty (default /etc, /run, /usr/lib of systemd/system)
#   VM_FACTS        the directory the run collected right after the package install (vm_collect_install): has2.out, has2.rc, apt-commandlines, recommends-installed, unit.sha256
#   VM_ENV          the environment of the running service (default /proc/MainPID/environ), VM_FDS an `ls -l` of its open files
# shellcheck source=e2e/report.sh
source "$(dirname "${BASH_SOURCE[0]}")/../report.sh"
VM_TPMRM=${VM_TPMRM:-/dev/tpmrm0}
VM_UNIT=${VM_UNIT:-/usr/lib/systemd/system/custodio.service}
VM_UNIT_DIRS=${VM_UNIT_DIRS:-/etc/systemd/system /run/systemd/system /usr/lib/systemd/system}
VM_FACTS=${VM_FACTS:-/var/lib/custodio-e2e-vm}
VM_TCTI_VAR=CUSTODIOD_TEST_SWTPM_TCTI

vm_judge_tpmrm0() { [ -e "$VM_TPMRM" ] || echo "$VM_TPMRM does not exist"; }

# vm_judge_has_tpm2 OUTPUT RC: systemd-analyze has-tpm2 reports full support: exit 0 and the output `yes`
vm_judge_has_tpm2() {
    [ "$1" = yes ] && [ "$2" = 0 ] || echo "systemd-analyze has-tpm2 printed '$1' and exited $2 (expected 'yes', 0)"
}

# vm_judge_no_recommends: every apt command line that installed anything has --no-install-recommends, and no recommended package of what it pulled in is installed
vm_judge_no_recommends() {
    local f=$VM_FACTS line
    [ -s "$f/apt-commandlines" ] || { echo "no apt command line was recorded"; return 0; }
    while IFS= read -r line; do
        case $line in *" install "*) case $line in *" --no-install-recommends "*) ;; *) echo "apt ran without --no-install-recommends: $line" ;; esac ;; esac
    done < "$f/apt-commandlines"
    [ ! -s "$f/recommends-installed" ] || echo "a recommended package is installed: $(tr '\n' ' ' < "$f/recommends-installed")"
}

# vm_judge_tcti_absent ENVFILE...: the variable that points the service at a test swtpm is in none of the files (the unit, its drop-ins, the environment)
vm_judge_tcti_absent() {
    local f
    for f in "$@"; do
        [ -e "$f" ] || continue
        if tr '\0' '\n' < "$f" | grep -q "$VM_TCTI_VAR"; then echo "$VM_TCTI_VAR is set in $f"; fi
    done
}

# vm_dropins: the files under any custodio.service.d of VM_UNIT_DIRS
vm_dropins() {
    local d
    for d in $VM_UNIT_DIRS; do [ ! -d "$d/custodio.service.d" ] || find "$d/custodio.service.d" -type f; done
}

# vm_judge_unit_shipped: no drop-in, the unit is the packaged one (its checksum is the .deb's, collected after the install), no test variable in the unit or a drop-in
vm_judge_unit_shipped() {
    local d sum want
    while IFS= read -r d; do [ -z "$d" ] || echo "drop-in present: $d"; done < <(vm_dropins)
    want=$(cat "$VM_FACTS/unit.sha256" 2> /dev/null || true)
    sum=$(sha256sum "$VM_UNIT" 2> /dev/null | cut -d' ' -f1 || true)
    [ -n "$want" ] || echo "the packaged unit's checksum was not collected"
    [ -z "$want" ] || [ "$sum" = "$want" ] || echo "the unit differs from the packaged one"
    # shellcheck disable=SC2046 # one word per file
    vm_judge_tcti_absent "$VM_UNIT" $(vm_dropins)
}

# vm_judge_via_device ENVFILE FDS: the running service has no test TCTI and holds /dev/tpmrm0, not a socket
vm_judge_via_device() {
    vm_judge_tcti_absent "$1"
    grep -q -- "$(basename "$VM_TPMRM")" "$2" 2> /dev/null || echo "the service has no $VM_TPMRM open"
    ! grep -qE -- 'socket:|swtpm|\.sock' "$2" 2> /dev/null || echo "the service holds a socket to a TPM, not the device"
}

# vm_collect_install DEB HAS2_OUTPUT HAS2_RC: run in the guest right after the package install and before any test tool: the facts the install-time cases judge.
# The driver read `systemd-analyze has-tpm2` itself at that moment and passes what it saw.
vm_collect_install() {
    local deb=$1 f=$VM_FACTS pkgs p r
    mkdir -p "$f"
    printf '%s\n' "$2" > "$f/has2.out"
    printf '%s\n' "$3" > "$f/has2.rc"
    # the first line of the output is the verdict (`yes`, `partial` or `no`)
    head -n 1 "$f/has2.out" > "$f/has2.verdict"
    grep '^Commandline:' /var/log/apt/history.log | sed 's/^Commandline: / /; s/$/ /' > "$f/apt-commandlines" || true
    pkgs=$(awk '/^Install:/ {gsub(/\([^)]*\)/, ""); gsub(/,/, " "); for (i = 2; i <= NF; i++) if ($i !~ /:/ || $i ~ /:amd64$/) { sub(/:amd64$/, "", $i); print $i }}' /var/log/apt/history.log | sort -u)
    : > "$f/recommends-installed"
    for p in $pkgs; do
        # shellcheck disable=SC2020 # tr maps each of the two separators to a newline
        for r in $(dpkg-query -W -f='${Recommends}' "$p" 2> /dev/null | tr ',|' '\n\n' | sed 's/([^)]*)//; s/[[:space:]]//g; /^$/d'); do
            case " $pkgs " in *" $r "*) continue ;; esac
            ! dpkg-query -W -f='${Status}' "$r" 2> /dev/null | grep -q '^install ok installed' || echo "$r" >> "$f/recommends-installed"
        done
    done
    dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/lib/systemd/system/custodio.service | sha256sum | cut -d' ' -f1 > "$f/unit.sha256"
}

# vm_service_facts: the environment and the open files of the running service, into VM_FACTS (used by the live judges)
vm_service_facts() {
    local pid
    local proc=${VM_PROC:-/proc}
    pid=$(systemctl show -p MainPID --value custodio)
    [ -n "$pid" ] && [ "$pid" != 0 ] || return 1
    cp "$proc/$pid/environ" "$VM_FACTS/service.environ" && ls -l "$proc/$pid/fd" > "$VM_FACTS/service.fds"
}

# The cases are judged more than once (after the shared setup and after the cases); vm_note collects the problems of each case, vm_finish reports
# every VM-only case once and fails when any pass found a problem.
declare -A VM_NOTES=()
vm_note() { VM_NOTES[$1]+=$(printf '%s\n' "$2" | sed '/^$/d'); }
vm_finish() { # prints the problems and returns 1, or reports the cases
    local c bad=''
    for c in vm-tpmrm0-exists vm-has-tpm2-full vm-install-no-recommends vm-unit-shipped vm-tpm-via-device; do
        if [ -n "${VM_NOTES[$c]:-}" ]; then printf 'e2e: FAIL: %s:\n%s\n' "$c" "${VM_NOTES[$c]}" >&2; bad=1; else case_run "$c"; fi
    done
    [ -z "$bad" ]
}

# vm_install_cases: the judges of what the install left (facts collected right after it, before any test tool)
vm_install_cases() {
    vm_note vm-has-tpm2-full "$(vm_judge_has_tpm2 "$(cat "$VM_FACTS/has2.verdict" 2> /dev/null)" "$(cat "$VM_FACTS/has2.rc" 2> /dev/null)")"
    vm_note vm-install-no-recommends "$(vm_judge_no_recommends)"
}

# vm_live_cases WHEN: the judges of what the running machine shows (run after the shared setup and again after the cases, logged each time)
vm_live_cases() {
    echo "vm_judge: live checks ($1)"
    vm_note vm-tpmrm0-exists "$(vm_judge_tpmrm0)"
    vm_note vm-unit-shipped "$(vm_judge_unit_shipped)"
    if vm_service_facts; then
        vm_note vm-tpm-via-device "$(vm_judge_via_device "$VM_FACTS/service.environ" "$VM_FACTS/service.fds")"
    else
        vm_note vm-tpm-via-device "the service has no main process"
    fi
}
