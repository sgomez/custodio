#!/usr/bin/env bash
# Host side of one VM run (F160, SPEC Design 1): `just e2e-vm MODE` and `just e2e-vm-cases MODE NAME...`.
#   run.sh MODE [NAME...]      MODE is `full` or `lacking`. Without names every case of e2e/vm/cases.list; names and globs (like `just e2e-cases`) select.
#   run.sh --check MODE [NAME...]   only the checks that come before anything starts (the recipes run it before the packages are built)
# The mode of the VM and the expectations of the case scripts (E2E_TPM, which the guest command carries): full -> swtpm (a complete TPM),
# lacking -> lacking (a TPM without RSA decrypt). The VM has no `none` mode.
# Steps (each timed in target/e2e/vm.MODE.phases.tsv): image, boot, copy, install, tools, setup, one per case group, teardown (vm.sh stop).
#   1 image.sh  2 vm.sh start MODE  3 copy N, N+1, the e2e tree and the files the container mounts  4 apt-get update and install N with --no-install-recommends,
#   then read `systemd-analyze has-tpm2` (before any test tool: tpm2-tools brings the libtss2 libraries it needs, F151)  5 test tools, in the guest only, also without recommends
#   6 e2e/guest.sh in VM mode (E2E_VM=1) on the guest, then check-cases.sh (CHECK_VM=1) on its E2E-CASE lines  7 the record. vm.sh stop on every exit.
# The record target/e2e/vm.MODE.record (key=value; a field that could not be read is `unknown`), the log vm.MODE.log. Nothing is installed on the host.
# Settings (the self-test uses them): VM_SH, VM_IMAGE_SH, E2E_OUT, E2E_PACKAGES, E2E_PACKAGES_NEXT, VM_SWTPM, TMPDIR.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$HERE/../.." && pwd -P)
cd "$ROOT"
# shellcheck source=e2e/vm/swtpm-path.sh
. "$HERE/swtpm-path.sh"
VM_SH=${VM_SH:-$HERE/vm.sh}
IMAGE_SH=${VM_IMAGE_SH:-$HERE/image.sh}
OUT=${E2E_OUT:-target/e2e}
PKG=${E2E_PACKAGES:-target/packages}
PKG_NEXT=${E2E_PACKAGES_NEXT:-target/packages-next}
LIST=e2e/vm/cases.list
TOOLS='tpm2-tools openssl opensc p11-kit pkcs11-provider libnss3-tools python3-gi'
die() { echo "e2e-vm: $*" >&2; exit 1; }

mode=${1:-}
check_only=
if [ "$mode" = --check ]; then check_only=1; shift; mode=${1:-}; fi
case $mode in
full) tpm=swtpm ;;
lacking) tpm=lacking ;;
*) die "'$mode' is not a VM mode; the allowed values are: full, lacking" ;;
esac
shift
names=()
set -f # an argument is a glob for the case ids, never for files
for n in "$@"; do for w in $n; do names+=("$w"); done; done
set +f
all=$(grep -v '^[[:space:]]*\(#\|$\)' "$LIST")
selection=$all
if [ "${#names[@]}" -gt 0 ]; then
    for n in "${names[@]}"; do
        [[ $n =~ ^[][A-Za-z0-9._*?-]+$ ]] || die "'$n' is not a case name or a glob of case names"
        hit=
        while IFS= read -r id; do
            # shellcheck disable=SC2053 # the glob is the point
            [[ $id == $n ]] && { hit=1; break; }
        done <<< "$all"
        [ -n "$hit" ] || die "no case matches '$n' (cases of $LIST)"
    done
    selection=$(while IFS= read -r id; do for n in "${names[@]}"; do
        # shellcheck disable=SC2053
        if [[ $id == $n ]]; then echo "$id"; break; fi
    done; done <<< "$all")
fi
[ -z "$check_only" ] || exit 0

# ---- the files: the newest package of each directory, as run.sh finds them
deb=$(find "$PKG" -name 'custodio_*.deb' 2> /dev/null | sort | tail -n 1)
[ -n "$deb" ] || die "no package custodio_*.deb in $PKG (the e2e-packages recipe builds it)"
deb_next=$(find "$PKG_NEXT" -name 'custodio_*.deb' 2> /dev/null | sort | tail -n 1)
[ -n "$deb_next" ] || die "no package N+1 custodio_*.deb in $PKG_NEXT (the e2e-packages recipe builds it)"
[ "$(realpath "$deb")" != "$(realpath "$deb_next")" ] || die "N and N+1 are the same file"
deps=$(dpkg-deb -f "$deb" Depends Recommends Pre-Depends) || die "cannot read the fields of $deb"
for t in $TOOLS polkitd; do
    ! grep -qw -- "$t" <<< "$deps" || die "the package depends on or recommends the test tool $t: the tools are installed in the guest only"
done
version=$(dpkg-deb -f "$deb" Version) || version=unknown

mkdir -p "$OUT"
rec=$OUT/vm.$mode.record log=$OUT/vm.$mode.log phases=$OUT/vm.$mode.phases.tsv
: > "$log"
tmp=$(mktemp -d)
vmdir=
declare -A F=([target]=vm [tpm]=$mode [image_serial]=unknown [kernel]=unknown [systemd]=unknown [package_version]=$version [swtpm_version]=unknown [has_tpm2]=unknown)
steps=()
status=1
say() { echo "e2e-vm[$mode]: $*" | tee -a "$log" >&2; }

vm_swtpm_resolve
F[swtpm_version]=$(vm_swtpm_run --version 2> /dev/null | head -n 1 || true)
[ -n "${F[swtpm_version]}" ] || F[swtpm_version]=unknown

write_record() {
    local k
    {
        for k in target tpm image_serial kernel systemd package_version swtpm_version has_tpm2; do echo "$k=${F[$k]}"; done
        for k in "${steps[@]}"; do echo "step_${k%%=*}=${k#*=}"; done
    } > "$rec"
    {
        printf 'step\tseconds\n'
        for k in "${steps[@]}"; do printf '%s\t%s\n' "${k%%=*}" "${k#*=}"; done
    } > "$phases"
    cat "$rec"
}
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ -n "$vmdir" ]; then
        t0=$SECONDS
        "$VM_SH" stop "$vmdir" >> "$log" 2>&1 || { echo "e2e-vm: vm.sh stop failed" >&2; rc=1; }
        vmdir=
        step teardown
    fi
    write_record
    rm -rf "$tmp"
    [ "$status" -eq 0 ] || [ "$rc" -ne 0 ] || rc=1
    exit "$rc"
}
trap cleanup EXIT
trap 'echo "e2e-vm: interrupted" >&2; exit 130' INT
trap 'echo "e2e-vm: terminated" >&2; exit 143' TERM

t0=$SECONDS
step() { steps+=("$1=$((SECONDS - t0))"); t0=$SECONDS; }
g() { "$VM_SH" run "$vmdir" "$@"; } # a command in the guest, as the ubuntu account
gt() { local t=$1; shift; "$VM_SH" run "$vmdir" -t "$t" "$@"; }

out=$("$IMAGE_SH") || die "the image is not available: $IMAGE_SH failed"
F[image_serial]=$(printf '%s\n' "$out" | sed -n 's/^serial=//p' | head -n 1)
[ -n "${F[image_serial]}" ] || F[image_serial]=unknown
step image

started=$("$VM_SH" start "$mode") || die "vm.sh start $mode failed"
vmdir=$(printf '%s\n' "$started" | sed -n 's/^VM_DIR=//p')
[ -n "$vmdir" ] || die "vm.sh start printed no VM_DIR"
step boot

# ---- copy: byte for byte, then placed where the case scripts look
tar -C e2e --exclude=__pycache__ -cf "$tmp/e2e.tar" .
tar -C e2e/targets/debian13 -cf "$tmp/target.tar" .
"$VM_SH" put "$vmdir" "$deb" "/tmp/$(basename "$deb")" || die "copying the package N failed"
"$VM_SH" put "$vmdir" "$deb_next" "/tmp/next-$(basename "$deb_next")" || die "copying the package N+1 failed"
"$VM_SH" put "$vmdir" "$tmp/e2e.tar" /tmp/e2e.tar || die "copying the e2e scripts failed"
"$VM_SH" put "$vmdir" "$tmp/target.tar" /tmp/target.tar || die "copying the target files failed"
"$VM_SH" put "$vmdir" docs/audit.md /tmp/audit.md || die "copying docs/audit.md failed"
"$VM_SH" put "$vmdir" scripts/check-no-plaintext.sh /tmp/check-no-plaintext.sh || die "copying check-no-plaintext.sh failed"
"$VM_SH" put "$vmdir" scripts/check_no_plaintext.py /tmp/check_no_plaintext.py || die "copying check_no_plaintext.py failed"
"$VM_SH" put "$vmdir" crates/custodiod/src/app_id_source.rs /tmp/app_id_source.rs || die "copying app_id_source.rs failed"
g "sudo mkdir -p /pkg /pkg-next /e2e /e2e-target /e2e-docs /e2e-noplain/scripts /e2e-src && sudo mv /tmp/$(basename "$deb") /pkg/ && sudo mv /tmp/next-$(basename "$deb_next") /pkg-next/$(basename "$deb_next") \
  && sudo tar -C /e2e -xf /tmp/e2e.tar && sudo tar -C /e2e-target -xf /tmp/target.tar && sudo cp /e2e/vm/cases.list /e2e-target/cases.list && sudo mv /tmp/audit.md /e2e-docs/ \
  && sudo mv /tmp/check-no-plaintext.sh /tmp/check_no_plaintext.py /e2e-noplain/scripts/ && sudo mv /tmp/app_id_source.rs /e2e-src/" >> "$log" 2>&1 || die "placing the files in the guest failed"
step copy

# ---- install the package with apt, without recommends; then, and only then, what the guest says about the TPM
gt 300 "sudo apt-get update" >> "$log" 2>&1 || die "apt-get update failed in the guest"
gt 900 "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends /pkg/$(basename "$deb")" >> "$log" 2>&1 || die "apt-get install of the package failed in the guest"
has_rc=0
has_out=$(g "systemd-analyze has-tpm2" 2>&1) || has_rc=$?
has_out=$(printf '%s' "$has_out" | head -n 1)
F[has_tpm2]="$has_out (exit $has_rc)"
F[kernel]=$(g "uname -r" 2> /dev/null | head -n 1 || true)
F[systemd]=$(g "systemctl --version" 2> /dev/null | head -n 1 || true)
for k in kernel systemd; do [ -n "${F[$k]}" ] || F[$k]=unknown; done
g "sudo bash -c '. /e2e/vm/judge.sh; vm_collect_install /pkg/$(basename "$deb") \"$has_out\" $has_rc'" >> "$log" 2>&1 || die "collecting the install facts failed in the guest"
step install
[ "$has_out" = yes ] && [ "$has_rc" = 0 ] || die "systemd-analyze has-tpm2 printed '$has_out' and exited $has_rc after the package install (expected yes, 0): the package lacks something the TPM needs"

# ---- the test tools, in the guest only
gt 900 "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $TOOLS" >> "$log" 2>&1 || die "apt-get install of the test tools failed in the guest"
step tools

# ---- the shared setup and the cases
sel=$(printf '%s\n' "$selection" | tr '\n' ' ')
guest_out=$tmp/guest.out
rc=0
gt 3000 "sudo env E2E_VM=1 E2E_TPM=$tpm E2E_SELECT='${sel% }' bash /e2e/guest.sh vm" 2>&1 | tee "$guest_out" | tee -a "$log" || rc=${PIPESTATUS[0]}
# the guest's E2E-PHASE lines are the times of its steps: install, service and import are the setup; a group counts when one of its cases was selected
setup=0
while read -r name secs; do
    case $name in
    install | service | import) setup=$((setup + secs)) ;;
    sign | noplain | pcr | fallback | tpmclear | upgrade)
        case $name in
        sign) pat='^sign-' ;; noplain) pat='^noplain-' ;; pcr) pat='^pcr-' ;; fallback) pat='^fallback-' ;;
        tpmclear) pat='^tpm-clear-' ;; upgrade) pat='^upgrade-kinds-' ;;
        esac
        ! grep -q "$pat" <<< "$selection" || steps+=("$name=$secs") ;;
    esac
done < <(sed -n 's/^E2E-PHASE \([^ ]*\) \([0-9]*\)$/\1 \2/p' "$guest_out")
steps+=("setup=$setup")
t0=$SECONDS
[ "$rc" -eq 0 ] || die "the guest run failed with status $rc (see $log)"
printf '%s\n' "$selection" > "$tmp/sel"
CHECK_VM=1 CHECK_TPM_MODE=$tpm bash e2e/check-cases.sh check "$LIST" e2e/vm/skip.list "$guest_out" "$tmp/sel" >> "$log" 2>&1 || { tail -n 8 "$log" >&2; die "the case accounting failed (see $log)"; }
status=0
say "passed"
