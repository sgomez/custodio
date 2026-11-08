#!/usr/bin/env bash
# What the VM target needs on the machine that runs it (SPEC "Host requirements"): KVM the current user can open, QEMU with KVM, the OVMF
# files, swtpm, a NoCloud seed tool, gpgv and the Ubuntu cloud image keyring. Prints one OK or MISSING line per requirement and exits
# non-zero if any is missing. It never falls back to another way of running the VM: that is a person's decision (BLOCKED.md).
# The paths can be overridden (the self-test stubs them); the defaults are those of Debian trixie's packages (docs/findings/F150.md).
set -u
KVM_DEV=${KVM_DEV:-/dev/kvm}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
KEYRING=${KEYRING:-/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg}
here=${BASH_SOURCE[0]%/*}
# shellcheck source=e2e/vm/swtpm-path.sh
. "$here/../e2e/vm/swtpm-path.sh"
rc=0
ok() { printf 'OK %s\n' "$1"; }
missing() { printf 'MISSING %s: %s\n' "$1" "$2"; rc=1; }

# Opened read-write for real: a mode, a nodev mount or a device cgroup that refuses it all fail here.
if [ ! -e "$KVM_DEV" ]; then
    missing kvm-device "$KVM_DEV does not exist (dev container: harness/run.sh --device; host: KVM enabled)"
elif ! (exec 3<> "$KVM_DEV") 2> /dev/null; then
    missing kvm-device "$KVM_DEV exists but the current user cannot open it read-write (group or mode)"
else
    ok kvm-device
fi

if command -v qemu-system-x86_64 > /dev/null; then
    ok qemu-system-x86_64
    if qemu-system-x86_64 -accel help 2> /dev/null | grep -qw kvm; then
        ok kvm-accel
    else
        missing kvm-accel "qemu-system-x86_64 -accel help does not list kvm"
    fi
else
    missing qemu-system-x86_64 "not installed (package qemu-system-x86)"
fi

if [ -f "$OVMF_CODE" ]; then ok ovmf-code; else missing ovmf-code "$OVMF_CODE not found (package ovmf)"; fi
if [ -f "$OVMF_VARS" ]; then ok ovmf-vars; else missing ovmf-vars "$OVMF_VARS not found (package ovmf)"; fi
vm_swtpm_resolve
if [ -n "$VM_SWTPM" ]; then
    ok swtpm
    # The lacking mode needs a profile (docs/findings/F152.md): swtpm 0.10 or newer; the container unpacks 0.10.2 under /opt/swtpm.
    if vm_swtpm_profile_support; then
        ok swtpm-profile
    else
        missing swtpm-profile "$VM_SWTPM_WHY (the lacking mode cannot start; harness/Containerfile adds 0.10.2)"
    fi
else
    missing swtpm "not installed (package swtpm)"
fi
if command -v cloud-localds > /dev/null; then ok seed-tool; else missing seed-tool "cloud-localds not installed (package cloud-image-utils)"; fi
if command -v gpgv > /dev/null; then ok gpgv; else missing gpgv "not installed (package gpgv)"; fi
if [ -f "$KEYRING" ]; then ok keyring; else missing keyring "$KEYRING not found (package ubuntu-keyring)"; fi
exit "$rc"
