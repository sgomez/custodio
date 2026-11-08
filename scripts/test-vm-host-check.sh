#!/usr/bin/env bash
# Tests of scripts/vm-host-check.sh (F150): it passes with every requirement of the VM target present (stubbed paths and tools), and for
# each requirement it fails, names exactly that one and never offers software emulation. No VM, no network, no container.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHECK=$ROOT/scripts/vm-host-check.sh
BASH_BIN=$(command -v bash)
GREP_BIN=$(command -v grep)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chmod 755 "$tmp"
fail=0
bad() { echo "test-vm-host-check: $*" >&2; fail=1; }

LABELS=(kvm-device kvm-accel qemu-system-x86_64 ovmf-code ovmf-vars swtpm seed-tool gpgv keyring)

# fresh: a stub world where everything is present. PATH holds only the stubs and grep, so the real tools of this machine never count.
fresh() {
    rm -rf "$tmp/w"
    mkdir -p "$tmp/w/bin"
    chmod 755 "$tmp/w" "$tmp/w/bin"
    ln -s "$GREP_BIN" "$tmp/w/bin/grep"
    printf '#!/bin/sh\nprintf "Accelerators supported in QEMU binary:\\ntcg\\nkvm\\n"\n' > "$tmp/w/bin/qemu-system-x86_64"
    for t in swtpm cloud-localds gpgv; do printf '#!/bin/sh\nexit 0\n' > "$tmp/w/bin/$t"; done
    chmod 755 "$tmp/w/bin/qemu-system-x86_64" "$tmp/w/bin/swtpm" "$tmp/w/bin/cloud-localds" "$tmp/w/bin/gpgv"
    : > "$tmp/w/kvm"; chmod 666 "$tmp/w/kvm"
    : > "$tmp/w/CODE.fd"; : > "$tmp/w/VARS.fd"; : > "$tmp/w/keyring.gpg"
    chmod 644 "$tmp/w/CODE.fd" "$tmp/w/VARS.fd" "$tmp/w/keyring.gpg"
}
# run [prefix...]: the check on the stub world; output in $tmp/out.
run() {
    env -i PATH="$tmp/w/bin" KVM_DEV="$tmp/w/kvm" OVMF_CODE="$tmp/w/CODE.fd" OVMF_VARS="$tmp/w/VARS.fd" KEYRING="$tmp/w/keyring.gpg" \
        "$@" "$BASH_BIN" "$CHECK" > "$tmp/out" 2>&1
}
# expect_only <label>: the run failed, names that label on a MISSING line, no other label, and says nothing of emulation.
expect_only() {
    local want=$1 l
    for l in "${LABELS[@]}"; do
        if [ "$l" = "$want" ]; then
            grep -qE "^MISSING $l:" "$tmp/out" || bad "$want: the output does not name it: $(cat "$tmp/out")"
        else
            if grep -qE "^MISSING $l:" "$tmp/out"; then bad "$want: $l is named too: $(cat "$tmp/out")"; fi
        fi
    done
    if grep -qiE 'tcg|emulat|software' "$tmp/out"; then bad "$want: the output mentions emulation: $(cat "$tmp/out")"; fi
}
control() { # control <label> <description>: the run must have failed.
    if run; then bad "$2: the check passed"; return 1; fi
    expect_only "$1"
}

fresh
if ! run; then bad "all present: the check failed: $(cat "$tmp/out")"; fi
for l in "${LABELS[@]}"; do grep -qE "^OK $l( |$)" "$tmp/out" || bad "all present: no OK line for $l: $(cat "$tmp/out")"; done
if grep -q MISSING "$tmp/out"; then bad "all present: MISSING in the output"; fi

# KVM missing.
fresh; rm "$tmp/w/kvm"; control kvm-device "kvm device missing" || true

# KVM present but not openable: mode 000, which only binds a non-root user.
fresh; chmod 000 "$tmp/w/kvm"
drop=()
if [ "$(id -u)" = 0 ]; then
    if command -v setpriv > /dev/null; then drop=(setpriv --reuid=65534 --regid=65534 --clear-groups)
    elif command -v runuser > /dev/null; then drop=(runuser -u nobody --)
    else drop=(none); fi
fi
if [ "${drop[0]:-}" = none ]; then
    echo "test-vm-host-check: SKIP kvm mode 000: running as root and neither setpriv nor runuser is available"
else
    if "${drop[@]}" "$BASH_BIN" -c "exec 3<>\"\$1\"" _ "$tmp/w/kvm" 2> /dev/null; then bad "kvm mode 000: the stub opens, the control is void"; fi
    if run ${drop[@]+"${drop[@]}"}; then bad "kvm mode 000: the check passed"; else expect_only kvm-device; fi
fi

# QEMU without KVM in its accelerators.
fresh; printf '#!/bin/sh\nprintf "Accelerators supported in QEMU binary:\\ntcg\\n"\n' > "$tmp/w/bin/qemu-system-x86_64"
control kvm-accel "qemu without kvm" || true

fresh; rm "$tmp/w/bin/qemu-system-x86_64"; control qemu-system-x86_64 "qemu missing" || true
fresh; rm "$tmp/w/CODE.fd"; control ovmf-code "OVMF code missing" || true
fresh; rm "$tmp/w/VARS.fd"; control ovmf-vars "OVMF vars missing" || true
fresh; rm "$tmp/w/bin/swtpm"; control swtpm "swtpm missing" || true
fresh; rm "$tmp/w/bin/cloud-localds"; control seed-tool "seed tool missing" || true
fresh; rm "$tmp/w/bin/gpgv"; control gpgv "gpgv missing" || true
fresh; rm "$tmp/w/keyring.gpg"; control keyring "keyring missing" || true

# Everything missing: every requirement is named once (kvm-accel needs qemu, so it is not checked then).
fresh; rm -f "$tmp/w/kvm" "$tmp/w/CODE.fd" "$tmp/w/VARS.fd" "$tmp/w/keyring.gpg" "$tmp/w/bin/"{qemu-system-x86_64,swtpm,cloud-localds,gpgv}
if run; then bad "all missing: the check passed"; fi
for l in "${LABELS[@]}"; do
    [ "$l" = kvm-accel ] && continue
    [ "$(grep -cE "^MISSING $l:" "$tmp/out")" -eq 1 ] || bad "all missing: $l is not named once: $(cat "$tmp/out")"
done
if grep -qiE 'tcg|emulat|software' "$tmp/out"; then bad "all missing: the output mentions emulation"; fi

exit "$fail"
