#!/usr/bin/env bash
# Sourced by e2e/vm/vm.sh and scripts/vm-host-check.sh: which swtpm the VM target runs, and whether it can take a profile.
# The dev container has swtpm 0.7.1 on PATH (no --profile) and swtpm 0.10.2 unpacked under VM_SWTPM_PREFIX (default /opt/swtpm, harness/Containerfile).
# The 0.10.2 one is used when present; otherwise the one on PATH. VM_SWTPM overrides the executable (the self-tests use it).
# shellcheck shell=bash disable=SC2034
# (SC2034: VM_SWTPM, VM_SWTPM_LIBS and VM_SWTPM_WHY are read by the scripts that source this file.)
# Sets VM_SWTPM (the executable; empty if none) and VM_SWTPM_LIBS (a LD_LIBRARY_PATH for it; empty if it needs none).

vm_swtpm_resolve() {
    local prefix=${VM_SWTPM_PREFIX:-/opt/swtpm}
    VM_SWTPM_LIBS=
    if [ -n "${VM_SWTPM:-}" ]; then
        :
    elif [ -x "$prefix/usr/bin/swtpm" ]; then
        VM_SWTPM=$prefix/usr/bin/swtpm
    else
        VM_SWTPM=$(command -v swtpm || true)
    fi
    case ${VM_SWTPM:-} in
    "$prefix"/usr/bin/*)
        # swtpm finds libswtpm_libtpms.so through a RUNPATH that points at the system path; the unpacked copy needs both directories.
        VM_SWTPM_LIBS=$prefix/usr/lib/x86_64-linux-gnu/swtpm:$prefix/usr/lib/x86_64-linux-gnu
        ;;
    esac
}

# vm_swtpm_run ARGS...: runs $VM_SWTPM with its libraries.
vm_swtpm_run() {
    if [ -n "$VM_SWTPM_LIBS" ]; then
        LD_LIBRARY_PATH=$VM_SWTPM_LIBS "$VM_SWTPM" "$@"
    else
        "$VM_SWTPM" "$@"
    fi
}

# vm_swtpm_profile_support: succeeds if $VM_SWTPM is 0.10 or newer and its `socket --help` lists --profile. On failure, sets VM_SWTPM_WHY.
vm_swtpm_profile_support() {
    # Bash builtins and grep only: vm-host-check's self-test runs with a PATH that holds nothing else.
    local v help out
    out=$(vm_swtpm_run --version 2> /dev/null || true)
    if [[ $out =~ version\ ([0-9]+)\.([0-9]+)(\.[0-9]+)? ]]; then
        v=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}${BASH_REMATCH[3]}
        if [ "${BASH_REMATCH[1]}" -lt 1 ] && [ "${BASH_REMATCH[2]}" -lt 10 ]; then
            VM_SWTPM_WHY="swtpm $v ($VM_SWTPM) is older than 0.10 and has no --profile"
            return 1
        fi
    else
        VM_SWTPM_WHY="cannot read the version of $VM_SWTPM"
        return 1
    fi
    help=$(vm_swtpm_run socket --help 2>&1 || true)
    if ! printf '%s\n' "$help" | grep -q -- '--profile'; then VM_SWTPM_WHY="swtpm $v ($VM_SWTPM) does not list --profile"; return 1; fi
    return 0
}
