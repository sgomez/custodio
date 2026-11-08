# BLOCKED — F150 needs a person

F150 is built and committed; it passes only on a rebuilt dev container with `/dev/kvm`.

1. Rebuild the dev container (`harness/run.sh` rebuilds `custodio-dev` from `harness/Containerfile`, which now installs qemu, OVMF, cloud-image-utils, ubuntu-keyring, gpgv).
2. From the **host** that runs the engine, paste `ls -l /dev/kvm; id` (on a Mac: `podman machine ssh 'ls -l /dev/kvm; id'`) so the finding can mark the host facts **verified**.
3. If the host has no `/dev/kvm` (for example a podman machine without nested virtualisation), options: (a) a host that offers KVM; (b) software emulation, your decision with its measured time; `run.sh` adds the device only if `/dev/kvm` exists where it runs, so on a Mac with a podman machine, tell me if it must be unconditional.
4. If the device is mode 0660 `root:kvm`, the user must be in `kvm`; `run.sh` passes `--group-add keep-groups`.

Then run `just vm-host-check` in the rebuilt container; it must exit 0.
