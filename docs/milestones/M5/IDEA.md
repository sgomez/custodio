Milestone: M5

M5 closes the gaps that M4 accepted as deviations for the `encrypted-tpm` kind
(`docs/milestones/M4/SPEC_DEVIATIONS.md`, F110 and F134): in containers systemd never seals to a
TPM, so that kind has never been proven end to end, only with stand-ins for `systemd-creds`. M5 adds
one end-to-end target on a VM, the Ubuntu 26.04 minimal cloud image with a virtual TPM (`swtpm`,
`tpm-crb`, OVMF), where systemd 259 seals with no PCR, the route of Fedora 44 and Arch too; the
cases of F134, F135, F137, F138, F140 and F141 run there with `encrypted-tpm`, RSA-PSS included, and
check the credential's key, since `auto` falls back to the host key silently when the TPM is
unusable. The VM is costly, so CI runs it only on the release, never on each PR, and within the
milestone only at the checkpoint and the last feature; no other distribution gets a VM, because on
systemd 257 the kind cannot exist. The same check found a packaging gap that M5 fixes: the `.deb`
lacks `libtss2-rc0t64`, which systemd loads by `dlopen` and Ubuntu only recommends, so on an install
without recommends an import that needs `encrypted-tpm` fails. Two smaller items: a person reads
once, on Debian 13 with a TPM, the PCR mask of a credential the daemon seals, to confirm or refute
the inferred PCR 7 binding; and Ubuntu 24.04 without a TPM, where import fails because systemd 255
gives a non-root service no host-bound credential, is fixed or documented as a limitation.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F150.
