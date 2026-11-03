Milestone: M4

M4 moves the keys into the TPM, so that root, a backup of `/var/lib` or a stolen disk cannot copy
them, as the report's second grade describes (`docs/reports/polkit-custodian-linux.md`, sections 4
and 8). Import wraps the key with `TPM2_Import` through `tss-esapi` under a parent in the owner
hierarchy; the service keeps only the wrapped blob, the certificate and the owner in its state
directory, and signs inside the TPM. Imported keys have an empty `authPolicy`, so `TPM2_Duplicate`
fails and they cannot leave the TPM again; no PCR policy, because PCR 7 also measures `dbx`, which
`fwupd` updates, and a key that stops loading cannot be imported again without the `.p12`; no PIN
either, because polkit is already the barrier. When there is no TPM, or it lacks the key's algorithm
or a hash a mechanism needs, the key goes to a file encrypted with `systemd-creds`, bound to the TPM
when there is one and to the host key otherwise; this is weaker, because the key is decrypted in the
service's memory to sign and root can take it, and the CLI and the API say which storage each key
uses. Custodio only runs in test VMs and nothing is usable before M5, so there is no migration:
keys from earlier milestones are purged, and no key remains unencrypted on disk. Tests run against `swtpm`; acceptance is repeated by hand on
a machine with a hardware TPM and a VM without one, checking with `tpm2-tools` that duplication
fails, and that the keys survive a reboot, a package upgrade and a `fwupd` `dbx` update.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F104.
