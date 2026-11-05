# F134 blocked: `lacking` cannot give `encrypted-tpm` in the debian13 container

The evaluator requires `lacking` to produce `encrypted-tpm` for at least one key type (SPEC acceptance 6), with `sign-kind-matches-mode` expecting it exactly. Two things stand in the way
(`docs/findings/F134.md`, last section):

1. The F131 `lacking` filter removes RSAPSS, which no key needs, so keys stay `tpm`. Removing RSA (`alg=0x1`) is a real lack (needs changes to `e2e/tpm-lib.sh` and its `tpm_observe`, F131's).
2. With a real lack the import ends with `CredentialsUnavailable`: the service seals through Varlink to the root `systemd-creds@.service`, and that daemon refuses the TPM in a container
   (`System lacks TPM2 support or running in a container`; `has-tpm2`: `-firmware -driver -subsystem`). A non-root CLI with `--tpm2-device` needs polkit. Nothing in this repository can change that.

Options (a person chooses):
- A. Change the e2e route so the creds daemon sees the TPM: a fake ACPI/sysfs TPM (`/sys/firmware/acpi/tables/TPM2`, `/sys/class/tpmrm` content) in the privileged container, or a wrapper replacing
  `systemd-creds@.service`'s command in the test only. Needs a decision on how far the harness may fake the host; I did not get `has-tpm2` to pass with a bind-mounted TPM2 table.
- B. Run the `lacking` mode on a VM or host with a real `/dev/tpmrm0` and EFI/ACPI TPM2 (changes the host/dev container).
- C. Record a deviation for the `encrypted-tpm` kind under signing in containers, with the finding as proof, and keep `lacking` == RSAPSS removed (then the lacking run adds nothing over `swtpm`;
  the evaluator rejected this; a person decides). F138 (fallback kinds) hits the same wall.

State: cases `sign-*` are committed and pass in `swtpm`, `none` and `lacking` (the last with `tpm`/`tpm`). The contract (amendment 2 withdrawn, last run step unticked) expects `encrypted-tpm`
under `lacking`, so `sign-kind-matches-mode` fails there until one option is taken.
