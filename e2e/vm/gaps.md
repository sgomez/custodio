# VM gap table

SPEC M5 acceptance 12: each gap of the M4 deviation (`docs/milestones/M4/SPEC_DEVIATIONS.md`, F134) maps to VM cases
that run in `lacking` (kind `encrypted-tpm`, credential read by the harness reader) and in `full` as control. Read by
`e2e/vm/gap-map.sh`; format `gap | cases`, one row per line.

```gap-table
F134 signing under encrypted-tpm, end to end | sign-kind-matches-mode sign-rsa-pkcs sign-rsa-composed sign-ec-ecdsa sign-ec-composed
F134 RSA-PSS with a real TPM-sealed credential, every hash and salt length | sign-rsa-pss-sha256 sign-rsa-pss-sha384 sign-rsa-pss-sha512
F135 no plaintext key in the state directory for encrypted-tpm | noplain-rsa noplain-ec noplain-no-key-file
F137 encrypted-tpm keys sign after a PCR change, a service restart and a guest power cycle | pcr-extended-signs pcr-restarted-signs pcr-signs-every-key
F138 the tpmbound fallback cases run, import and list say weaker and why | fallback-tpmbound-import fallback-tpmbound-cli-list tpm-kind-import-rsa tpm-kind-api-list tpm-kind-cli-list tpm-kind-journal
F140 after a TPM clear, signing fails with an entry, the key stays listed and deletable | tpm-clear-sign-fails tpm-clear-keys-listed tpm-clear-delete
F141 an upgrade keeps encrypted-tpm keys, owners, certificates and kinds | upgrade-kinds-before upgrade-kinds-kept upgrade-kinds-signs upgrade-kinds-tpmbound
```
