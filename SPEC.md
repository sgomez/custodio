# Custodio — Milestone 5: The encrypted fallback on real machines

M5 builds on the code of M0–M4 (specs and results in `docs/milestones/`, `docs/findings.md` and
`docs/findings/`, `docs/decisions.md`, `docs/api.md`, `docs/audit.md`, `docs/install.md`). Everything
those milestones established stays true unless this document says otherwise. This milestone's
features are numbered from F150.

## Problem

Since M4, a key that the TPM cannot hold is stored as a file encrypted with `systemd-creds`. M4 has
three storage kinds: `tpm`, `encrypted-tpm` and `encrypted-host`. The middle one, an encrypted file
bound to the machine's TPM, is used when a TPM is present but lacks a capability that the key type
needs. It has never been produced end to end by the real `systemd-creds` daemon on a real kernel
TPM:

- In the end-to-end containers, systemd detects the container and never seals to a TPM
  (`docs/findings/F134.md`, last section). M4 therefore accepted two deviations
  (`docs/milestones/M4/SPEC_DEVIATIONS.md`, F110 and F134). The cases of F134 (signing), F135 (no
  plaintext), F137 (PCR change and restarts), F138 (fallback kinds and CLI text), F140 (TPM cleared)
  and F141 (upgrade keeps kinds) cover `encrypted-tpm` only with integration tests and stand-ins
  for `systemd-creds`. RSA-PSS has never been checked against a credential that the real daemon
  sealed to a TPM.
- The service never chooses the key the daemon seals with. It sends a user-scoped Varlink
  `Encrypt`, and the daemon's automatic key is "host plus TPM" when the daemon finds a usable TPM
  and "host only" otherwise. That fallback is silent. The service refuses a credential whose binding
  does not match the kind it chose (the `binding_mismatch` cause), but no test has shown that guard
  working with the real daemon and a real TPM.
- Doing the same check on hardware turned up a packaging gap. systemd loads `libtss2-rc` with
  `dlopen`, and Ubuntu only *recommends* `libtss2-rc0t64`. On an install without recommends, which
  includes the Ubuntu minimal cloud image, `systemd-creds` cannot use the TPM. An import that needs
  `encrypted-tpm` then fails with a binding mismatch on a machine that should support it.
- Two items from M4 are still open. First, the claim that the systemd 257 daemon (Debian 13,
  Alma 10) binds its TPM credentials to PCR 7 was *inferred* from source and never read on a
  machine with a TPM. Second, on Ubuntu 24.04 without a TPM every import fails, because systemd
  255 gives a non-root service no host-bound credential; the service keeps a code path of its own
  for 255 (the `systemd-creds` CLI with a TPM device) only for that system. M5 drops Ubuntu 24.04
  and every system with a systemd older than 257: a project has to set a floor somewhere.

This matters now because M6 publishes the packages and writes the public threat model. Every kind
that the API, the CLI and the documentation promise must be proven on a real system first, and
the package dependencies must be right before people install them.

## Threat model

The threat model of M0–M4 holds unchanged (`docs/milestones/M4/SPEC.md`, "Threat model"). M5 adds no
new capability and no new trust. It proves part of M4's model on a real system and closes a
packaging gap.

- **In scope (as M4, now proven end to end on one target):**
  - **Silent downgrade of storage.** When `systemd-creds` cannot use the TPM for any reason
    (missing library, unusable TPM, a daemon that falls back to the host key), an import that
    needs `encrypted-tpm` must fail with the documented error. It must never store a host-bound
    credential under the `encrypted-tpm` kind or under any other kind.
  - **PCR binding.** No `encrypted-tpm` credential the service stores is bound to any PCR, so a
    `dbx` update or other PCR change never makes a key unusable.
  - **root reading the state directory, backups, copies of the disk.** As in M4: no plaintext key
    in the state directory under `encrypted-tpm`.
- **Out of scope:** everything M0–M4 exclude. Also out: attacks on the test infrastructure (the
  VM image, the hypervisor, `swtpm` on the host). That infrastructure is test-only and never
  shipped.
- **Not guaranteed:**
  - **The VM proves systemd's behaviour, not a hardware TPM's.** `encrypted-tpm` runs end to end
    on a virtual TPM only. TPM quirks of real firmware are covered only by M4's manual acceptance
    for the `tpm` kind.
  - **Fedora 44 and Arch** take the same route as Ubuntu 26.04 (systemd 259 and later, user-scoped
    Varlink, no PCR by default), but `encrypted-tpm` is not run end to end on them. Their packages
    install the TPM2 Software Stack as one package, so the dependency gap of the `.deb` does not
    apply to them. This is inferred, not run.
  - **Debian 13 and Alma 10 (systemd 257).** With a TPM present, the encrypted fallback stays
    unavailable while the daemon binds to a PCR, because the service refuses such a credential
    (M4 deviation F110). M5 replaces the inference with one manual reading on Debian 13; Alma 10 is
    stated as inferred from it.
  - **Systems with a systemd older than 257** (Ubuntu 24.04 among them) are not supported, and the
    packages refuse to install there (Design 5).

## Goal

On a real Linux system with a virtual TPM (the Ubuntu 26.04 minimal cloud image, installed without
recommends), a key whose type the TPM cannot hold gets the `encrypted-tpm` kind. The credential is
sealed by the real `systemd-creds` to that TPM with no PCR, and a test verifies this independently
of the service. The key passes every case M4 accepted only with stand-ins: every mechanism, RSA-PSS
included, no plaintext, PCR change and restarts, TPM clear, and upgrade. The packages carry every
dependency this needs, and the two remaining M4 items are settled and documented.

## Design

The product architecture does not change: `custodiod`, its unit, the D-Bus API, polkit on every
call, the journal, the PKCS#11 module and the CLI. M5 changes the packages' dependencies, removes
the service's code path for systemd 255, and updates the documentation. Most of M5 is
test infrastructure.

### 1. A VM end-to-end target

The new target runs next to the existing container targets. It is not a replacement.

- **Image.** The Ubuntu 26.04 minimal cloud image, unmodified. Before use, the harness checks the
  download against Ubuntu's signed checksums. The run record names the image serial. The image is
  cached outside the repository and never committed. A boot of the 26.04 minimal image with
  `swtpm`, `tpm-crb` and OVMF showed its `generic` kernel has the TPM drivers built in
  (`CONFIG_TCG_CRB=y`) and `/dev/tpmrm0` appears; `systemd-analyze has-tpm2` lacks only the
  `libtss2` libraries, which the package brings (section 4). A finding records that boot. The image
  ships empty apt lists, so the run needs network to install the package and its dependencies.
- **Machine.** QEMU with KVM, OVMF firmware, and a `tpm-crb` device backed by `swtpm` on the host.
  The guest therefore sees a real kernel TPM (`/dev/tpmrm0`, the ACPI TPM2 table), and systemd's
  TPM detection treats it as a real machine. The `swtpm` state persists across guest reboots
  within a run and is fresh for each run. The guest is configured on first boot by the image's
  standard mechanism (cloud-init NoCloud seed). The harness drives it over a channel that needs no
  change to the product.
- **Product under test.** The `.deb` built by `just package` is installed with the distribution's
  tool and **without recommends**. The installed unit is the shipped one. There is no test drop-in
  and no test TCTI variable (`CUSTODIOD_TEST_SWTPM_TCTI`, `docs/decisions.md`), and the run checks
  both are absent. The service reaches the TPM through `/dev/tpmrm0`, as on a person's machine.
  Test tools (the polkit test agent, `tpm2-tools`, `openssl`, the PKCS#11 consumers the cases use)
  are installed in the guest by the harness and are never dependencies of the package.
- **TPM modes.**
  - **full:** the virtual TPM unchanged. It is a control run, and both key types get kind `tpm`.
  - **lacking:** the virtual TPM is made to lack a capability that RSA 2048 needs (the capability
    list of F107/F111 in `docs/api.md`), so the RSA key gets `encrypted-tpm`; RSA is the type that
    carries the RSA-PSS cases. P-256 getting `encrypted-tpm` too is optional: the service's parent
    is an ECC P-256 primary, so removing P-256 may break the parent, systemd's sealing or the
    kernel's TPM. How the TPM is made to lack is an open question. Whatever the route, it changes
    the TPM as every guest process sees it (kernel, `systemd-creds`, the service, `tpm2-tools`),
    never the service alone, and leaves a TPM that the guest kernel and systemd use normally.
  - **The silent fallback** is one case of the lacking run, not a mode of its own (section 3).
- **Cases.** The VM reuses the existing case scripts and the existing case accounting: every case
  is reported exactly once per run, as run or skipped, and an unknown or missing case fails the run.
  The VM gets its own case list:
  - the groups of F134 (`sign-*`), F135 (`noplain-*`), F137 (`pcr-*`), F138 (`fallback-*`), F140
    (`tpm-clear-*`) and F141 (`upgrade-kinds-*`), run with `encrypted-tpm` keys;
  - the setup they need: install, service, users, key import;
  - the new checks of sections 2 and 3.

  The cases that M4 always reports skipped (`fallback-tpmbound-*`, `upgrade-kinds-tpmbound`) **run**
  in the VM and stay skipped in the containers. Where a container case uses something a VM does not
  have in the same form, the VM case uses the VM equivalent and the contract records the mapping.
  For example, "restart `swtpm`" in a container becomes a guest power cycle with the `swtpm` state
  kept. "Clear the TPM" uses the TPM's own clear command from the guest, or a fresh `swtpm` state,
  as the contract settles.
- **Record.** As for the containers: the target, the TPM mode, the image serial, the guest kernel,
  systemd, the package version, the `swtpm` version, `systemd-analyze has-tpm2` in the guest, and
  the time of each step.

Prior art worth copying: systemd's own integration tests (mkosi images booted in QEMU with OVMF and
`swtpm`); `autopkgtest-virt-qemu`; the `swtpm` documentation for QEMU (`-tpmdev emulator` with a
`tpm-crb` device); `cloud-localds` and the NoCloud datasource; and this repository's container
harness (`e2e/run.sh`, `e2e/guest.sh`, `e2e/check-cases.sh`), whose case scripts and accounting
the VM reuses.

### 2. Checking the credential's key, independently of the service

The service already reads the credential header back and refuses a nonzero PCR mask, a null key or
a binding that does not match the kind. A test that trusted that code would prove nothing about it.
So every case that expects `encrypted-tpm` also reads the stored credential itself, as root in the
guest, with the harness's **own reader**, which shares no code with the service. It checks:

- the key identifier is the one systemd uses for "host plus TPM, user-scoped" in the installed
  version, and is neither host-only nor the null key;
- the PCR mask is zero.

The identifiers and the header layout come from a finding on systemd's source for the installed
version, as F110 did for 257, 259 and 262 (the identifiers change between versions). They are not
copied from the service's code. The reader is tested on the host against credentials made by the
real `systemd-creds` (with `swtpm` in the dev container, as in F110): one TPM-bound credential,
one host-only, one with PCR 7, and one with the null key. Each must be told apart.

### 3. The silent fallback, fail-closed

One case of the lacking run hides `libtss2-rc` from systemd without removing the package (which
depends on it), for example with `dpkg-divert`, and restarts what needs it. An import that the TPM's
capabilities send to `encrypted-tpm` then fails: it returns the documented error
(`CredentialsUnavailable`), records the `binding_mismatch` cause in its journal entry, stores
nothing, and leaves no key of any kind. With the library back, the same import gives
`encrypted-tpm`.

### 4. Packaging: `libtss2-rc0t64`

- The `.deb` **depends** on `libtss2-rc0t64`, next to the TPM2 Software Stack libraries it already
  declares. A dependency, not a recommendation, because installs without recommends are exactly
  where the gap appears. The `.rpm` and the Arch package already depend on `tpm2-tss`, which ships
  every `libtss2` library.
- `docs/install.md` lists the new dependency and says why it is needed.
- The VM run installs without recommends, so it is the end-to-end proof of this section; section 3
  is the proof that the library is what makes the difference.

### 5. systemd 257 as the floor: Ubuntu 24.04 dropped

- **Packages.** Every package requires systemd 257 or later. The `.deb`'s `Pre-Depends` rises from
  255 to 257; the `.rpm` and the Arch package already require 257. On Ubuntu 24.04 the package
  manager refuses the install, naming the systemd version.
- **Service.** The credential client keeps only the user-scoped Varlink route. The 255 path (the
  `systemd-creds` CLI run with `--tpm2-device`, TPM alone) and its tests go, and so does whatever
  chooses between the two routes. No stored credential needs it: nothing is usable before M6.
- **Tests and documentation.** The `ubuntu2404` end-to-end target goes, with the cases and
  fixtures that exist only for it. `docs/install.md` states the floor and drops the Ubuntu 24.04
  `dbus-broker` section. The bus check stays: it tests `ProcessFD`, not a distribution. The glibc
  ceiling stays where it is (a stricter bound than the supported systems need); raising it is a
  separate decision.
- The coverage, CRAP and `mutants` gates hold at their thresholds over the code that remains.

### 6. The PCR mask on Debian 13, by hand

A person on Debian 13 with a TPM (hardware, or a VM with a virtual TPM; the record says which)
follows written steps that the milestone ships:

1. Confirm that systemd's TPM support is complete (`systemd-analyze has-tpm2`, with `libtss2-rc`
   installed).
2. Have the daemon seal a user-scoped credential through the same call the service makes.
3. Read the credential's key identifier and PCR mask, with the reader of section 2 or the
   documented equivalent. A credential that is not TPM-bound invalidates the reading.
4. Record the result in a finding.

The service's behaviour does not depend on the outcome, because the guard reads every credential.
Only the documentation does:

- **If PCR 7 is confirmed:** the documents that describe the kinds and the supported systems call
  it verified.
- **If it is refuted:** the same documents say `encrypted-tpm` is available on Debian 13.

Either way, Alma 10 is stated as inferred from the Debian 13 reading.

### 7. When and where the VM runs

- **Release only in CI.** The VM run is a release test. It runs for the release and its failure
  blocks the release. It never runs on an ordinary pull request or push, and the container
  end-to-end workflow is unchanged for those. CI recognises the release as the pull request whose
  head is a `milestone/*` branch, the one `just release` opens; a tag alone cannot gate it, because
  it is pushed after the merge. A person approves the new required status check.
- **Within the milestone**, the VM suite runs only in the checkpoint feature's `verify` and the
  last feature's `verify`. Other features prove their parts with host-side self-tests (the
  credential reader, the case lists and accounting, image verification with negative controls,
  argument handling) and with the container suite where a part applies there.
- **Host requirements.** The VM needs KVM on the machine that runs it. If the dev container or a
  CI runner lacks it, that is a person's decision (`BLOCKED.md`). A builder does not switch to
  software emulation silently.

## Language and harnesses

Rust for the product, as before. The VM harness is written in the languages the end-to-end harness
already uses and follows its conventions. Every harness of M0–M4 stays and keeps blocking the merge
at the same thresholds: unit, integration and end-to-end tests (the container suite on every target,
debian13 also without a TPM); `cargo-mutants` with no surviving mutant; coverage and the CRAP gate;
`cargo-fuzz`; Miri and AddressSanitizer on the FFI layer; `rustfmt` and `clippy` with the service's
restriction lints; `cargo-machete` and `cargo-deny`; `taplo`, `typos`, `shellcheck`, `actionlint`
and `zizmor`; the systemd exposure score and the unit and bus-policy checks; the package gates;
the API contract check; commitlint; and `just` as the entry point.

M5 adds, all blocking:

- **The VM end-to-end run** (Design 1–3), blocking the release, in the full and lacking modes.
  It is reachable from `just`.
- **Host-side self-tests of the VM harness**, in the same place as the other end-to-end
  self-tests: the credential reader against real `systemd-creds` fixtures, the VM case list
  against the case accounting, refusal of an image whose checksum or signature does not verify,
  and the mode handling. Each has a negative control.
- **Supply chain.** The image download is verified (Design 1) and recorded. Any new workflow
  follows the existing pinning rules (actions by commit, tools by checksum) and passes
  `actionlint` and `zizmor`.
- A package gate checks that each format requires systemd 257 or later, with a negative control.

## Scope

- The VM end-to-end target on the Ubuntu 26.04 minimal cloud image with `swtpm`, `tpm-crb` and
  OVMF. It runs the M4 cases that were deviated for `encrypted-tpm` and the new credential and
  fail-closed checks.
- The release-only CI run of the VM target, and its place in the milestone (checkpoint and last
  feature).
- The `.deb` dependency on `libtss2-rc0t64` and `docs/install.md`.
- systemd 257 as the floor: the package dependencies, the removal of the 255 code path and of the
  `ubuntu2404` target, and `docs/install.md` (Design 5).
- The written manual steps for the Debian 13 PCR reading, the reading itself, and the documentation
  updates that follow from it.
- The findings these need (the image boot, how to make the virtual TPM lack an RSA capability, the
  credential identifiers for systemd 259, KVM on the hosts).

## Out of scope

- A VM for any other distribution. On systemd 257 the kind cannot exist (the service refuses the
  PCR 7 binding), and Fedora 44 and Arch share the 259 route.
- Changing the storage choice, the kinds, the PCR guard or the credential call. If a VM case
  fails, the bug is fixed under the M4 rules, never by loosening a guard.
- Making `encrypted-tpm` available on systemd 257 with a TPM (for example a root helper, or
  accepting PCR 7).
- Running the container end-to-end suite in the VM, or replacing any container case.
- Hardware-TPM runs of `encrypted-tpm`.
- Any support for Ubuntu 24.04 or a systemd older than 257; raising the glibc ceiling; a reading on
  Alma 10.
- Everything listed for M6 and under "Unassigned" in `docs/milestones.md`, including the
  administrator setting that refuses the encrypted kinds.

## Acceptance

Automated, on the VM target (the release run and the checkpoint and last features), unless marked
host:

1. The harness boots the Ubuntu 26.04 minimal cloud image after verifying its download, and refuses
   an image whose checksum or signature fails (host self-test with a negative control). In the
   guest, `/dev/tpmrm0` exists, and after the package is installed `systemd-analyze has-tpm2`
   reports full support. The run record lists every item of Design 1, "Record".
2. The `.deb` installs without recommends. The installed unit has no drop-in and no test TCTI
   variable, and the service reaches the TPM through `/dev/tpmrm0`.
3. **full mode:** importing an RSA 2048 and a P-256 `.p12` gives kind `tpm` for both.
4. **lacking mode:** the RSA 2048 key gets kind `encrypted-tpm` in the import result, the API's
   list, `custodio list` and the import journal entry, and `custodio import` says the key is weaker
   and why (P-256 too, if the route allows it). `fallback-tpmbound-*` run and are not skipped.
5. For every `encrypted-tpm` key of 4, the harness's own reader finds the user-scoped "host plus
   TPM" key identifier of the installed systemd and a zero PCR mask in the stored credential. On
   the host, the same reader tells apart real credentials that are TPM-bound, host-only, PCR
   7-bound and null-keyed.
6. Each `encrypted-tpm` key signs through the PKCS#11 module with every mechanism the service
   offers for its type. That includes `CKM_RSA_PKCS_PSS` with each supported hash and the salt
   lengths 0, the hash length and the maximum. Every signature verifies with the key's
   certificate in `openssl`.
7. After each `encrypted-tpm` import, `scripts/check-no-plaintext.sh` finds no encoding of the
   private key in the state directory, and no unencrypted key file exists.
8. After extending PCR 7 and another PCR and restarting the service, and again after a guest power
   cycle with the `swtpm` state kept, every `encrypted-tpm` key still signs.
9. After the TPM is cleared, signing with an `encrypted-tpm` key fails with the documented error
   and a journal entry. The key is still listed and can be deleted.
10. Upgrading from package N to N+1 keeps each `encrypted-tpm` key, its owner, its certificate and
    its kind, and the key signs afterwards. `upgrade-kinds-tpmbound` runs and is not skipped.
11. **Silent fallback case:** with `libtss2-rc` hidden from systemd, an import that needs
    `encrypted-tpm` fails with `CredentialsUnavailable`. Its journal entry carries the
    `binding_mismatch` cause, the state directory holds nothing new, and no key of any kind exists
    for that id. Once systemd's TPM libraries are restored, the same import gives `encrypted-tpm`.
12. Each VM run reports every case of its case list exactly once, run or skipped. Each gap of the
    M4 F134 deviation (F134, F135, F137, F138, F140, F141 for `encrypted-tpm`, and RSA-PSS with a
    real TPM-sealed credential) maps to a VM case that ran. A person can check this from the
    contract's table and the run record.

Automated, on the host or in the container suite:

13. The `.deb` declares `libtss2-rc0t64`, and the package gates pass.
14. The container end-to-end suite passes on every target as in M4. The tpmbound cases are still
    reported skipped there.
15. CI runs the VM target for a release and the release cannot merge when it fails. CI does not
    run it on an ordinary pull request or push. This is checked by a test of the workflow
    definitions and observed on the milestone's release.
16. Every package requires systemd 257 or later, and the package gate fails on a package that
    allows less (negative control). The service seals and opens credentials only through Varlink
    (the integration and VM suites pass with the 255 path gone), the `ubuntu2404` target is gone,
    and `docs/install.md` states the floor; its steps are run as written.

Manual (a person, following written steps the milestone ships in the repository):

17. On Debian 13 with a TPM, the steps of Design 6 produce a TPM-bound credential from the daemon.
    The person reads its PCR mask and records it in a finding with the machine, the systemd
    version and whether the TPM is hardware or virtual. The documentation that describes the kinds
    and supported systems states the result as Design 6 says.

## Open questions

- **How to make the virtual TPM lack an RSA capability.** Candidates: M4's `tpm-filter`
  between QEMU and `swtpm` (QEMU's emulator backend speaks `swtpm`'s control channel and passes the
  data channel differently from the socket TCTI the filter was built for); an `swtpm`/`libtpms`
  profile that disables an algorithm, if the host's `swtpm` supports profiles (the dev container's
  0.7.1 does not); or another route. Side effects to check: the service's parent is an ECC P-256
  primary (`docs/decisions.md`), systemd chooses its own SRK type, and recent kernels may create
  an ECC P-256 primary for bus encryption. So removing P-256 may break the parent of both types,
  systemd's sealing or the kernel's TPM, and removing RSA may affect systemd's choice. Settle by a
  finding. If RSA cannot get `encrypted-tpm` without breaking the TPM for the kernel or systemd,
  that is a `BLOCKED.md` question: RSA carries the RSA-PSS cases.
- **KVM on the hosts.** Whether the dev container exposes `/dev/kvm`, and whether the CI runner
  does (GitHub reports hardware acceleration on standard Linux runners once the runner user may
  open `/dev/kvm`). Settle by a finding. A change to the dev container or the host goes to a
  person. Software emulation is a person's choice too, with its measured time.
- **Image pinning.** Should the harness pin one dated serial (reproducible, but old serials are
  removed from the mirror) or take the current release image verified by signature (current, but
  it changes under the tests)? Default: verify the signature and record the serial either way.
  Pinning is the builder's choice, recorded in `docs/decisions.md`.
- **The credential identifiers for systemd 259**, user-scoped "host plus TPM" and the others the
  reader must reject. F110 has the 257 and 262 values and some 259 values from a container, but
  not a TPM-bound one. Settle by a finding on the source and on real credentials, made with
  `swtpm` in the dev container.
- **Upgrade baseline in the VM:** N to N+1, as in M4. The last released M4 package lacks
  `libtss2-rc0t64`, so it cannot hold an `encrypted-tpm` key without recommends.
- **Research boots.** The research features above need to boot the image to answer their
  questions. Default: a research feature may boot the VM by hand and records what it ran. Only the
  checkpoint and last features run the VM suite in their `verify`.
