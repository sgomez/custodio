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
  255 gives a non-root service no host-bound credential. Nothing tells the person why, and nothing
  documents the limitation.

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
    (M4 deviation F110). M5 replaces the inference with one reading on Debian 13. The Alma 10 claim
    still rests on that Debian reading and on the shared upstream version (see Open questions).
  - **Ubuntu 24.04 without a TPM** may stay unable to import (see Design, section 5).

## Goal

On a real Linux system with a virtual TPM (the Ubuntu 26.04 minimal cloud image, installed without
recommends), a key whose type the TPM cannot hold gets the `encrypted-tpm` kind. The credential is
sealed by the real `systemd-creds` to that TPM with no PCR, and a test verifies this independently
of the service. The key passes every case M4 accepted only with stand-ins: every mechanism, RSA-PSS
included, no plaintext, PCR change and restarts, TPM clear, and upgrade. The packages carry every
dependency this needs, and the two remaining M4 items are settled and documented.

## Design

The product architecture does not change: `custodiod`, its unit, the D-Bus API, polkit on every
call, the journal, the PKCS#11 module and the CLI. M5 changes the `.deb`'s dependencies, possibly
what the CLI and journal say on Ubuntu 24.04 without a TPM, and the documentation. Most of M5 is
test infrastructure.

### 1. A VM end-to-end target

The new target runs next to the existing container targets. It is not a replacement.

- **Image.** The Ubuntu 26.04 minimal cloud image, unmodified. Before use, the harness checks the
  download against Ubuntu's signed checksums. The run record names the image serial. The image is
  cached outside the repository and never committed. If the minimal image's kernel lacks the TPM
  drivers, a finding names the image or kernel package to use instead (Open questions). The
  replacement must still install the `.deb` without recommends.
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
  - **lacking:** the virtual TPM is made to lack a capability that a key type needs (the
    capability list of F107/F111 in `docs/api.md`), so that key type gets `encrypted-tpm`. Both
    key types must get `encrypted-tpm` in some lacking run. How the TPM is made to lack is an open
    question: M4's `tpm-filter` placed between QEMU and `swtpm`, an `swtpm` profile, or another
    route. Whatever the route, it changes the TPM as every guest process sees it (kernel,
    `systemd-creds`, the service, `tpm2-tools`), never the service alone. It must still leave a
    TPM that the guest kernel and systemd use normally.
  - **broken-for-systemd:** the TPM is full, but systemd's TPM support cannot load, as when
    `libtss2-rc` is missing. This is a negative control for the silent fallback (section 3).
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

Under broken-for-systemd mode, an import that the TPM's capabilities send to `encrypted-tpm`
fails. It returns the documented error (`CredentialsUnavailable`), records the `binding_mismatch`
cause in its journal entry, stores nothing, and leaves no key of any kind. The same import then
succeeds as `encrypted-tpm` once systemd can load the TPM libraries again. Section 4 makes that
outcome the default.

### 4. Packaging: what systemd loads by `dlopen`

- The `.deb` **depends** on `libtss2-rc0t64`, next to the TPM2 Software Stack libraries it already
  declares. It is a dependency, not a recommendation, because installs without recommends are
  exactly where the gap appears.
- The list of TPM2 Software Stack libraries that systemd's TPM support loads by `dlopen` comes from
  a finding: systemd's source for each supported version, and its ELF dlopen metadata where the
  installed systemd has it. That list is recorded once. A package check fails when the declared
  dependencies of a package format do not provide every library on it. It covers each format (the
  `.rpm` and the Arch package declare `tpm2-tss`, which ships them all) and has a negative control.
  The parity, lint and glibc-ceiling gates still pass.
- `docs/install.md` lists the new dependency and says why it is needed.
- The VM run installs without recommends, so it is the end-to-end proof of this section. Section 3
  is the proof that the dependency is what makes the difference.

### 5. Ubuntu 24.04 without a TPM

On systemd 255 the service can make only a TPM-alone credential, so without a TPM every import fails
(M4 deviation F110). M5 either fixes this or documents it. The decision is made by a person on the
basis of a finding that weighs these options:

- **(a) Document as a limitation** (the conservative default). The import still fails and stores
  nothing. `custodio import` and the journal entry name the actual cause: this systemd version
  cannot give a non-root service a host-bound credential, and the machine has no TPM. They must
  not report a generic credential-service fault, and they point to the documentation.
  `docs/install.md` states the limitation and what the person can do. Any new error name or
  journal value follows the API's compatibility rule and the API contract check.
- **(b) A fix**, only if the finding shows one that keeps every M0–M4 rule. The fix must not keep
  a secret of the service's own on disk, must run no product code as root, must not widen the
  unit's access past the exposure gate, and must never weaken the kind it reports.

If the finding shows no fix that meets (b), the outcome is (a) and nobody needs to decide.

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
- **If it is refuted:** the same documents say `encrypted-tpm` is available on Debian 13, and the
  Alma 10 claim is marked as unverified.

### 7. When and where the VM runs

- **Release only in CI.** The VM run is a release test. It runs for the release and its failure
  blocks the release. It never runs on an ordinary pull request or push, and the container
  end-to-end workflow is unchanged for those. How CI recognises a release so that the VM run gates
  it is an open question. A tag is pushed after the merge, so a run triggered by the tag alone
  cannot gate the release.
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

- **The VM end-to-end run** (Design 1–3), blocking the release, in the full, lacking and
  broken-for-systemd modes. It is reachable from `just`.
- **Host-side self-tests of the VM harness**, in the same place as the other end-to-end
  self-tests: the credential reader against real `systemd-creds` fixtures, the VM case list
  against the case accounting, refusal of an image whose checksum or signature does not verify,
  and the mode handling. Each has a negative control.
- **The `dlopen` dependency check** of Design 4, with a negative control.
- **Supply chain.** The image download is verified (Design 1) and recorded. Any new workflow
  follows the existing pinning rules (actions by commit, tools by checksum) and passes
  `actionlint` and `zizmor`.
- If section 5 changes product code, its tests and `mutants` coverage follow the M4 rules (a
  mutant that reports the wrong cause is killed).

## Scope

- The VM end-to-end target on the Ubuntu 26.04 minimal cloud image with `swtpm`, `tpm-crb` and
  OVMF. It runs the M4 cases that were deviated for `encrypted-tpm` and the new credential and
  fail-closed checks.
- The release-only CI run of the VM target, and its place in the milestone (checkpoint and last
  feature).
- The `.deb` dependency on `libtss2-rc0t64`, the `dlopen` dependency check for every package
  format, and `docs/install.md`.
- Ubuntu 24.04 without a TPM: fixed or documented (Design 5).
- The written manual steps for the Debian 13 PCR reading, the reading itself, and the documentation
  updates that follow from it.
- The findings these need (kernel drivers in the image, how to make the virtual TPM lack a
  capability, the `dlopen` list, the credential identifiers for systemd 259, KVM on the hosts, the
  release trigger).

## Out of scope

- A VM for any other distribution. On systemd 257 the kind cannot exist (the service refuses the
  PCR 7 binding), and Fedora 44 and Arch share the 259 route.
- Changing the storage choice, the kinds, the PCR guard or the credential call. If a VM case
  fails, the bug is fixed under the M4 rules, never by loosening a guard.
- Making `encrypted-tpm` available on systemd 257 with a TPM (for example a root helper, or
  accepting PCR 7).
- Running the container end-to-end suite in the VM, or replacing any container case.
- Hardware-TPM runs of `encrypted-tpm`.
- Everything listed for M6 and under "Unassigned" in `docs/milestones.md`, including the
  administrator setting that refuses the encrypted kinds.

## Acceptance

Automated, on the VM target (the release run and the checkpoint and last features), unless marked
host:

1. The harness boots the Ubuntu 26.04 minimal cloud image (or the replacement a finding names)
   after verifying its download, and refuses an image whose checksum or signature fails (host
   self-test with a negative control). In the guest, `/dev/tpmrm0` exists, and after the package
   is installed `systemd-analyze has-tpm2` reports full support. The run record lists every item
   of Design 1, "Record".
2. The `.deb` installs without recommends. The installed unit has no drop-in and no test TCTI
   variable, and the service reaches the TPM through `/dev/tpmrm0`.
3. **full mode:** importing an RSA 2048 and a P-256 `.p12` gives kind `tpm` for both.
4. **lacking mode:** each key type that the TPM is made to lack gets kind `encrypted-tpm` in the
   import result, the API's list, `custodio list` and the import journal entry, and
   `custodio import` says the key is weaker and why. Over the lacking runs, both key types get
   `encrypted-tpm`. `fallback-tpmbound-*` run and are not skipped.
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
11. **broken-for-systemd mode:** an import that needs `encrypted-tpm` fails with
    `CredentialsUnavailable`. Its journal entry carries the `binding_mismatch` cause, the state
    directory holds nothing new, and no key of any kind exists for that id. Once systemd's TPM
    libraries are restored, the same import gives `encrypted-tpm`.
12. Each VM run reports every case of its case list exactly once, run or skipped. Each gap of the
    M4 F134 deviation (F134, F135, F137, F138, F140, F141 for `encrypted-tpm`, and RSA-PSS with a
    real TPM-sealed credential) maps to a VM case that ran. A person can check this from the
    contract's table and the run record.

Automated, on the host or in the container suite:

13. The `.deb` declares `libtss2-rc0t64`. The `dlopen` dependency check passes for every package
    format and fails when a library on the list is missing from a format's dependencies (negative
    control). The package gates pass.
14. The container end-to-end suite passes on every target as in M4. The tpmbound cases are still
    reported skipped there.
15. CI runs the VM target for a release and the release cannot merge when it fails. CI does not
    run it on an ordinary pull request or push. This is checked by a test of the workflow
    definitions and observed on the milestone's release.
16. Ubuntu 24.04 without a TPM, outcome (a): an import fails, stores nothing, and the CLI output
    and journal entry name the documented cause, not a generic credential-service fault. This is
    checked by an end-to-end case on Ubuntu 24.04, or, if no automated target can reach that state
    (Open questions), by a written manual step. Outcome (b): the import succeeds with the kind
    the fix gives, and the kind is reported truthfully, checked the same way. Either way,
    `docs/install.md` describes the behaviour, and its steps are run as written.

Manual (a person, following written steps the milestone ships in the repository):

17. On Debian 13 with a TPM, the steps of Design 6 produce a TPM-bound credential from the daemon.
    The person reads its PCR mask and records it in a finding with the machine, the systemd
    version and whether the TPM is hardware or virtual. The documentation that describes the kinds
    and supported systems states the result as Design 6 says.

## Open questions

- **TPM drivers in the minimal image.** The minimal cloud image ships a reduced kernel. An Ubuntu
  bug once reported the `linux-kvm` flavour built without TPM support, fixed for 22.04. It is not
  verified whether the 26.04 minimal image loads `tpm_crb`. Settle by a finding that boots the
  image with `tpm-crb` and lists `/dev/tpmrm0` and `systemd-analyze has-tpm2`. If the drivers are
  missing, the finding names the image or kernel package to use instead (the idea allows this),
  and the replacement must still install the `.deb` without recommends.
- **How to make the virtual TPM lack a capability, per key type.** Candidates: M4's `tpm-filter`
  between QEMU and `swtpm` (QEMU's emulator backend speaks `swtpm`'s control channel and passes the
  data channel differently from the socket TCTI the filter was built for); an `swtpm`/`libtpms`
  profile that disables an algorithm, if the host's `swtpm` supports profiles (the dev container's
  0.7.1 does not); or another route. Side effects to check: the service's parent is an ECC P-256
  primary (`docs/decisions.md`), systemd chooses its own SRK type, and recent kernels may create
  an ECC P-256 primary for bus encryption. So removing P-256 may break the parent of both types,
  systemd's sealing or the kernel's TPM, and removing RSA may affect systemd's choice. Settle by a
  finding. If one key type cannot get `encrypted-tpm` without breaking the TPM for the kernel or
  systemd, that is a `SPEC_DEVIATIONS.md` entry with the finding, and the other type carries the
  cases.
- **KVM on the hosts.** Whether the dev container exposes `/dev/kvm`, and whether the CI runner
  does (GitHub reports hardware acceleration on standard Linux runners once the runner user may
  open `/dev/kvm`). Settle by a finding. A change to the dev container or the host goes to a
  person. Software emulation is a person's choice too, with its measured time.
- **How CI recognises the release.** Candidates: a job on the release pull request (the head
  branch of `just release`), or a status set by `just release` after a local VM run, as
  `signoff/ci` and `signoff/mutants` are today. The requirement is that it blocks the merge. Settle
  in the CI feature's contract. A person approves any new required status check.
- **Image pinning.** Should the harness pin one dated serial (reproducible, but old serials are
  removed from the mirror) or take the current release image verified by signature (current, but
  it changes under the tests)? Default: verify the signature and record the serial either way.
  Pinning is the builder's choice, recorded in `docs/decisions.md`.
- **The credential identifiers for systemd 259**, user-scoped "host plus TPM" and the others the
  reader must reject. F110 has the 257 and 262 values and some 259 values from a container, but
  not a TPM-bound one. Settle by a finding on the source and on real credentials, made with
  `swtpm` in the dev container.
- **Upgrade baseline in the VM.** M4's F141 upgrades between two builds of the same tree (N to
  N+1). Upgrading from the last released M4 package would also exercise the new dependency
  arriving on upgrade. But that package lacks `libtss2-rc0t64`, so without recommends its
  `encrypted-tpm` keys cannot exist before the upgrade. Default: N to N+1, as in M4. A person may
  ask for both.
- **Research boots.** The research features above need to boot the image to answer their
  questions. Default: a research feature may boot the VM by hand and records what it ran. Only the
  checkpoint and last features run the VM suite in their `verify`.
- **Ubuntu 24.04: fix or document, and how to test it.** Settle the choice by the finding and the
  person's decision of Design 5. The `ubuntu2404` container target is refusal-only (its default bus
  has no `ProcessFD`). Whether it can switch to `dbus-broker` inside a container, as
  `docs/install.md` tells a person to do, decides whether acceptance 16 is an automated case or a
  manual step.
- **Alma 10.** RHEL patches systemd. Whether the Debian 13 reading also stands for Alma 10's
  257, or Alma 10 needs its own reading, is not settled. Default: the documentation states the
  Alma 10 claim as inferred unless it is read there too.
- **Not in the idea, found during M4 (`docs/findings/F149.md`).** The purge of pre-M4 keys looks
  only inside `<uid>/` directories, so key files in the M0–M2 top-level layout survive an
  upgrade. The person judged it not serious before M5. Whether M5 fixes it, or it waits, is the
  person's call when approving this spec.
