# Custodio — Milestone 4: Keys in the TPM

M4 builds on the code of M0–M3 (specs and results in `docs/milestones/`, `docs/findings.md`,
`docs/decisions.md`, `docs/api.md`, `docs/audit.md`). Everything those milestones established
stays true unless this document says otherwise. This milestone's features are numbered from F104.

## Problem

Custodio holds the signing keys of people who sign with FNMT certificates on Linux. Since M3 each
key belongs to the uid that imported it, and every use or change of a key needs a polkit approval.
But the private key itself is still a plain file in the service's state directory, readable by the
service's uid. So the guarantee ends at "a process of the person's uid cannot copy the key", the
first grade of `docs/reports/polkit-custodian-linux.md` (section 8). Today:

- **root** can read the key file and copy the key;
- **a backup of `/var/lib`** carries the key in the clear;
- **a stolen or discarded disk** gives the key to whoever reads it.

The report's second grade ("Key in the TPM", sections 4 and 8) closes these three: a key imported
with `TPM2_Import` is wrapped so that only that TPM can load it, and with an empty `authPolicy` it
cannot be duplicated out again. Root can still *use* the key while it has the machine, but no one
can *copy* it.

This matters now because the storage format and the hardening of the unit can still change freely:
Custodio only runs in test VMs and nothing is usable before M5. After M5 the format becomes
something people depend on, and a change of storage would need a migration that M4 can still
avoid.

## Threat model

The threat model of M0–M3 still holds. M4 changes it as follows.

- **In scope (new):**
  - **root reading the state directory**, and anything root can read (a backup of `/var/lib`, a
    copy of the disk). For a key in the TPM, nothing in the state directory, alone or together with
    anything else on the disk, lets anyone reconstruct the private key or use it on another
    machine.
  - **A stolen or discarded disk** without the machine's TPM: as above.
  - **An attempt to take a key out of the TPM** with the TPM's own commands (`TPM2_Duplicate`, by
    anyone, root included): it must fail for every key Custodio imported into the TPM.
  - **A firmware update** that changes PCR values (for example a `dbx` update by `fwupd`): it must
    not make any key unusable.
  - **Downgrade of the storage**: a fault or misconfiguration must never make the service silently
    store a key with weaker protection than the machine can give. The weaker storage is chosen only
    for the reasons this spec lists, and its use is always visible.
- **Out of scope:** everything M0–M3 exclude (a hostile process of the same uid, a compromised
  kernel, tampering with the journal), except that root reading files is now partly in scope as
  above. Still out: root *using* a key while it controls the running machine; physical attacks on
  the TPM or its bus (interposers, fault injection, decapping); firmware TPM vulnerabilities; side
  channels on the TPM.
- **Not guaranteed:**
  - **Root can use a TPM key.** The key has no PIN and no PCR policy, by design (polkit is the
    barrier for use), so root, or anyone else who can talk to the TPM and read the state directory,
    can load the wrapped blob and sign with it on that machine. Root cannot copy it.
  - **Whoever takes the whole machine can use the keys** (disk and TPM together), unless the disk
    is encrypted. Full-disk encryption is the person's protection here; M5 warns about it.
  - **Fallback storage protects less** (section 2 of Design). With the file encrypted with
    `systemd-creds`, the key is decrypted in the service's memory to sign, so root can take it. When
    it is bound to the host key and not to a TPM, a backup of `/var/lib` or a copy of the disk
    carries both the encrypted key and the host key, so it protects against almost nothing beyond
    a copy of the state directory alone.
  - **Clearing the TPM destroys its keys.** A TPM clear (by the person, the firmware setup, some
    firmware updates of firmware TPMs, or a motherboard replacement) changes the owner hierarchy,
    and every key wrapped under it, and every fallback key bound to it, can no longer be loaded.
    Keys cannot be exported, by design, so the only recovery is importing the `.p12` again.
    Fallback keys bound to the host key are lost with the host key or a change of machine-id.
  - **Import is still the weak point.** The `.p12` and its password pass through the person's
    session and, once, through the service's memory (report, section 4). If the original `.p12`
    stays on disk, Custodio protects nothing.
  - **Pre-M4 key files are deleted, not erased.** Their bytes may survive in filesystem blocks,
    snapshots or backups made before M4 (M3's rule for deletion).

## Goal

On a machine with a TPM that supports the key's algorithm, every imported key lives only as a blob
wrapped by that TPM, signs inside it, survives reboots, package upgrades and `dbx` updates, and
cannot be duplicated out. Elsewhere, the key is stored encrypted with `systemd-creds`, and the CLI,
the API and the journal always say which storage each key uses; no key is ever stored unencrypted.

## Design

The architecture stays: `custodiod` on the system bus as `com.rfirma.Custodio1` under its hardened
unit; the documented M3 API; per-uid ownership; polkit for every sign, import, delete and replace
certificate; one journal entry per authorized call; the PKCS#11 module and the CLI as clients of
the documented API only. M4 changes what the store holds and where the private-key operation runs.

### 1. Storage kinds

Each key has exactly one **storage kind**, chosen at import and never changed afterwards:

| Kind | Where the private key is | Who can copy it |
|---|---|---|
| **TPM** | Only inside the TPM; the state directory holds a blob that only this TPM can load | Nobody (grade 2 of the report) |
| **Encrypted, TPM-bound** | A file encrypted with `systemd-creds`, with a key bound to this machine's TPM | root, while the machine runs (it is decrypted in the service's memory) |
| **Encrypted, host-bound** | A file encrypted with `systemd-creds` with the host key | root; anyone with a backup or copy of `/var/lib` |

There is no fourth kind: no key is ever written to disk unencrypted, temporary files included.

The kind is part of the public API and of the journal: its values are chosen once, documented in
the client documentation and `docs/audit.md`, and from then on only added to, under the existing
compatibility rule. The API contract check covers them.

### 2. Choosing the kind at import

After polkit approves the import and the `.p12` has been decrypted (M3's order stays), the service
chooses:

1. **TPM**, when a TPM is reachable and supports the key's algorithm and every hash that some
   mechanism the service offers for that key type needs (see 4). The capabilities each key type
   needs are listed once in the documentation, from a finding, and the check asks the TPM for
   exactly those.
2. **Encrypted, TPM-bound**, when a TPM is reachable but lacks one of those capabilities.
3. **Encrypted, host-bound**, when the machine has no TPM.

**Only these reasons choose a weaker kind.** "No TPM" means the platform exposes no TPM device;
"lacks" means the TPM answered a capability query and the capability is absent. Any other failure
(the device exists but cannot be opened, a TPM error during import, an owner hierarchy the service
cannot use, the credential service unavailable) fails the import with a documented error and
stores nothing. It never falls through to a weaker kind. A person can see why from the journal.

The import result says which kind was chosen. The `.p12`, the password and the decrypted key stay
in `secrecy`/`zeroize` types, as today, and are dropped as soon as the key is stored.

### 3. TPM keys

- **Import.** The key is imported with `TPM2_Import` under a parent key in the **owner (storage)
  hierarchy**, through `tss-esapi`. The parent and how it is obtained are an open question
  (persistent SRK or a primary recreated from a fixed template); whichever is chosen, it must
  survive reboots and package upgrades without the service storing any secret of its own, and the
  service must detect that a stored blob belongs to a different parent rather than try to use it.
- **Attributes of the imported key**, all required, all checkable with `tpm2_readpublic`:
  - an **empty `authPolicy`**, so `TPM2_Duplicate`, which always needs a policy session, can never
    be authorized;
  - an **empty `authValue`** and no PIN: polkit is the barrier for use;
  - **no PCR policy** of any kind: PCR 7 also measures `dbx`, which `fwupd` updates, and a key that
    stops loading cannot be imported again without the `.p12`;
  - a signing key, with the scheme freedom the mechanisms of section 4 need, and no more usages
    than those (whether that includes the `decrypt` attribute is an open question).
- **What the state directory keeps** for a TPM key: the wrapped blob (the public and private areas
  the TPM returned), enough to identify the parent, the certificate, the owner and the kind.
  Nothing else; in particular nothing from which the private key could be recomputed.
- **Signing** loads the key into the TPM and signs there. The private key is never in the
  service's memory after import. TPM objects and sessions the service creates for a call are
  released by the end of that call, whatever the outcome, so no number of calls can exhaust the
  TPM's slots.
- **Device access** goes through the kernel's TPM resource manager, never the raw device. The unit
  gains only the access this needs. The exposure score gate keeps its current threshold; how the
  unit reaches the device without loosening it is an open question.
- **A blob that does not load** (TPM cleared, a different machine, a different parent) makes sign
  fail with a documented error and its journal entry. The service does not fall back, does not
  delete the key, and keeps listing it, so the person can see it and delete it.

Prior art: `tpm2_import` and `tpm2_load` in `tpm2-tools` (the report's pending experiment 8);
`tpm2-pkcs11`, which signs with imported keys through ESAPI; `systemd-cryptenroll`, which uses the
SRK in the owner hierarchy.

### 4. Mechanisms on a TPM key

Every mechanism the service offers today for a key type (`CKM_RSA_PKCS` with a caller-supplied
payload, `CKM_RSA_PKCS_PSS` with the requested hash and salt length, `CKM_ECDSA`, and the
composed mechanisms the module builds on them) must give the same result for a TPM key as for an
encrypted one: a signature that verifies with the certificate, under the same bounds and the same
errors. Two points are known to be hard and are open questions:

- `TPM2_Sign` with the RSASSA scheme takes a hash and a digest, not an arbitrary `DigestInfo`
  payload, and with the RSAPSS scheme it does not take a salt length; TPMs disagree on the salt
  they use (the TPM 2.0 structures specification has said "the largest salt that fits", libtpms
  and some firmware use the hash length). TLS 1.3, which Firefox uses here, requires the salt to be
  the hash length.
- The service truncates SHA-384 and SHA-512 digests for P-256 (`docs/decisions.md`); whether a TPM
  key then needs SHA-384/512 support from the TPM depends on how the digest is handed to it.

If a mechanism cannot be served by the TPM for a key type on a given TPM, that key type on that
TPM falls under "lacks a capability" (section 2) and is stored encrypted, TPM-bound. A mechanism is
never silently dropped or changed for a TPM key.

### 5. Encrypted keys (fallback)

- The key is encrypted with `systemd-creds` (directly or through its Varlink interface; the service
  is not root, and the host key is readable only by root, so how the service reaches it is an open
  question). It is bound to the TPM when there is one and to the host key otherwise, and **never
  to any PCR**, explicitly, whatever the default of the systemd version installed.
  Deviation (`SPEC_DEVIATIONS.md`, F110): on systemd 257 (Debian 13, Alma 10) the service cannot
  choose the PCRs, so it refuses any credential bound to a PCR, and the TPM-bound kind is not
  available there; on systemd 255 (Ubuntu 24.04) there is no host-bound kind, so import fails
  without a TPM. Follow-up in M4.1.
- The encrypted file is the only form on disk. To sign, the service decrypts the key into
  `secrecy`/`zeroize` memory for that one signature and drops it afterwards; it keeps no decrypted
  key between calls.
- A credential that cannot be decrypted (TPM cleared, host key changed) behaves like a TPM blob
  that does not load (section 3).
- Prior art: services that keep secrets with `systemd-creds` and `LoadCredentialEncrypted=`
  (`systemd.exec(5)`); Custodio cannot use that directive, because keys arrive at run time.

### 6. State and the end of pre-M4 keys

- The state format may change freely in M4. Per key it records: owner, id, kind, certificate, and
  the protected key (TPM blob or encrypted credential). The store's existing rules apply to every
  new file: exact modes, owner checks, no symlinks, refuse rather than repair, atomic writes that
  never overwrite silently. Delete, replace certificate and concurrent imports keep M3's atomicity.
- **No migration.** Keys stored by earlier milestones are **purged**: once an M4 build runs, no key
  file of the old format remains in the state directory, and those keys are gone from the API. Each
  purged key leaves a journal entry (owner, id, and that it was purged), documented in
  `docs/audit.md`. The service does not answer calls before the purge is complete. Whether the
  service or the package scripts do it is a builder choice, but it must hold for every package
  format and for the service started without an upgrade.
- **Upgrades between M4 builds** keep keys, owners, certificates and kinds, as M2/M3's upgrade
  tests require.
- **Removal and purge** of the package keep M2's behaviour for the state directory. TPM blobs left
  behind are useless without the TPM; nothing is written into the TPM's persistent storage that
  removal would need to clean, unless the parent open question settles on that, in which case
  removal's handling of it is documented.

### 7. What clients see

- **API.** Import returns the kind next to the key type. List returns the kind of each key. A
  failure of the TPM or of the credential service has a documented error name (the existing
  internal/storage error, or new names added under the compatibility rule). The client
  documentation explains each kind and what it protects against, in the words of this spec's
  threat model.
- **CLI.** `custodio import` says which kind the key got, and when it is not TPM, says plainly that
  the key is weaker and why (no TPM, or the TPM lacks what the key needs). `custodio list` shows
  the kind of each key.
- **PKCS#11 module.** No visible change is required; it keeps every M1–M3 guarantee.
- **Journal.** The import entry names the kind. Sign entries keep their fields; a sign that fails
  because a key no longer loads has its own documented outcome or error.

## Language and harnesses

Rust, as before. `tss-esapi` and the TPM2 Software Stack it links are new dependencies; the
service's own code adds no `unsafe` (the existing `forbid(unsafe_code)` outside the PKCS#11 FFI
layer stays). Every harness of M0–M3 stays and keeps blocking the merge with the same thresholds:
unit and integration tests on a private bus with fake polkit; end-to-end tests on every supported
target (scope below); `cargo-mutants` with no surviving mutant; coverage report and the CRAP gate; `cargo-fuzz`;
Miri and AddressSanitizer on the FFI layer; `rustfmt`, `clippy` with the service's restriction
lints; `cargo-machete`, `cargo-deny`; `taplo`, `typos`, `shellcheck`, `actionlint`, `zizmor`; the
systemd exposure score at its current threshold and the unit and bus-policy checks; the package
gates (parity, linters, glibc ceiling); the API contract check and the dependency check of M3;
commitlint; `just` as the entry point.

M2/M3's upgrade tests change on one point: they upgrade between two M4 builds and must keep keys
and their kinds. One added upgrade test starts from an M3 build and checks the purge (section 6).

M4 adds, all blocking:

- **End-to-end scope.** `just e2e` runs on every supported target with `swtpm`. A case runs on
  every target only when what it checks depends on the distribution: the package format and its
  scripts, systemd, polkit and its agent, the bus daemon, journald, or a PKCS#11 consumer the
  distribution ships (OpenSC, NSS, pkcs11-provider). A case whose outcome depends only on the TPM
  or the key kind runs on debian13. The run without a TPM is on debian13 only: the TPM mode changes
  only the kind a key gets on import. The upgrade from the old-path package runs on one target per
  package format. Self-tests of the test helpers that need no installed system run on the host,
  not in each container. Each run records the time of each of its steps.
- **TPM tests against `swtpm`.** Integration and end-to-end tests run the TPM path against
  `swtpm`, not a mock, for both key types and every mechanism; each signature is verified with the
  certificate by an independent implementation. The same suites run with no TPM (host-bound
  fallback) and with a TPM lacking a needed capability (TPM-bound fallback; for example an `swtpm`
  profile that disables an algorithm, or a documented replacement if the installed `swtpm` cannot).
  Deviation (`SPEC_DEVIATIONS.md`, F134): in the containers systemd never seals to a TPM, so the
  TPM-bound kind runs only in integration tests with a stand-in for `systemd-creds`, not end to
  end. Follow-up in M4.1.
- **No-plaintext check.** After each import, under every kind, a test searches the whole state
  directory for the private key in every encoding the test can produce (raw scalar or primes,
  PKCS#1, PKCS#8, SEC1, the `.p12` itself) and fails on any match.
- **Duplication check.** For every TPM key, a test uses `tpm2-tools` on the stored blob: the public
  area shows an empty `authPolicy`, `tpm2_duplicate` fails, and the blob does not load in a second,
  independent `swtpm`.
- **No PCR dependency.** A test extends PCR 7 (and other PCRs) in `swtpm` after import, and every
  key, TPM and TPM-bound, still signs.
- **Storage choice tests.** Tests through a replaceable TPM access point inject each failure that
  is not a listed reason (device present but unopenable, TPM errors, credential service down) and
  check that import fails and stores nothing. Mutation testing covers the storage choice, so a
  mutant that falls back on the wrong condition is killed.
- **Resource test.** More signatures and imports in a row than the TPM has object slots all
  succeed.
- **Fuzzing.** Targets for every parser of stored state (TPM blob and credential framing as the
  service reads them back from disk) and for any new parsing of signing input the TPM path adds.
- **Supply chain.** `cargo-deny` accepts the new crates under the existing policy; the packages
  declare the TPM2 Software Stack libraries each target needs, and the parity, lint and glibc
  ceiling gates pass with them.

## Scope

- Import into the TPM with `TPM2_Import` under an owner-hierarchy parent, signing in the TPM, with
  the key attributes of section 3.
- Fallback storage with `systemd-creds`, TPM-bound or host-bound, never PCR-bound.
- The storage kind in the API, the CLI, the client documentation and the journal.
- The unit and the packages changed so the service can reach the TPM and the credential service
  on every supported target of M2.
- Purge of pre-M4 keys; a new state format.
- Tests against `swtpm`; the written manual acceptance steps for a hardware TPM and a VM without
  one.

## Out of scope

- Migration of existing keys into the TPM (listed in `docs/milestones.md`, dropped by this
  milestone's idea: there are no keys worth keeping).
- Moving a key between kinds after import, or re-wrapping keys when a TPM appears later.
- A PIN or `authValue` on TPM keys; PCR policies, signed policies, `systemd-pcrlock`.
- Keys born in the TPM (`C_GenerateKeyPair`, CSR), grade 3.
- Key export, backup or recovery after a TPM clear.
- New key types (RSA 3072/4096, P-384) or new mechanisms.
- An administrator setting that forces a kind (see open questions).
- The encrypted-disk warning, `SECURITY.md`, and publishing (M5).

## Acceptance

Automated (integration tests and `just e2e` with `swtpm`, on the targets the end-to-end scope in
"Language and harnesses" gives each case):

1. With a TPM, importing an RSA 2048 and a P-256 `.p12` gives kind TPM in the import result, in
   the API's list and in `custodio list`, and the import journal entry names the kind.
2. Each of those keys signs with every mechanism the service offers for its type (PSS with each
   supported hash and salt length), and every signature verifies with the key's certificate.
3. After every import, under each kind, the state directory contains none of the encodings of the
   private key listed in Harnesses, and no unencrypted key file.
4. For each TPM key, `tpm2_readpublic` on the stored public area shows an empty `authPolicy`, and
   `tpm2_duplicate` on the loaded key fails. The blob does not load in a different `swtpm`.
5. After extending PCR 7 and restarting both `swtpm` and the service, every key (TPM and
   TPM-bound) still signs. Upgrading from one M4 build to the next keeps keys, owners,
   certificates and kinds.
6. With no TPM, import gives kind "encrypted, host-bound"; with a TPM lacking a needed capability,
   "encrypted, TPM-bound". In both, `custodio import` says the key is weaker and why, and the keys
   sign as in 2. The TPM-bound half, and the TPM-bound keys of 3, 5 and 8, are proven by
   integration tests only (`SPEC_DEVIATIONS.md`, F134).
7. With a TPM device present but failing in each injected way of Harnesses, import fails with the
   documented error, stores nothing, and leaves one journal entry; no key ends up in a weaker kind.
8. After the TPM is cleared, signing with a TPM key and with a TPM-bound key fails with the
   documented error and a journal entry; the keys are still listed and can be deleted.
9. Upgrading from an M3 build with keys: after the upgrade the state directory has no file of the
   old format, `list` shows none of those keys, the journal has one purge entry per key, and the
   same ids can be imported again.
10. More signatures and imports in a row than the TPM has object slots all succeed.
11. The API contract check passes with the kinds and any new error names; `docs/audit.md`
    documents every new field and value, and its queries work.
12. The unit passes the exposure gate at its current threshold, and every M0–M3 acceptance check
    that `just e2e` automates still passes with a TPM on every supported target, and without one
    on debian13.

Manual (a person, following written steps the milestone ships in the repository):

13. On a machine with a hardware TPM: import an RSA 2048 and a P-256 `.p12`; both are kind TPM;
    as root, with `tpm2-tools`, the stored public area shows an empty `authPolicy` and
    `tpm2_duplicate` fails. Then, in order, a reboot, an upgrade to the next M4 package and a
    `fwupd` `dbx` update (or, where none is pending, the documented substitute that changes PCR 7);
    after each, Firefox and LibreOffice still sign with both keys after the polkit dialog.
14. In a VM without a TPM: import a `.p12`; `custodio import` and `custodio list` say the key is
    encrypted with the host key and weaker; after a reboot it still signs from Firefox or
    LibreOffice.
15. On both machines, a copy of the whole state directory taken as root contains no private key
    (the written steps give the command that checks it).

## Open questions

- **Which parent.** A persistent SRK at the handle the TCG provisioning guidance reserves (what
  `systemd-cryptenroll` and, since v262, `systemd-creds` use), or a primary recreated from a fixed
  template on each use. Also: what to do when the owner hierarchy has a password, or the persistent
  handle holds a key with another template. Settle by a finding on `swtpm` and a hardware TPM.
  Default: whatever needs no write to the TPM's NV storage and no secret in the service; an owner
  hierarchy the service cannot use fails the import (section 2), never falls back.
- **Mechanism parity on the TPM** (section 4). Either `TPM2_Sign` only (parse the `DigestInfo` for
  `CKM_RSA_PKCS`, accept only the salt the TPM produces for PSS, and treat the rest as "lacks"), or
  the padding built in the service and only the raw RSA private operation in the TPM, which needs
  the `decrypt` attribute on the key and makes it usable for decryption by root. Settle by a
  finding that runs every mechanism against `swtpm` and a hardware TPM, records the salt length
  each produces, and weighs the `decrypt` attribute against the threat model. A person approves the
  choice, which is recorded in `docs/decisions.md`. The same finding settles which hashes a P-256
  key needs from the TPM.
- **Is the key wrapped on its way into the TPM?** `TPM2_Import` accepts a plain sensitive area, so
  the private key would cross the TPM bus in the clear once. Physical attacks are out of scope, but
  an outer wrap to the parent's public key or an encrypted session costs little. Default: wrap or
  encrypt; settle in the import feature's contract.
- **How the service reaches the TPM under its unit.** `PrivateDevices=yes` hides the TPM device,
  access to the resource manager node is by group (`tss` in `tpm2-tss`'s udev rules), and the unit
  has `PrivateUsers=yes` and a dynamic/static `custodio` user. Whether the `tss` group exists on
  every target, and whether device access by supplementary group works under `PrivateUsers=yes`,
  is not verified. Settle by a finding under the real unit on each target. If no configuration
  meets the exposure threshold, a person decides (`BLOCKED.md`); the threshold is not raised by a
  builder.
- **How the service uses `systemd-creds` without root.** The host key is readable only by root;
  `systemd-creds` has offered user-scoped credentials (`--user`, bound to uid, user name and
  machine-id) and a Varlink interface `io.systemd.Credentials` since v256, and sources disagree on
  when unprivileged use became complete (v257 or v258). Debian 13 and RHEL 10 ship v257. Settle by
  a finding on every supported target: which scope and which call work from the service's unit,
  whether TPM binding is available that way, and whether "TPM-bound" means TPM alone or host plus
  TPM. If a target cannot do it, that is a `SPEC_DEVIATIONS.md` entry with a finding, never a
  plaintext key.
- **How `swtpm` reaches the end-to-end containers.** The containers are privileged systemd
  containers. A TPM device inside them needs `swtpm` with the kernel's vTPM proxy (a host kernel
  module) or another route; the service could instead be pointed at `swtpm`'s socket by a test-only
  drop-in, which must not exist in the shipped unit. Settle by a finding; a host change goes to a
  person.
- **A TPM that lacks a capability only for some mechanisms** (for example PSS with the hash-length
  salt). Should such a key go to the TPM and lose that mechanism, or be stored encrypted and keep
  it? This spec says encrypted (section 4); a person may prefer the TPM for keys whose clients do
  not need that mechanism. Revisit with the parity finding.
- **An administrator override** that forbids the weaker kinds (import fails instead) or forces one.
  Not built in M4; worth deciding before M5, since an organisation may prefer no key over a weaker
  one.
- **Refused calls before authorization** (from M1 and M3) remain open; M4 changes nothing.
