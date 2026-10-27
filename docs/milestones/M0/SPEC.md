# Custodio — Milestone 0

A prototype to decide, with evidence, whether Custodio is worth building.

## Problem

AI agents now run shell commands as the user. A signing key stored where the user can read it (a
`.p12` file, an NSS database whose PIN sits in the desktop keyring) can be used by such an agent
without the person noticing, either through a signing application or directly with OpenSSL.

## Threat model

- **In scope:** a process running as the user that signs **by mistake**, including one that looks
  for workarounds when blocked (reading the keyring with `secret-tool`, using a `.p12` it finds).
- **Out of scope:** a hostile process running as the same uid (it can hijack the polkit dialog by
  registering its own authentication agent), root, physical access, a compromised kernel.
- **Not guaranteed:** intent. The dialog cannot prove which hash is signed.

## Goal

Every signature with a custodied key requires the person to authenticate, and the key cannot be
read by the user's processes.

## Design

- **Service:** `custodiod`, a system service with its own uid (`DynamicUser=`,
  `StateDirectory=custodio`). Keys live in its state directory, readable only by that uid.
- **Transport:** system D-Bus, name `com.rfirma.Custodio1`, object `/com/rfirma/Custodio1`.
- **Authorization:** on every signature the service calls polkit `CheckAuthorization` for action
  `com.rfirma.custodio.sign` with a `system-bus-name` subject for the sender, so polkit resolves the
  caller's pidfd itself. Defaults: `auth_self` for active, inactive and any. Never a `_keep`
  variant: each signature must ask.
- **Client:** `libcustodio-pkcs11.so`, a thin PKCS#11 module that forwards to the service over
  D-Bus. Registered for p11-kit with a `.module` file so PKCS#11 consumers find it.
- **Template:** `siguldry-pkcs11` (fedora-infra/siguldry), a Rust `cdylib` over `cryptoki-sys` that
  exports only signing and forwards to a system service.

## Language and harnesses

Rust, pinned with `rust-toolchain.toml`, `Cargo.lock` committed. Every harness runs in CI and
blocks the merge.

- **Tests:** unit tests per crate, and integration tests against a private `dbus-daemon` with a fake
  polkit authority that approves or denies on demand.
- **End-to-end:** in a systemd container or VM with the real service, polkit and a test
  authentication agent: sign with `pkcs11-tool` and through NSS (`modutil`, `certutil`), and cover
  approve, deny and the second-signature case.
- **Mutation testing:** `cargo-mutants` on the authorization path and the key store; a surviving
  mutant fails the build.
- **Coverage:** `cargo-llvm-cov`, as a report to find untested code, not as a target.
- **Fuzzing:** `cargo-fuzz` on everything that parses untrusted input: the `.p12` import, the D-Bus
  method arguments and the PKCS#11 arguments the module receives.
- **Unsafe code:** `#![forbid(unsafe_code)]` in every crate except the PKCS#11 module, whose FFI layer
  runs under Miri and the address sanitizer.
- **Secrets in memory:** key material and passwords in `zeroize` / `secrecy` types, never in `Debug`
  output or logs.
- **Lints:** `rustfmt`, `clippy` with `-D warnings` and the `pedantic` group. In the service, also
  `unwrap_used`, `expect_used`, `panic` and `indexing_slicing` from the `restriction` group.
- **Complexity:** a CRAP gate that blocks complex functions with low coverage.
- **Unused dependencies:** `cargo-machete`.
- **Rest of the repository:** `taplo` for TOML, `typos` for spelling, `shellcheck` for scripts,
  `actionlint` and `zizmor` for the GitHub workflows.
- **Entry point:** `just` for every task (`just check`, `just fmt`), and lefthook with the fast checks
  on pre-commit and the slow ones on pre-push.
- **Supply chain:** `cargo-deny` for advisories, licences compatible with EUPL-1.2, banned and
  duplicate crates, and allowed sources.
- **Service hardening:** a check that `systemd-analyze security custodio.service` stays under a fixed
  exposure score, and a test that the state directory and key files are owned by the service uid
  with mode `0700` / `0600`.

## Scope

- Key types: RSA 2048 and ECDSA P-256, the ones FNMT issues to individuals.
- Import from a `.p12` and its password, once. The tool tells the person to delete the original
  file afterwards.
- PKCS#11: enough to list the certificate, find the private key object and `C_Sign`.
- Storage: plain files owned by the service uid. No TPM.
- Packaging: one `.deb` or one `.rpm` installing the binary, the systemd unit, the D-Bus policy,
  the polkit action and the p11-kit `.module`.

## Out of scope

- TPM (`TPM2_Import`), flatpak, snap, immutable distributions.
- Key types other than RSA 2048 and P-256.
- Showing document details in the dialog.
- Multiple distributions and repositories.

## Acceptance

1. After import, the user cannot read the key material.
2. rFirma lists the certificate as a token and signs with it; each signature shows the polkit
   dialog.
3. Firefox lists the certificate through the module and uses it for TLS client authentication;
   each signature shows the polkit dialog.
4. Cancelling the dialog makes `C_Sign` fail; no signature is produced.
5. A second signature right after an approved one asks again.
6. Fingerprint works when the distribution's `polkit-1` PAM stack includes `pam_fprintd`.

## Open questions

- Whether NSS and OpenSSL honour `CKA_ALWAYS_AUTHENTICATE` with `C_Login(CKU_CONTEXT_SPECIFIC)`,
  which would let clients expect a pause on each signature.
- How a D-Bus client behaves inside third-party processes (threads, `fork`) such as Firefox and
  LibreOffice.
- Minimum versions: polkit 124 and a bus exposing `ProcessFD` (dbus-daemon 1.15.8, dbus-broker 34).
  Which target distributions meet them.
