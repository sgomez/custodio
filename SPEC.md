# Custodio — Milestone 1: PKCS#11 compatibility and audit

M1 builds on the M0 code (`docs/milestones/M0/SPEC.md`, results in `docs/findings.md`). Everything
M0 established stays true unless this document says otherwise. This milestone's features are
numbered from F19.

## Problem

People in Spain sign documents and authenticate with FNMT certificates (RSA 2048 or P-256). On
Linux they use rFirma and LibreOffice. M0 showed that Custodio can keep such a key away from the
user's own processes and ask polkit before every signature. But the M0 manual run
(`docs/findings.md`, section 4) also showed that clients have to adapt to Custodio:

- The module offers only raw mechanisms (`CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`, `CKM_ECDSA`). A client
  that asks for `CKM_SHA256_RSA_PKCS` or `CKM_ECDSA_SHA256` gets `CKR_MECHANISM_INVALID`. rFirma
  only worked after it gained a fallback to `CKM_RSA_PKCS` over its own `DigestInfo`.
- `C_Login` returns `CKR_FUNCTION_NOT_SUPPORTED`. rFirma only worked after it stopped calling
  `C_Login` when the token lacks `CKF_LOGIN_REQUIRED`. Any client that always logs in fails.
- `custodiod` logs nothing per signature. An administrator cannot tell afterwards who signed with
  which key, or whether a signature was refused. With AI agents running commands as the user, that
  question matters.

Client workarounds do not scale: each client we do not control (LibreOffice, OpenSSL with a
PKCS#11 provider, Java tools) would need its own. M1 makes the module behave like an ordinary
PKCS#11 token, and makes every signature leave an audit trail.

## Threat model

M0's threat model still holds. M1 changes it as follows.

- **In scope:**
  - A process running as the user that signs **by mistake**, as in M0. M1 adds: such a process
    must not be able to sign without leaving a journal entry, and must not be able to remove or
    rewrite the entries the service wrote.
  - A client that sends arbitrary or malformed PKCS#11 input to the module, including arbitrary
    data sizes and call sequences for the new mechanisms and for `C_Login`.
- **Out of scope:** everything M0 excludes (a hostile process with the same uid, root, physical
  access, a compromised kernel). Also: tampering with the journal by root or by members of a group
  allowed to change journal files; the Linux audit subsystem (`auditd`); forwarding entries off the
  machine.
- **Not guaranteed:**
  - Intent, as in M0. The module hashes inside the client's process, so a client can still hand
    the service any hash it likes. Hashing in the module adds compatibility, not trust.
  - That an entry identifies a *person*. The uid and pid identify the calling process when the
    call was made. A pid can be reused once that process has exited.
  - That entries survive. Journal rate limiting, a full disk, volatile journal storage or rotation
    can drop entries after the service has submitted them.
  - That entries cannot be imitated. Any local process can write journal entries with the same
    message text and user-chosen fields. Only the journal's trusted fields (the ones set by
    journald, such as the unit and the sender's uid) show that an entry came from `custodiod`.
    Administrators must filter on those fields.

## Goal

rFirma and LibreOffice, unmodified, sign on Linux with a custodied RSA 2048 or P-256 key. Every
signature attempt that reaches polkit leaves exactly one journal entry. The entry says who asked,
with which key, and what happened, and never contains key material or the data being signed.

## Design

The architecture stays as in M0: `custodiod` on the system bus (`com.rfirma.Custodio1`), polkit
asked on every signature with a `system-bus-name` subject, and the thin PKCS#11 module that opens a
connection per call. M1 changes three things.

### 1. Composed mechanisms in the module

- **Mechanisms.** For RSA keys: `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`,
  `CKM_SHA512_RSA_PKCS`. For P-256 keys: `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`,
  `CKM_ECDSA_SHA512`. The raw mechanisms M0 offers stay. Each token lists in `C_GetMechanismList`,
  and describes in `C_GetMechanismInfo`, only the mechanisms that fit its key type. Composed
  mechanisms take no parameter, as PKCS#11 defines them.
- **Where hashing happens.** The module hashes the data in the client's process. For RSA it wraps
  the digest in the `DigestInfo` that RFC 8017 (section 9.2) defines for that hash. For ECDSA it
  passes the bare digest. It then asks the service for a raw signature (`CKM_RSA_PKCS` over the
  `DigestInfo`, or `CKM_ECDSA` over the digest). The service never sees the document or message.
  It receives only a digest, or a `DigestInfo` that holds one. The existing D-Bus `Sign` method
  already takes this input, so M1 needs no change to the D-Bus interface for signing. If a builder
  finds one is needed, that is a spec change, not a builder decision.
- **ECDSA with a hash longer than the curve.** SHA-384 and SHA-512 digests are longer than the
  P-256 order. The signature must be the standard ECDSA result for that hash (the digest truncated
  as FIPS 186 and SEC 1 define), and must verify with an independent implementation such as
  OpenSSL. Whether the module or the service does the truncation is a builder choice. The result
  must not depend on that choice.
- **Single-part and multi-part.** PKCS#11 allows multi-part operations for hash-and-sign
  mechanisms, and some clients use them (OpenSSL's pkcs11-provider signs through
  `C_SignUpdate`/`C_SignFinal`). For the composed mechanisms the module supports both `C_Sign` and
  `C_SignUpdate`…`C_SignFinal`. The raw mechanisms stay single-part only.
- **Invariants carried over from M0, extended to the new paths:**
  - polkit is asked once per completed signature. It is never asked for a length query or a
    too-small buffer. Retrying after `CKR_BUFFER_TOO_SMALL` must neither lose the hash state nor
    sign twice.
  - An operation that fails for any reason other than a small buffer ends the operation, as
    PKCS#11 says.
  - The data passed to a composed mechanism has no size limit beyond what the client's memory
    allows. Only the digest crosses the bus, so the service's existing input limit still applies.
  - The module keeps no thread, connection or lock past a call, and stays fork-safe
    (`docs/findings.md`, section 2). Hash state belongs to the session.
- **Prior art.** OpenSC's PKCS#11 module offers hash-and-sign mechanisms on top of a card that only
  does raw RSA or ECDSA, by hashing in software. That is the same split as here. SoftHSMv2 is a
  reference for multi-part semantics and return codes.

### 2. `C_Login` as a no-op

- `C_Login` succeeds for a valid session, with any PIN, including a NULL or empty one, for the
  normal user (`CKU_USER`) and for a context-specific login (`CKU_CONTEXT_SPECIFIC`). It does not
  contact the service or polkit. It grants nothing: signing never requires a login, and a login
  never stands in for polkit.
- The PIN is never stored, forwarded, logged or included in an error message.
- `C_Logout` succeeds as a no-op as well, because Firefox calls `C_Logout` before `C_Login`
  (`docs/findings.md`, section 1).
- The token flags do not change. In particular `CKF_LOGIN_REQUIRED` and
  `CKF_PROTECTED_AUTHENTICATION_PATH` stay unset, so clients that check them keep skipping the login
  and see no extra prompt. `CKA_ALWAYS_AUTHENTICATE` stays false (`docs/decisions.md`).
- Some behaviour is left open; see Open questions: the security officer user type, a repeated
  login, and whether the reported session state changes after a login.

### 3. One journal entry per signature

- **Who writes it.** `custodiod`, never the module. The module runs in the client's process and
  cannot be trusted to log.
- **When.** Every `Sign` call that reaches the authorization step produces exactly one entry, once
  the outcome is known. The outcomes to tell apart are: approved and a signature produced; approved
  but signing failed; denied by the person or by polkit; authorization not possible (polkit or the
  caller's credentials unavailable). Calls refused earlier, during argument validation, are covered
  by an open question.
- **Content.** At least:
  - the caller's uid and pid;
  - the key id;
  - the outcome.

  It may add the mechanism. It never contains key material, the password, the data, digest or
  `DigestInfo` sent for signing, or the signature. A string that failed validation is never copied
  into an entry.
- **Where the uid and pid come from.** The bus daemon, for the same sender connection that polkit
  is asked about (the bus's connection credentials). They never come from the method's arguments.
  If the bus cannot give them, the signature is refused, and the entry records that.
- **Fail closed.** If the service cannot submit the entry to the journal, it does not return the
  signature. A signature that leaves no entry is a bug.
- **Format.** A human-readable message, plus structured journal fields so an administrator can
  query by uid, key and outcome. The entry carries a fixed message identifier, following the
  systemd convention of `MESSAGE_ID` and the journal catalog. Field names, the identifier and the
  priorities are chosen once, documented for administrators in the repository, and then treated as
  a stable interface. The documentation includes a `journalctl` query that matches only entries
  written by `custodio.service`, using journald's trusted fields.
- **Transport.** The journal's native protocol (systemd.io, "Native Journal Protocol"). Plain text
  on stdout or stderr cannot carry structured fields. Whether to use an existing crate or a small
  writer of our own is a builder choice, within the supply-chain policy. The service's hardening
  must not loosen: the exposure gate keeps its current threshold. The Linux audit subsystem is not
  used, because it needs `CAP_AUDIT_WRITE` and the unit drops every capability.
- **Testability.** The service writes entries through an interface that tests can replace, so
  integration tests on a private bus can assert exactly one entry per call and its content. The
  end-to-end suite checks the real journal.
- **Prior art.** sudo and sshd log one structured journal entry per privileged action. polkit
  itself logs authentication outcomes. systemd's catalog explains how message identifiers work.

## Language and harnesses

Rust, as in M0. Every M0 harness stays and keeps blocking the merge with the same thresholds:

- unit and integration tests (private `dbus-daemon`, fake polkit);
- end-to-end in a systemd container;
- `cargo-mutants` with no surviving mutant;
- coverage as a report, plus the CRAP gate;
- `cargo-fuzz`;
- `forbid(unsafe_code)` outside the FFI layer, with Miri and AddressSanitizer on that layer;
- `secrecy`/`zeroize` for secrets;
- `rustfmt` and `clippy` (pedantic, plus the service's restriction lints);
- `cargo-machete`, `cargo-deny`;
- `taplo`, `typos`, `shellcheck`, `actionlint`, `zizmor`;
- the systemd exposure score, the unit and bus-policy checks;
- commitlint; `just` as the entry point.

M1 adds:

- **Known-answer and cross-verification tests.** For every composed mechanism and both key types,
  the signature verifies with an independent verifier over the original message. The RSA
  `DigestInfo` encodings match RFC 8017. Single-part and multi-part signing of the same message
  give signatures that both verify (and for RSA PKCS#1 v1.5, are byte-identical).
- **PKCS#11 conformance tests through the built module** (the existing `cryptoki` integration
  test), for:
  - the new mechanisms, including length queries and too-small buffers in both `C_Sign` and
    `C_SignFinal`;
  - polkit asked exactly once per signature;
  - mismatched key and mechanism, and parameters given to composed mechanisms;
  - `C_SignUpdate` after `C_SignInit` with a raw mechanism;
  - `C_Login` and `C_Logout`;
  - the fork and thread tests, extended to cover an open multi-part operation.
- **Audit tests.** Integration tests assert one entry per `Sign` call that reaches authorization,
  for every outcome, with the right uid, pid and key, and with none of the forbidden content. A
  test shows that a failure to write the entry withholds the signature.
- **Fuzzing.** The PKCS#11 fuzz target covers the new mechanisms, multi-part call sequences and
  `C_Login` arguments.
- **Mutation testing** extends to the audit path in the service, and to the module's mechanism
  mapping, hashing and `DigestInfo` construction. These decide what gets signed and what gets
  recorded.
- **Miri and AddressSanitizer** cover the new FFI entry points.
- **End-to-end** adds:
  - signing with each composed mechanism through `pkcs11-tool`, and through a client that uses
    multi-part signing (for example OpenSSL with pkcs11-provider, if the target distribution ships
    it), each verified with OpenSSL;
  - a `C_Login` before signing;
  - journal checks: one entry per approved and per denied signature, with the expected uid and
    key, and neither the hex nor the base64 of the signed data or digest anywhere in the service's
    journal.

## Scope

- The six composed mechanisms above, single-part and multi-part, for RSA 2048 and P-256 keys.
- `C_Login` and `C_Logout` as no-ops.
- One journal entry per signature attempt that reaches authorization, written by `custodiod`, and
  documentation of its fields and of a query that selects them.
- Manual acceptance with unmodified rFirma and LibreOffice, with an RSA 2048 key and a P-256 key.
- Debian 13 stays the end-to-end target and the only package, as in M0.

## Out of scope

- SHA-1 and SHA-224 composed mechanisms; composed RSA-PSS mechanisms (`CKM_SHA256_RSA_PKCS_PSS`
  and peers). Raw `CKM_RSA_PKCS_PSS` stays as it is.
- Digest functions of the PKCS#11 API (`C_Digest*`), verification, and any other new function.
- Real PIN or login semantics; changing token flags or `CKA_ALWAYS_AUTHENTICATE`.
- Changes to the polkit dialog, the action or its defaults; showing document details.
- Logging from the module; `auditd`; remote log shipping; a log viewer.
- Everything M2 and later covers (`docs/milestones.md`): packaging for other distributions,
  Firefox snap and registration without p11-kit, rFirma integration, TPM.

## Acceptance

Automated (CI or `just e2e`):

1. For each of `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS` and `CKM_SHA512_RSA_PKCS` with an RSA
   2048 key, and `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384` and `CKM_ECDSA_SHA512` with a P-256 key,
   `pkcs11-tool` signs a message through the module after polkit approval. OpenSSL verifies each
   signature over the original message with the certificate's public key.
2. Signing the same message with a composed mechanism through `C_Sign`, and through `C_SignUpdate`
   in several parts followed by `C_SignFinal`, gives signatures that both verify.
3. A length query, or a buffer that is too small, in `C_Sign` or `C_SignFinal` does not ask polkit.
   The following call with a large enough buffer asks polkit exactly once and returns a valid
   signature.
4. The data the service receives for a composed-mechanism signature is the digest, or the RFC 8017
   `DigestInfo` holding it, and never the message. An integration test checks this by observing
   the service's input.
5. Each token lists only the mechanisms that fit its key: no ECDSA mechanism on an RSA token, no
   RSA mechanism on a P-256 token. `C_SignInit` with a mismatched pair fails without asking polkit.
6. `C_Login` with `CKU_USER` and with `CKU_CONTEXT_SPECIFIC`, with a NULL, empty or arbitrary PIN,
   returns `CKR_OK` and does not contact the service. `C_Logout` returns `CKR_OK`. A signature after
   a login still asks polkit, and a denial still fails it.
7. Each `Sign` call that reaches authorization adds exactly one entry to the journal of
   `custodio.service`, in each case: approved and signed, denied, and polkit unavailable. Each
   entry's uid and pid are those of the calling process, and it names the key and the outcome.
8. No journal entry of `custodio.service` contains the signed data, the digest, the `DigestInfo`,
   the signature or the import password, whether as raw bytes, hex or base64.
9. When the entry cannot be written, the `Sign` call fails and no signature is returned.
10. Every M0 acceptance check that `just e2e` automates still passes. The signing tests M0 already
    had pass unchanged.

Manual (a person, in a graphical Debian 13 or Ubuntu 26.04 session, following written steps that
the milestone ships in the repository):

11. A released rFirma build, without the two workarounds in `docs/findings.md` section 4, lists the
    custodied certificate and signs a document with an RSA 2048 key and with a P-256 key. Each
    signature shows the polkit dialog, a second signature asks again, and cancelling makes the
    signature fail.
12. LibreOffice, with the module registered in the NSS database it uses, signs an ODF document with
    an RSA 2048 key and with a P-256 key. Each signature shows the polkit dialog. LibreOffice reports
    the signature as valid after the document is reopened.
13. After steps 11 and 12, the documented `journalctl` query run by an administrator shows one entry
    for each signature and each cancellation in those steps, with the person's uid, the pid of
    rFirma or LibreOffice, and the key used.

## Open questions

- **Security officer login.** Should `C_Login` with `CKU_SO` also succeed, or fail as PKCS#11 allows
  on a write-protected token with read-only sessions? Proposed default: fail, since nothing needs
  it. Settle by checking whether rFirma, LibreOffice/NSS, pkcs11-provider or `pkcs11-tool` ever send
  it.
- **Repeated login and session state.** On a second `C_Login`, return `CKR_OK` or
  `CKR_USER_ALREADY_LOGGED_IN`? After a login, should `C_GetSessionInfo` report a user-functions
  state rather than a public one? Some clients check the state to decide whether to prompt. Settle
  by running the manual acceptance clients and pkcs11-provider against both behaviours. Until then,
  the most tolerant behaviour that keeps the M0 tests green.
- **LibreOffice and a PIN prompt.** `docs/findings.md` says LibreOffice's password callback always
  shows a dialog when NSS asks. With `CKF_LOGIN_REQUIRED` unset, NSS should not ask, but this has
  not been observed. If LibreOffice still shows a PIN dialog, is that acceptable, or does it justify
  setting a token flag (with its effect on Firefox)? Settled by acceptance step 12.
- **LibreOffice with ECDSA.** LibreOffice gained ECDSA signing with NSS years ago, and later fixed
  bugs in it. Whether today's Debian or Ubuntu LibreOffice signs ODF with a P-256 key through an
  external PKCS#11 token has not been checked. If it cannot, even with a software NSS token holding
  the same key, the person approving the milestone decides whether acceptance step 12 is met for
  RSA only.
- **Which rFirma build.** Acceptance step 11 needs an rFirma build without the M0 workarounds:
  either a release from before them or a build with them reverted. The rFirma maintainers must
  provide it.
- **Calls refused before authorization.** Should calls with malformed arguments, or an unknown key,
  also leave an entry? Logging them closes a gap in the audit trail. But it lets any local process
  flood the service's journal without a polkit dialog, and journald's per-service rate limit could
  then drop real entries. Settle by measuring the rate limit's effect, or by logging refusals in
  aggregate.
- **More caller detail.** The pid alone is weak evidence after the fact. The executable name or the
  cgroup would help, but reading them conflicts with the unit's `ProtectProc=`/`ProcSubset=`
  hardening. The bus's connection credentials or a pidfd might give enough. Settle by checking what
  the bus daemons on the supported targets expose, without loosening the exposure gate.
- **Volatile journals.** On systems with volatile journal storage the entries are lost at reboot.
  Should the package require or recommend persistent storage, or only document it? Settle with the
  M2 packaging work.
