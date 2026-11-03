# Custodio — Milestone 3: Client API

M3 builds on the code of M0–M2 (specs and results in `docs/milestones/`, `docs/findings.md`,
`docs/decisions.md`). Everything those milestones established stays true unless this document
says otherwise. This milestone's features are numbered from F63.

## Problem

Custodio holds signing keys for people who sign with FNMT certificates on Linux, and asks polkit
before every signature. Up to M2 its D-Bus interface `com.rfirma.Custodio1` was shaped by its
first two clients (the PKCS#11 module and the `custodio import` command), not by a contract other
programs can rely on:

- **Import is open to everyone.** Any process of any uid can import a `.p12` with no polkit
  question. A process acting for the user (such as an AI agent with a shell) can replace or add
  keys without the person knowing.
- **Keys have no owner.** Every uid lists every key and can ask to sign with any of them. polkit
  is the only barrier, and it asks the *caller's* user, so user B can sign with user A's key by
  approving their own dialog.
- **Keys cannot be managed.** A client cannot delete a key, and cannot install the renewed
  certificate of a key it already holds. The only fix today is a new import under a new id, which
  leaves the old key behind.
- **The record does not say which app asked.** rFirma's flatpak (M5) will reach the service
  through `xdg-dbus-proxy`. A journal entry then names only the uid and the proxy's pid.
- **Nothing is documented for clients.** rFirma's integration (M5) must be built in another
  repository against an API that has to be written down, including how to detect the service and
  what each error means.

This matters now because the rFirma side is planned for M5 against this API, and because nothing
is usable before M5 and Custodio only runs in test VMs. So the interface and the state format can
still change freely, with no migration.

## Threat model

The threat model of M0–M2 still holds. M3 changes it as follows.

- **In scope:**
  - A process running as the user that **by mistake** imports, deletes or replaces the
    certificate of a key. Each of these operations needs a polkit approval for that one call, as
    a signature does. None of them may happen without a journal entry.
  - A process of one uid that tries to list, sign with, delete, replace the certificate of, or
    learn whether there is a key belonging to another uid. To a caller, another uid's key must look
    exactly like a key that does not exist: same error and same journal behaviour, and the same
    answer about whether polkit is asked.
  - A caller that uses import as a password oracle. The service must not try the `.p12` password
    before polkit has approved the call.
  - Hostile input in everything a caller controls, which now includes the contents and the file
    type of `/.flatpak-info` as seen through the calling process. A process can build its own mount
    namespace and put a symlink, FIFO, device, oversized file, FUSE mount or malformed text at that
    path.
- **Out of scope:** everything M0–M2 exclude: a hostile process running as the same uid, root,
    physical access, a compromised kernel, tampering with the journal by root. Also escapes from the
    flatpak sandbox, and the security of `xdg-dbus-proxy` itself.
- **Not guaranteed:**
  - **The app-id is not authenticated.** It is a record, not an authorization. A process that is
    not sandboxed can create a user namespace with a `/.flatpak-info` of its choosing, so an entry
    that names an app-id shows what the caller's filesystem *claimed*. polkit and ownership never
    depend on it.
  - **Ownership follows the numeric uid**, as the bus reports it. If an account is removed and its
    uid is later given to someone else, the new account owns the old keys.
  - **Deletion does not erase the disk.** Deleting a key removes it from the service, and its file
    from the state directory. Copies of its bytes may survive in filesystem blocks, snapshots or
    backups.
  - **The dialog does not show which key or file is involved.** The person approves "an import" or "a deletion" by the
    calling program.
  - **The pid in an entry for a flatpak caller is the proxy's pid**, not the app's.
  - Everything M1 lists as not guaranteed for audit entries (`docs/audit.md`, "Not guaranteed").

## Goal

Any client, without reading Custodio's source, can follow the client documentation to detect the
service, import, list, delete, replace a certificate and sign. Every key belongs to the uid that
imported it, and is invisible to every other uid. Every change to a key needs a polkit approval
and leaves one journal entry, which names the flatpak app-id when the caller is a flatpak.

## Design

The architecture stays: `custodiod` on the system bus as `com.rfirma.Custodio1`, under the same
hardened unit; polkit asked with a `system-bus-name` subject; caller credentials from the bus
(`UnixUserID`, `ProcessID`, `ProcessFD`), never from method arguments; the PKCS#11 module, which
opens one connection per call; native journal entries. M3 changes the following.

### 1. The public API

- **One documented contract.** The interface `com.rfirma.Custodio1` at its object path is the only
  way into the service. Its methods, arguments, return values and errors are defined once, in
  client documentation shipped in the repository, and the service's introspection data must agree
  with that document (see Harnesses). The interface name and bus name do not change. Methods and
  signatures may change freely from M2's, because no client outside this repository exists.
- **Operations.** At least:
  - *Import*: a `.p12`, its password and a client-chosen key id. Returns the key's type.
  - *List*: the caller's keys. For each, its id, key type and DER certificate, so a client (the
    PKCS#11 module included) needs no second call.
  - *Delete*: one of the caller's keys, with its certificate.
  - *Replace certificate*: a new DER X.509 certificate for one of the caller's keys. It is accepted
    only if its public key is the key's public key. The key itself is untouched.
  - *Sign*: as today. M1 holds that hashing stays in the client and the service gets a digest or
    `DigestInfo`.

  Whether list is one method or the current pair (`ListKeys`, `ListCertificates`) is a builder
  choice. Whatever the choice, it must be documented, and the module must need only what the
  documentation gives.
- **Errors are D-Bus error names.** Each failure a client must tell apart has its own error name
  in a namespace of the project's. Its message text is for people, never contains key material, a
  password, a path or a string that failed validation, and clients must not parse it. At least
  these cases are distinct: invalid arguments; no such key (also used for another uid's key);
  a key id already taken; polkit denied; authorization unavailable (polkit or the caller's
  credentials); wrong password or unreadable `.p12`; unsupported key type; certificate does not
  match the key; audit unavailable; internal or storage failure. The names are chosen once,
  documented, and from then on only added to, under the same compatibility rule as
  `docs/audit.md`. Prior art: UDisks2 and fwupd, which give each failure its own D-Bus error name
  in their own namespace.
- **Detection.** The documentation says how a client finds out that Custodio is installed and
  reachable, both on the host and from inside a flatpak that has
  `--system-talk-name=com.rfirma.Custodio1`. It also says what a client sees when the service is
  absent, not activatable, or blocked by the sandbox. The activation file keeps `Exec=/bin/false`
  (`docs/decisions.md`). M3 exposes no version or capability property.
- **Limits.** Every argument has a documented bound, as `Sign` and `ImportP12` already have,
  including the certificate given to replace certificate. A call over a bound is refused before
  any key, file or polkit is touched.

### 2. Ownership

- **Owner.** A key belongs to the uid the bus reports for the connection that imported it. The
  owner is stored with the key, in the service's state, and no argument can set or change it.
- **Namespace.** Key ids are unique per owner. Two uids may each have a key `my-key`. Whether
  something exists is never revealed across uids: an import under an id another uid uses
  succeeds, and acting on another uid's key fails exactly as for a missing key.
- **Every operation checks the owner** against the caller's uid from the bus, for the same
  connection polkit is asked about. Sign, delete and replace certificate look the key up among the
  caller's keys before polkit: when it is not there, the call fails with "no such key" and shows no
  dialog. The store keeps each owner's keys apart, so a lookup never touches another uid's keys and
  the two cases cannot differ by construction. List returns only the caller's keys. Root is a uid like any
  other through the API (root's file access is out of scope).
- **Credentials unavailable.** If the bus gives no uid, or the existing `ProcessFD` cross-check
  fails, the call is refused as "authorization unavailable". List included: it returns an error,
  never an empty or unfiltered list.
- **Prior art.** The Secret Service API and systemd-homed both scope objects to the calling user.

### 3. polkit for every change

- Import, delete and replace certificate each ask polkit once per call, with
  `AllowUserInteraction`, under an action that is not the signing action, so the dialog says what
  is being approved. The defaults are `auth_self` on every line, as for signing, and never a
  `_keep` variant. The action file declares the same owner annotation the signing action needs
  (`docs/decisions.md`, "Fixes for a live systemd"). Each operation has its own action, so an
  administrator can write rules such as "never allow delete" and each dialog has its own text.
- polkit fails closed exactly as for signing (`docs/decisions.md`, "polkit fails closed"). No
  authorization is ever cached or reused across calls.
- **Order for import.** Arguments are checked first, then whether the caller already has the id. polkit is asked before the `.p12` is
  decrypted, so a caller without approval learns nothing about the password. After approval, a
  wrong password and an unsupported key are errors of their own.
- List asks no polkit: it shows only the caller's own keys and certificates, which are public
  data.

### 4. State

- The state format may change freely in M3. It must record the owner of each key.
- **No migration, and no code for earlier state.** Nothing is usable before M5 and earlier keys
  exist only in test VMs and containers, so the software does nothing about them. Every test and
  manual step of M3 starts from a clean machine.
- Upgrades from an M3 build to a later M3 build keep keys, owners and certificates, as M2's
  upgrade tests require.
- The store's existing rules still apply, extended to the new state: exact modes, owner checks,
  no symlinks, refuse rather than repair, atomic writes that never overwrite silently.
- **Replace certificate is atomic.** A concurrent reader sees the old certificate or the new one,
  never neither. **Delete** removes the key and its certificate together. A signature in progress
  either completes with the key or fails with "no such key". Two concurrent imports of the same id
  by the same owner leave exactly one key.

### 5. Journal entries

- **Which calls.** Every call to sign, import, delete or replace certificate that reaches the
  authorization step leaves exactly one entry, once the outcome is known, as signing does since
  M1. List leaves none. Refusals before authorization keep M1's behaviour; that open question is
  still open.
- **Content.** As in `docs/audit.md`, plus the operation, so an administrator can query by it.
  Fields, outcome values and messages for the new operations are added under the existing
  compatibility rule: nothing documented changes meaning, and existing signing entries stay valid.
  An import entry names the key id and type. No entry contains the `.p12`, its password, the
  certificate bytes, the data or the signature.
- **Fail closed.** No change is reported to the caller as done unless its entry was submitted. For
  sign this is M1's rule. For import and replace certificate, a change whose entry cannot be
  submitted is not kept. Delete first makes the key unusable (sign then fails with "no such key"),
  submits the entry, and only then removes the files; if the entry cannot be submitted, the key is
  restored and the call fails as "audit unavailable". A deleted key never lacks an entry.
- **Flatpak app-id.** When the calling process is a flatpak, the entry names its app-id. The
  process meant here is the one the bus credentials name, which is `xdg-dbus-proxy` for a
  flatpak: flatpak runs the proxy in a sandbox that holds the app's `/.flatpak-info`, which is how
  `xdg-desktop-portal` identifies apps.
  - The service reads the application name from `/.flatpak-info` as the process pinned by the
    bus's `ProcessFD` sees it. It confirms the process is still the same one after reading.
  - The file is hostile input. Symlinks are not followed, only a regular file of bounded size is
    read, a FIFO, device or slow filesystem cannot block the service beyond a bounded time, and
    stuck reads cannot exhaust it. The value is copied into the entry only if it is a valid
    flatpak application id. A value that fails validation is never copied anywhere.
  - The entry tells apart three cases: an app-id was read; the caller has no `/.flatpak-info`;
    the app-id could not be determined.
  - The app-id never changes the outcome. A failure to read it neither refuses nor delays the
    operation beyond the bound above.
  - **Feasibility risk.** Reading another uid's `/proc/<pid>/root` needs a `PTRACE_MODE_READ`
    check that the service fails today. It runs as `custodio` with no capabilities,
    `PrivateUsers=yes`, `ProtectProc=invisible` and `ProcSubset=pid` (`data/custodio.service`,
    `docs/findings.md` M1.2). The exposure gate must not loosen. See the open question "How
    `custodiod` can read the app-id"; a finding must settle it before this part is built. If it
    settles on (c), the rules above apply to that source instead of `/.flatpak-info`, and the
    hostile-input tests and acceptance 9 follow it. If it settles on (d), acceptances 9 and 15 are
    amended with the deviation: the entry always says the app-id could not be determined.

### 6. Clients in this repository

- **The PKCS#11 module** moves to the new API. To a PKCS#11 client the only visible change is
  that a process now sees only its own uid's keys as tokens. Every M1 and M2 module guarantee
  stays: a connection per call, fork safety, no thread left behind, and no slots when the service
  is absent.
- **The CLI** gains `custodio list` and `custodio delete`, next to `custodio import`. It talks to
  the service only through the documented API, as an outside client would: neither the CLI nor
  the module depends on the service's crate. A small client-side library shared by the two is
  allowed, if it holds nothing the documentation does not describe.
  - `list` shows each of the caller's keys with its id, key type, and enough of the certificate
    (at least the subject and the end of validity) to tell keys apart. With no keys it says so and
    succeeds.
  - `delete` names one key. Before calling the service it asks for confirmation on the terminal,
    saying that the key cannot be recovered. polkit then asks as well. There is no flag that skips
    the confirmation.
  - Errors are shown from the documented error names, and the exit status is non-zero on failure.
    Usage errors keep their own status, as today.
  - **polkit without a graphical agent.** `import` and `delete` now need polkit, which fails as
    "authorization unavailable" over SSH or on a console with no agent. When stdin is a terminal,
    the CLI starts `pkttyagent --fallback` registered for its own process only, as `systemctl`
    does, and stops it when the call returns. polkitd uses that fallback agent only when the
    session has no other agent, so a graphical agent keeps answering (polkit cannot be asked
    whether an agent is registered; see `SPEC_DEVIATIONS.md`, F89). It never registers an agent for
    another process or for the whole session (`docs/reports/polkit-custodian-linux.md`, the
    per-process agent attack).

### 7. Client documentation

The documentation is a document in the repository, for people who write clients. It covers:
detection (host and flatpak); every method, with arguments, bounds and results; every error name
and when it occurs; ownership and its consequences; which calls show a polkit dialog, and which
action each uses; what is journalled; and that hashing stays in the client. It includes a short
worked example per operation using a common tool such as `busctl` or `gdbus`. Prior art:
`docs/audit.md` (the same compatibility rule), and freedesktop.org's D-Bus API design guidelines
for naming and versioning.

## Language and harnesses

Rust, as before. Every harness of M0–M2 stays and keeps blocking the merge with the same
thresholds, including:

- unit and integration tests on a private bus with fake polkit;
- end-to-end tests in the containers for every supported target;
- `cargo-mutants` with no surviving mutant; coverage as a report plus the CRAP gate;
- `cargo-fuzz`; `forbid(unsafe_code)` outside the FFI layer, with Miri and AddressSanitizer on it;
- `secrecy`/`zeroize` for secrets;
- `rustfmt`, `clippy` with the service's restriction lints;
- `cargo-machete`, `cargo-deny`;
- `taplo`, `typos`, `shellcheck`, `actionlint`, `zizmor`;
- the systemd exposure score at its current threshold, and the unit and bus-policy checks;
- the package gates (parity, linters, glibc ceiling);
- commitlint; `just` as the entry point.

M2's upgrade tests change on one point only: they upgrade between two M3 builds, never from a
pre-M3 package, and must still keep keys (section 4).

M3 adds, all blocking:

- **Ownership tests.** Integration tests with at least two caller uids (through the replaceable
  credentials interface) cover every operation. For each, another uid's key gives the same result
  as a missing key, with the same polkit and journal behaviour. End-to-end tests repeat this with
  two real accounts.
- **polkit tests.** Import, delete and replace certificate ask the fake polkit exactly once per
  call. Denial and unavailability change nothing. Import does not try the password before
  approval.
- **Audit tests.** Exactly one entry per operation that reaches authorization, for every outcome,
  with no forbidden content. A failure to submit the entry withholds the result, as in section 5.
  A fake `/.flatpak-info` source covers the three app-id cases and hostile files: a symlink, a
  FIFO, an oversized file, an invalid id, and a reader that never returns.
- **API contract check.** A test compares the client documentation with three sources: the
  service's live introspection data for methods, arguments and properties; the service's error
  type for error names, which introspection does not carry; and the shipped `.policy` file for
  polkit actions. Every item in a source must be in the documentation, and every item the
  documentation lists must be in its source.
- **Dependency check.** A check fails if the CLI or the PKCS#11 module depends on the service's
  crate.
- **Fuzzing.** New targets, or extended ones, for the argument parsing of every new method, for
  certificate input to replace certificate, and for the `/.flatpak-info` parser.
- **Mutation testing** covers the ownership checks, the authorization path of every operation and
  the app-id validation.

## Scope

- The documented `com.rfirma.Custodio1` API: import, list, delete, replace certificate, sign, error
  names, detection.
- Per-uid ownership and per-owner key ids.
- polkit on import, delete and replace certificate, with the polkit action file(s) shipped in
  every package.
- A new state format that records owners.
- Journal entries for every authorized operation, with the flatpak app-id, documented in
  `docs/audit.md`.
- The PKCS#11 module and `custodio import` moved to the new API; `custodio list` and
  `custodio delete`.
- Client documentation.
- All supported targets of M2 and all three package formats.

## Out of scope

- The rFirma side of the integration, and rFirma's flatpak (M5).
- Migration of earlier keys, or compatibility with M2 clients.
- A CLI command for replacing a certificate (API only).
- A non-interactive flag for `custodio delete`.
- A version or capability property in the API; revisited with rFirma's integration in M5, since
  the API can still change until then.
- Details such as the key id in the polkit dialogs.
- Authorization based on the app-id, and per-app policies.
- Key export, backup, renaming, sharing a key between uids, or transferring ownership.
- An administrator interface that acts on other users' keys.
- Validation of the certificate chain, revocation or dates during replace certificate.
- Changes to the signing action, its defaults or its dialog; showing document details.
- TPM (M4); publishing packages and SECURITY/README work (M5).
- Firefox snap or Flatpak support (unassigned in `docs/milestones.md`).

## Acceptance

Automated (integration tests, `just e2e` on every supported target):

1. Uid A imports a key. A's `list` shows it. Uid B's `list` does not. B's sign, delete and replace
   certificate on that id fail with the same error name as for an id nobody has, none of them
   shows a polkit dialog, and journal behaviour matches too.
2. Uid A and uid B can each import a key with the same id. Each signs with their own, and each
   signature verifies against that uid's certificate.
3. Import, delete and replace certificate each ask polkit exactly once per call. With polkit
   denying, or unavailable, the call fails with the documented error and the state is unchanged.
   A second call asks again.
4. An import with a wrong password, made without polkit approval, fails as "denied", and the
   service has not tried the password (observable through a test double of the `.p12` decoder).
   After approval, a wrong password gives its own documented error.
5. Replace certificate with a certificate for the same key succeeds. `list` then shows the new
   certificate, and the PKCS#11 module exposes it. A signature made afterwards verifies with the
   new certificate. A certificate for a different key fails with the documented error and changes
   nothing.
6. After delete, the key is absent from `list`, the module shows no token for it, sign fails with
   "no such key", and the key's file is gone from the state directory. Its id can be imported
   again.
7. Every sign, import, delete and replace certificate call that reaches authorization leaves
   exactly one journal entry of `custodio.service`, naming the operation, the caller's uid and
   pid, the key id and the outcome. No entry contains the `.p12`, the password, the certificate
   bytes, the signed data or the signature (raw, hex or base64). `docs/audit.md` documents every
   new field and value, and every query it documents works.
8. When the entry cannot be submitted, sign returns no signature, and an import or a replace
   certificate leaves no change behind.
9. With a fake or real flatpak caller, the entry names the app-id. With a non-sandboxed caller it
   says there is none. With a hostile `/.flatpak-info` (symlink, FIFO, oversized, invalid id), the
   entry says the app-id could not be determined, no invalid text is copied, the operation's
   outcome is unaffected, and the call returns within the documented bound.
10. An upgrade from one M3 build to the next keeps keys, owners and certificates.
11. `custodio list` prints the caller's keys with id, type, subject and end of validity, and says
    there are none when there are none. `custodio delete <id>` asks for confirmation, then for
    polkit, and deletes. Declining either deletes nothing and exits non-zero. On a terminal with no
    polkit agent, `custodio import` and `custodio delete` ask for the password through
    `pkttyagent`.
12. The API contract check passes: the client documentation lists exactly the methods and
    arguments of the introspection data, the error names of the service's error type, and the
    actions of the `.policy` file. The dependency check shows neither the
    CLI nor the module depending on the service crate.
13. Every acceptance check of M0–M2 that `just e2e` automates still passes, except that upgrades
    start from an M3 build (acceptance 10).

Manual (a person, following written steps the milestone ships in the repository, in a graphical
session on a supported target VM):

14. Following only the client documentation, the person detects the service, then imports, lists,
    replaces the certificate of, signs with and deletes a key, using `busctl` or `gdbus`, and sees
    each documented polkit dialog and error.
15. A test flatpak with `--system-talk-name=com.rfirma.Custodio1` detects the service by the
    documented steps and signs (or imports) after the polkit dialog. The journal entry names its
    app-id and the uid of the person.
16. Firefox and LibreOffice, as in M1/M2, still sign with a key the person imported. A second
    account on the same machine sees no token for that key.

## Open questions

- **How `custodiod` can read the app-id.** Under the current unit, reading another uid's
  `/proc/<pid>/root` fails: it needs a `PTRACE_MODE_READ` check (`CAP_SYS_PTRACE` for another
  uid), which the empty bounding set, `PrivateUsers=yes` and `ProtectProc=invisible` all prevent.
  Options:
  (a) loosen the unit, which fails the exposure gate and exposes every process to the key holder;
  (b) a separate, minimal component with just enough privilege to read that one file for a
  pidfd it is handed, talking only to `custodiod`;
  (c) another source of the app-id that needs no `/proc` access of another uid (for example the
  caller's cgroup, the `app-flatpak-<id>-*.scope` convention, through something the unit already
  allows);
  (d) a recorded deviation, with the field always "could not be determined" until a later
  milestone.
  Settle by a finding that tries each candidate under the real unit on a supported target.
  Default: (c) if it works, otherwise (d). The app-id is not authenticated, and a cgroup name can
  be forged as easily as `/.flatpak-info`, so (c) loses nothing; (b) adds a privileged component
  for a field that is only a record, and is not built in M3. Never (a).
- **Detection through the flatpak proxy.** Which bus-driver calls (`NameHasOwner`,
  `ListActivatableNames`, `StartServiceByName`) `xdg-dbus-proxy` passes for a `--system-talk-name`
  has not been checked. Settle by reading `xdg-dbus-proxy`'s filtering rules and by acceptance 15.
- **Refused calls before authorization** (from M1, still open) now also cover import, delete and
  replace certificate. Aggregation is the recommendation in `docs/findings.md` M1.3. Settle there;
  M3 changes nothing unless a feature adopts it.
