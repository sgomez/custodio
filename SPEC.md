# Custodio — Milestone 6: Browsers and public release

M6 builds on the code of M0–M5 (specs and results in `docs/milestones/`, `docs/findings.md` and
`docs/findings/`, `docs/decisions.md`, `docs/api.md`, `docs/audit.md`, `docs/install.md`). Everything
those milestones established stays true unless this document says otherwise. The route for the
Firefox snap was chosen and tried on a VM before this spec: evidence, verified and inferred claims,
and rejected alternatives are in `docs/reports/firefox-snap.md`. This milestone's features are
numbered from F170.

## Problem

Custodio is ready to be published, but most desktop users could not use it from their browser:

- **Ubuntu's default Firefox is a snap and cannot reach Custodio at all.** It cannot load a module
  from the host's `/usr/lib` (the snap sees its base's `/usr`), and AppArmor denies its calls to
  `com.rfirma.Custodio1` on the system bus (`apparmor="DENIED" operation="dbus_method_call"`). Both
  are verified in the report. The supported snapd routes do not apply: the `dbus` interface needs the
  slot to be a snap and a plug from Mozilla, and the `pkcs11` interface exists only on Ubuntu Core.
  Chromium and Thunderbird snaps have the same rules (inferred).
- **Native Firefox loads no p11-kit module on most systems.** Mozilla's own builds (the tarball and
  Mozilla's `.deb`), and Firefox on Debian and Arch, do not load `p11-kit-proxy.so`, so the person
  registers the module by hand with `modutil`, once per profile (`docs/install.md`). Only Fedora and
  RHEL/Alma's system NSS load it.
- **The release is not documented for the people who will use it.** There is no README, no written
  threat model for the whole product, and nothing warns a person that, without full-disk encryption,
  whoever takes the machine can use their keys.

It matters now because M6 is the public release. The packages are about to be published and the
repository made public; a person who installs Custodio on Ubuntu and finds that Firefox does not see
it has no working route today.

## Threat model

The threat model of M0–M5 holds (`docs/milestones/M4/SPEC.md` and `docs/milestones/M5/SPEC.md`,
"Threat model"). M6 adds one new entry point, the snap sockets, and a command that writes into the
user's home. It adds no new operation on keys.

- **In scope (new):**
  - **A process of another snap, or an unconfined process, using a snap's socket.** Each socket
    serves only peers whose AppArmor label belongs to the snap the socket is for. Unconfined
    processes, processes of other snaps and processes under any other AppArmor profile are refused
    before any call is served, whatever their uid, root included. Unconfined callers keep the system
    bus, which is unchanged.
  - **A snap using the socket for more than listing and signing.** The socket offers listing and
    signing only. Import, delete and certificate replacement are not reachable through it.
  - **Authorization of the real caller.** Every signature through a socket asks polkit about the
    peer process itself, pinned by the pidfd the kernel gives for the connection, and the uid the
    kernel gives for it. Nothing the peer sends (no pid, uid, label or name in a message) is trusted.
    The kernel's peer credentials are taken once per connection. Nothing is cached across calls.
  - **A peer whose identity cannot be established** (no pidfd, no label, a uid that does not map
    to the real one): refused, never treated as another identity.
  - **Replacement of the socket by the snap.** The socket directories are root-owned and writable by
    root alone, so a snap, which AppArmor lets write there, still cannot replace the socket (the DAC
    permissions stop it). The service refuses to serve a socket whose directory does not meet this.
  - **Exhaustion through a socket.** A peer that opens many connections, sends oversized messages or
    stalls in the handshake must not stop the service from serving the bus or other sockets, and must
    not crowd the journal so that signatures fail for lack of an audit entry.
  - **The registration command** never writes outside the invoking user's own browser profiles and
    their snap directories. It never edits a profile a running browser holds, and it never leaves a
    half-written module copy or profile.
- **Out of scope:** everything M0–M5 exclude: a hostile process of the same uid outside any sandbox
  (it can replace the module copy in the user's home, edit profiles and drive the browser), a
  compromised kernel, root controlling the running machine, and tampering with the journal. Also out:
  a compromise of snapd, of AppArmor or of the snap's publisher; a snap whose confinement the person
  loosened (devmode, classic confinement).
- **Not guaranteed:**
  - **The snap route rests on a snapd default rule that no document promises**
    (`/run/snap.@{SNAP_INSTANCE_NAME}/**` in snapd's AppArmor template). If snapd removes it, the
    socket stops working. It fails closed: the browser sees no Custodio slot, and no key or
    authorization is exposed. The end-to-end test of Design 6 is what detects it. It is not a
    supported snapd interface.
  - **Inside the snap, the module copy is code in the user's home.** The browser loads it as the
    user, like any module the user registers. Its integrity rests on the user's account.
  - **A compromised snap can ask for signatures with the user's keys.** It can list the user's keys
    and can request signatures. Each request shows a polkit dialog, as on the bus. A person who
    approves a dialog without reading it authorizes the snap.
  - **Without full-disk encryption, whoever takes the machine can use the keys.** For `tpm` keys
    they cannot copy them. M6 warns when the state directory is not on an encrypted device (Design
    7). The warning is advice: it blocks nothing.
  - **Firefox Flatpak, parallel snap instances (`firefox_x`) and snaps other than `firefox`,
    `chromium` and `thunderbird`** get no socket and see no Custodio slot.
  - **Several dialogs per page in TLS client authentication.** By design: every signature asks.

## Goal

A person who installs the Custodio package on Ubuntu 26.04 and runs one command can authenticate
with their certificate in the default Firefox snap, with a polkit dialog for every signature that
names Firefox's own process. The same command registers the module in native Firefox and its
derivatives. The release ships a README, a threat model, `SECURITY.md` and release notes that say
what Custodio protects against and where it stops.

## Design

The architecture stays: `custodiod` on the system bus as `com.rfirma.Custodio1` under its hardened
unit; the documented API; per-uid ownership; polkit on every sign, import, delete and replace; one
journal entry per authorized call; the PKCS#11 module and the CLI as clients of the documented API.
M6 adds a second way into the same service for confined snaps, a registration command, a warning,
and the release documents.

### 1. The snap sockets

- **Where.** One socket per known snap at `/run/snap.<snap>/custodio.sock`, for exactly `firefox`,
  `chromium` and `thunderbird`. The list is fixed in the shipped files; a person adds no snap by
  configuration.
- **Directories.** `/run/snap.<snap>/` is owned by root, mode `0755`, created by a `tmpfiles.d`
  entry shipped by the package. Not by `RuntimeDirectory=`, which removes the directory when the
  service stops, and not by the service. The socket file is reachable by any uid (the peer check is
  the service's, not the file mode's).
- **Who creates the sockets.** The service runs as an unprivileged dynamic user, with a read-only
  `/run` and in its own user namespace. It cannot create a root-owned socket in a root-owned
  directory. The service manager creates the listening sockets and hands them to the service
  (socket activation). A connection to a socket therefore also starts the service, as a bus call
  does. The service's hardening is not loosened to create them, and the systemd exposure score does
  not rise above M5's.
- **Directory check.** Before it serves a socket, the service checks that its directory is owned by
  root and writable by root alone. If not, it does not serve that socket and records why in the
  journal. The other sockets and the bus are unaffected.
- **Protocol.** Peer-to-peer D-Bus on the socket (no bus daemon), with the same interface name,
  object path, method signatures, error names and error messages as on the bus, so the module keeps
  one client. On the socket the interface has **only `ListKeys` and `Sign`**. Every other method of
  the interface fails as the standard unknown-method error, asks no polkit, writes no journal entry
  and changes nothing. Introspection on the socket shows only those two methods.
- **Peer check, per connection.** On accept, the service reads from the kernel the peer's
  credentials (`SO_PEERCRED`), its pidfd (`SO_PEERPIDFD`) and its security label (`SO_PEERSEC`). It
  serves the connection only if all three are available and the label is an AppArmor label of the
  snap the socket is for (`snap.<snap>.<app or hook>`), in enforce mode. Anything else is refused:
  the connection is closed before any method is served. Which labels of the snap are accepted beyond
  the browser app itself is an open question; the default is any label of that snap in enforce mode.
- **Real uid.** The uid used for ownership and for polkit must be the peer's real uid, as the bus
  reports it today. The service runs with `PrivateUsers=`, under which the kernel translates a peer
  uid outside the namespace to the overflow uid. Any uid that is not the real one is refused, never
  used. How the service obtains the real uid without weakening the unit is an open question.
- **Ownership.** As on the bus: the owner is the peer's uid. `ListKeys` shows only that uid's keys;
  another uid's key id is `NoSuchKey`.
- **Authorization.** Every `Sign` that finds the key asks polkit, action `com.rfirma.custodio.sign`,
  with interaction allowed, on a `unix-process` subject built from the connection's pidfd and uid.
  The same fail-closed rule as the bus applies (`docs/decisions.md`, "polkit fails closed"). A
  peer that has exited makes polkit fail ("Process not found"), and that is a refusal.
- **Journal.** Every entry for a call through a socket records the same fields as a bus call, plus
  which transport carried it and the peer's AppArmor label. These are new documented fields in
  `docs/audit.md`, added under its compatibility rule. `CUSTODIO_PID` is the peer's own pid (there is
  no proxy). Refused connections are recorded at a bounded rate, so a peer cannot flood the journal
  and make signatures fail with `AuditUnavailable`.
- **Limits.** The service bounds what one socket can take: concurrent connections, message size (no
  larger than the bus allows for the same method), and time in the handshake and between messages.
  Hitting a bound closes that connection. The bus and the other sockets keep working. The values are
  the builder's, documented with their reasons.
- **Platforms.** The sockets and directories ship in every package format, the same as the rest of
  the file list. Where snaps are not confined by AppArmor, the peer has no snap label and is
  refused. The snap route is supported and tested on Ubuntu 26.04 only.

Prior art worth copying: the verified prototype of the report (a socket in `/run/snap.firefox/`
reading `SO_PEERCRED`, `SO_PEERPIDFD` and `SO_PEERSEC`); systemd socket activation of D-Bus
services; snapd's own `/run/snapd-snap.socket` and `snapd.socket` (a host service with a socket that
confined snaps reach, checked by peer credentials); polkit's `unix-process` subject with `pidfd`.

### 2. The module chooses its transport

- If `SNAP_INSTANCE_NAME` is set, the module connects to
  `/run/snap.$SNAP_INSTANCE_NAME/custodio.sock` and never to the bus. Outside a snap, it uses the
  system bus as today.
- The module refuses a `SNAP_INSTANCE_NAME` that is not a valid snap instance name, and a socket
  whose directory is not root-owned and writable by root alone. Either way it reports no slots, as
  it does today when the service is absent.
- One connection per call, as today (`docs/decisions.md`, "a connection per call"), with the same
  fork and thread rules. Each call's connection therefore carries fresh kernel credentials.
- Error mapping is unchanged. A refused connection, a missing socket and an absent service all look
  like "service absent" to the PKCS#11 caller (no slots). A refusal in a call maps as on the bus.

### 3. The registration command

A subcommand of `custodio`, run by the person as themselves, that makes the module visible to their
browsers. The name of the subcommand and its options are the builder's; the man page documents them.

- **Native browsers.** For every profile listed in the profile index of a known native browser
  (Firefox, all channels, in both the legacy `~/.mozilla/firefox` and the XDG location that Firefox
  uses since version 147; Thunderbird; and the derivatives a finding confirms), it registers the
  installed module by its installed path in that profile's NSS database.
- **Snaps.** For each of `firefox`, `chromium` and `thunderbird` that is installed and whose profile
  or NSS database exists, it places a copy of the installed module in `~/snap/<snap>/common/` and
  registers the copy's path in that snap's profile(s) or NSS database. The copy's path does not
  change between versions, so a registration stays valid across refreshes.
- **Idempotent.** Running it again changes nothing that is already right and never adds a second
  entry. An existing entry is recognised by the library it points to (the installed module or the
  copy), whatever its name, so an entry the person added by hand with `docs/install.md`'s
  `modutil` line is not duplicated. An entry that points to a Custodio path that no longer exists is
  updated in place.
- **Browsers that already see Custodio through p11-kit.** Where the system NSS loads the p11-kit
  proxy (Fedora, RHEL/Alma), registering native profiles would show the same keys twice. The default
  is not to register native profiles there, and to say why. Snap profiles are still registered,
  because snaps do not see the host's p11-kit. This is to be confirmed (open question).
- **Safety.** It refuses to run as root or under `sudo`, because it writes into the invoking user's
  home. It does not edit a profile whose browser holds it (the profile lock) and reports which one to
  close. It writes copies and profile changes so that an interruption leaves the old state or the
  new one, never a mix. A running browser that has the old copy loaded keeps working until it
  restarts. It touches only entries that point to Custodio.
- **Removal.** The same command can remove every registration and copy it made, with the same
  idempotence. The README says to run it before uninstalling the package. Copies left behind after
  an uninstall are inert: the socket is gone, so the browser sees no slot.
- **Report.** It prints, per browser and profile, what it found and what it did (registered, already
  registered, refreshed, skipped and why). It exits non-zero if any profile it should have handled
  was skipped for a reason the person can fix (a running browser, a profile it could not write).
- **How the NSS database is written** (NSS's own tool as a dependency, or a writer of our own) is an
  open question.

Prior art worth copying: OpenSC's `pkcs11-register` (registers a module in Firefox, Thunderbird and
Chrome profiles, can be re-run); NSS `modutil` and the `pkcs11.txt` format; Ubuntu's guide
"enable smart cards in snapped browsers" (copies modules to `~/snap/firefox/common/`).

### 4. Stale module copies

A package upgrade replaces the installed module but not the copies in the users' homes. The spec
decides:

- **Detection.** A copy is stale when its bytes differ from the installed module's. It is not
  compared by version number, because two builds of one version can differ. The registration command
  checks every copy it finds, on every run.
- **Refresh.** Whenever it runs, the registration command replaces each stale copy atomically, in
  place, at the same path. It refreshes only copies that exist: a refresh never registers a browser
  the person did not register.
- **Automatic refresh.** The package ships a per-user trigger, run by the user's service manager,
  that refreshes existing copies at login and when the installed module changes while the person is
  logged in. The person does not have to remember. Its outcome, success or failure with the reason,
  goes to the user's journal.
- **Never silent.** A copy that could not be refreshed is reported by the trigger (user journal) and
  by the registration command (non-zero exit, naming the copy). Whether the copy should also show it
  at run time, in a place the browser displays, is an open question.
- **Compatibility.** The protocol between module and service stays compatible within the release
  series, so a stale copy keeps working between an upgrade and its refresh. A future incompatible
  change must make an old copy fail visibly (no slots and a journal entry from the service), never
  sign wrongly. A test pins the module–service compatibility of this release.

### 5. The module copy runs on the snap's libraries

Inside a snap, the copy is loaded against the snap's base (its glibc and loader), not the host's.
Each snap's base can be older than the host. The module's ELF requirements (glibc symbol versions,
needed libraries) must fit the oldest base used by the stable channel of the three snaps. A package
gate checks this, with the bases and their glibc recorded with sources in the same way as
`packaging/glibc-ceiling.txt`. The module needs no library that the bases lack.

### 6. End-to-end on the Ubuntu 26.04 VM

The M5 VM target (Ubuntu 26.04 minimal cloud image, `swtpm`, OVMF; `docs/milestones/M5/SPEC.md`,
Design 1) gains a snap group of cases. They use the same case accounting: every case is reported once,
run or skipped, and an unknown or missing case fails the run.

- The run installs the `.deb` as in M5 and the Firefox snap from the store (`stable`). It records
  the snap revision, its base, the snapd version, the AppArmor and dbus-daemon versions, and the label
  the service observed.
- **Through the socket:** as a regular user, a PKCS#11 client runs under the Firefox snap's
  confinement (`snap run --shell firefox`). The client and the module copy are placed in
  `~/snap/firefox/common/` by the registration command. The client lists the user's keys and signs
  with each key type, every signature verifies with `openssl`, polkit was asked once per signature
  about the client's process, and the journal entry carries the snap label.
- **Denied on the bus:** from the same confinement, a call to the service on the system bus is
  denied by AppArmor.
- **Refusals:** an unconfined process connecting to the socket, root included, is refused. A
  process under another snap's label is refused at the Firefox socket (how such a label is obtained
  in the VM, for example a test profile loaded by the harness, is for the contract). On the socket,
  import, delete and replace fail as unknown methods and change nothing.
- **Fail closed:** the case fails, and is not skipped, if the snap is not confined (the observed label
  is not `snap.firefox.*` in enforce mode), if the socket stops being reachable, or if the bus stops
  being denied. Either change means snapd's rules moved, and a person must look.
- **Stale copy:** after an upgrade of the package from N to N+1, the trigger or the command refreshes
  the copy and the client still signs.
- **When.** As in M5: a release test in CI, and in the `verify` of the checkpoint and last features
  only. It needs network for the snap store, like M5's package install.

### 7. Warning about an unencrypted state directory

- The **service** decides whether its state directory is on an encrypted device: the block-device
  chain beneath the filesystem that holds the state directory (what `lsblk` shows for it) contains a
  dm-crypt device. The service does this, not the CLI, because only the service can see its state
  directory. It does this with the access its unit already has and runs no external tool.
- The result is one of *encrypted*, *not encrypted* or *unknown* (a chain the service cannot read, or
  storage it cannot classify, such as a filesystem's own encryption or a network filesystem).
  *Unknown* is never reported as *encrypted*.
- The service records the result in the journal when it starts. It exposes the result to clients
  through a documented, read-only addition to the API (on the bus only), added under the API's
  compatibility rule and checked by `just api-contract`.
- `custodio import` and `custodio list` print a warning when the result is *not encrypted* or
  *unknown*. It says that whoever takes the machine can use the keys, though not copy a `tpm` key,
  and points to the README. The warning blocks nothing.

### 8. Release documents

All in English, in the repository, and linked from the README. Commands they show are run by a test
as written, as `docs/api.md`'s examples are. Prose is checked by a person against the acceptance
list, never by a test that greps wording.

- **Threat model.** One document for the whole product as released. It covers what is protected and
  from whom, in scope, out of scope and not guaranteed, consolidated from M0–M6, including the snap
  socket and its reliance on an undocumented snapd rule, and the full-disk encryption advice.
  `SECURITY.md` links it and its scope adds the snap sockets and the registration command.
- **README for users.** What Custodio is; what it protects against and its limits; the three
  storage kinds and what each protects against (a `tpm` key cannot be copied even by root;
  `encrypted-tpm` and `encrypted-host` are decrypted in the service's memory to sign). It says that
  import falls back to the encrypted kinds without asking (`docs/decisions.md`) and that `custodio
  list` shows each key's kind. It covers the full-disk encryption warning; how to register browsers,
  and to remove the registration before uninstalling; and the limits: the snap route is not a
  supported snapd interface, Firefox Flatpak cannot use it, lost keys need the original `.p12`, and
  TLS client authentication shows several dialogs per page.
- **Release notes** for the first public release: supported systems, what is new since the last
  milestone, known limits, and the upgrade note (keys from before M4 were purged).
- **`docs/install.md`** replaces the manual `modutil` steps with the registration command, keeping
  the manual route as a fallback.
- **Manual acceptance steps** for Design 6's desktop check, in `docs/manual-acceptance.md`.

## Language and harnesses

Rust for the product, as before. Harness code follows the conventions of the existing end-to-end
harness. Every harness of M0–M5 stays and keeps blocking the merge at the same thresholds: unit,
integration and end-to-end tests (the container suite on every target, the VM suite for the
release); `cargo-mutants` with no surviving mutant; coverage and the CRAP gate; `cargo-fuzz`; Miri
and AddressSanitizer on the FFI layer; `rustfmt` and `clippy` with the service's restriction lints;
`cargo-machete` and `cargo-deny`; `taplo`, `typos`, `shellcheck`, `actionlint` and `zizmor`; the
systemd exposure score and the unit and bus-policy checks; the package gates; the API contract
check; commitlint; and `just` as the entry point.

M6 adds, all blocking:

- **Integration tests of the socket transport** against the real service on real sockets, with the
  peer label supplied by a test-only source that never ships (as the test TCTI rule of
  `docs/decisions.md` does for the TPM, with a check that nothing shipped enables it). They cover
  accepted and refused labels, missing credentials, the overflow uid, the unknown methods,
  ownership, polkit on the pidfd subject, the journal fields, the limits and the directory check.
- **Fuzzing** of every new parser of untrusted input: the peer label, and the browser files the
  registration command reads (profile indexes, NSS module lists). The socket's message handling is
  exercised by a fuzz target too.
- **The API contract check** extended to the socket: exactly `ListKeys` and `Sign` are served there,
  and the bus API with the Design 7 addition matches `docs/api.md`.
- **Unit and package checks:** the socket units are exactly the three snaps; the directories come
  from `tmpfiles.d` as root `0755`; the exposure score does not rise; the per-user refresh trigger
  ships in every format; the module's ELF requirements fit the snap bases (Design 5), with a negative
  control.
- **End-to-end:** the registration command against native Firefox (and Thunderbird where the target
  ships it) in the container suite, on each target where they are packaged. The VM snap group
  (Design 6) is a release test.
- **Supply chain:** the snap installed in the VM comes from the store's signed assertions as snapd
  verifies them; the run records the revision. Any new workflow follows the existing pinning rules.

## Scope

- The three snap sockets: `tmpfiles.d` directories, socket activation, peer check, list and sign
  only, polkit on the pidfd subject, journal fields, limits, directory check.
- The module's transport choice inside a snap.
- The registration command for native Firefox and its derivatives and for the three snaps, its
  removal mode, stale-copy detection and refresh, and the per-user automatic refresh trigger.
- The snap-base fit of the module and its gate.
- The VM snap cases and the manual desktop acceptance.
- The encrypted-state-directory check in the service, its API addition and the CLI warning.
- The release documents: threat model, README, `SECURITY.md` update, release notes, `docs/install.md`,
  `docs/api.md` and `docs/audit.md` updates, manual acceptance steps.
- The findings these need.

## Out of scope

- Everything the idea leaves to a person: the external review of the authorization path, the FFI
  layer and the socket; publishing the packages; making the repository public; rFirma's integration;
  the question on the snapcraft forum.
- Firefox Flatpak; parallel snap instances; snaps other than the three; classic or devmode snaps.
- Native Chromium and Chrome (`~/.pki/nssdb`) registration, unless a finding shows they need nothing
  beyond the same NSS registration and the person approves adding them.
- Import, delete or replace through a socket; any new operation on keys; any change to the storage
  kinds, the fallback rule or the PCR guard; the administrator setting that refuses the encrypted
  kinds (`docs/decisions.md`).
- Caching or grouping authorizations to reduce dialogs in TLS client authentication.
- Writing into another snap's data (`/var/snap/...`) or into the administrator's browser policies
  (rejected in the report).
- A snap or Flatpak package of Custodio itself; systemd-sysext.
- Running the snap cases on any distribution other than Ubuntu 26.04.

## Acceptance

Automated, on the host, in the integration suites or in the container suite:

1. The packages install a `tmpfiles.d` entry for each of `/run/snap.firefox/`, `/run/snap.chromium/`
   and `/run/snap.thunderbird/`, and no other. After install, and after a reboot, each directory is
   root-owned with mode `0755` and holds `custodio.sock`. Stopping the service does not remove them.
2. A peer whose label is the socket's snap label in enforce mode lists its own keys and signs. A
   peer that is unconfined, carries another snap's label, carries a non-snap label, carries the
   right snap in complain mode, or lacks a pidfd or a label, is refused before any method is served,
   whatever its uid (root included). Each is a test with the label source of the integration
   harness.
3. On the socket, `ImportP12`, `DeleteKey` and `ReplaceCertificate` fail as unknown methods. They
   show no dialog, write no journal entry and change no file. Introspection lists only `ListKeys`
   and `Sign`.
4. A `Sign` through the socket asks polkit once, on a `unix-process` subject carrying the
   connection's pidfd and the peer's real uid. Denial gives `PolkitDenied`; an unreachable polkit,
   or a peer that has exited, gives `AuthorizationUnavailable`; nothing is cached across calls.
5. A peer whose uid reaches the service as the overflow uid, or whose uid cannot be read, is refused
   (`AuthorizationUnavailable` or a closed connection). It never sees another uid's keys.
6. Every journal entry for a socket call carries the transport and the peer's label in the fields
   `docs/audit.md` documents, and `CUSTODIO_PID` is the peer's pid. Bus entries are unchanged
   except for the transport field.
7. A peer that exceeds the connection, size or time bounds is disconnected. During that, a bus
   client and a peer on another socket still list and sign, and signatures do not fail with
   `AuditUnavailable` because of journal flooding.
8. With a socket directory not owned by root or writable by others, the service does not serve that
   socket and records why. The bus and the other sockets keep working.
9. With `SNAP_INSTANCE_NAME` set, the module uses only the matching socket and never the bus. With an
   invalid instance name, a missing socket or a socket directory that is not root-only, it reports no
   slots.
10. The registration command, run on a home with native Firefox profiles in both the legacy and the
    XDG location, a hand-registered entry, and the three snaps, registers each profile once. A
    second run changes nothing (the profile files are byte-identical). Removal leaves no Custodio
    entry and no copy, and leaves every other module entry as it was. It refuses to run as root. It
    skips a locked profile and exits non-zero naming it. NSS's own tools list exactly one Custodio
    module in each registered profile.
11. In the container suite, on each target that packages native Firefox, Firefox's NSS in a
    registered profile sees the Custodio token and the imported certificate.
12. A copy whose bytes differ from the installed module is reported stale and is replaced at the
    same path by the command and by the per-user trigger. A copy that cannot be replaced makes the
    command exit non-zero and leaves an entry in the user's journal. A refresh never creates a copy
    for a snap that had none.
13. The package gate fails on a module whose ELF requirements exceed the oldest snap base recorded
    (negative control) and passes on the shipped module.
14. The service classifies its state directory as *encrypted* on a dm-crypt chain (including LVM on
    LUKS), *not encrypted* on a plain device and *unknown* where it cannot tell. It records the
    result at start, and `just api-contract` checks the API addition. `custodio import` and `custodio
    list` print the warning for *not encrypted* and *unknown*, and not for *encrypted*.
15. The exposure score of the unit is not higher than M5's, and the shipped units and files enable
    no test-only label source (a check counts it).
16. Every command in the README, the threat model, `docs/install.md` and the release notes runs as
    written in a test.

Automated, on the VM target (release run, checkpoint and last features):

17. Design 6: under `snap run --shell firefox`, a PKCS#11 client in `~/snap/firefox/common/`, set up
    by the registration command, lists the user's keys and signs with an RSA 2048 and a P-256 key.
    Each signature verifies with `openssl`. Each asked polkit about the client's process, and each
    journal entry carries a `snap.firefox.*` label. From the same confinement, a system-bus call to
    the service is denied by AppArmor. An unconfined process and a process under another snap's
    label are refused at the Firefox socket. The run record lists the snap revision, its base, the
    snapd, AppArmor and dbus-daemon versions and the observed label.
18. If the observed label is not a `snap.firefox.*` label in enforce mode, if the socket is not
    reachable from the confinement, or if the bus is not denied, the VM run fails (not skips).
19. After an upgrade of the package from N to N+1, the Firefox snap copy is refreshed without the
    person running anything (the trigger), and case 17's client still signs.

Manual (a person, following steps the milestone ships in `docs/manual-acceptance.md`):

20. On an Ubuntu 26.04 desktop VM with the real Firefox snap from the store, after installing the
    package and running the registration command: Firefox completes TLS client authentication
    against a test server that requires a client certificate, once with an RSA and once with a P-256
    key. A polkit dialog appears for each signature, and refusing it fails the handshake. The journal
    shows each signature with the Firefox label and Firefox's pid. The record names the snap
    revision.
21. A person checks the README, the threat model, `SECURITY.md` and the release notes against
    Design 8's list. Every item is present and agrees with `docs/api.md`, `docs/audit.md` and
    `docs/decisions.md`.

## Open questions

- **The real uid under `PrivateUsers=`.** The unit maps every uid but its own and root's to the
  overflow uid, so `SO_PEERCRED` on a direct socket will not give the person's uid. Candidates: a
  `PrivateUsers=` mode that keeps uids identical (available in systemd 257, the floor); reading the
  uid another way that the kernel guarantees; dropping the user namespace. The last weakens the
  unit. Settle by a finding and a test. If no route keeps the exposure score, that is a `BLOCKED.md`
  question.
- **polkit's `unix-process` pidfd subject on each target.** Verified with polkit 127 on Ubuntu 26.04.
  Which polkit versions accept `{pidfd, uid}`, and what Debian 13's and Alma 10's do with it? The
  service fails closed either way, but the snap route only matters where snaps are confined. Settle
  by a finding.
- **Which labels of the snap to accept.** Any app or hook of the snap (default), or only the browser
  app (`snap.firefox.firefox`, `snap.chromium.chromium`, `snap.thunderbird.thunderbird`)? Narrower is
  more conservative but may break a helper app that loads the module. Settle by a finding on the
  three snaps' apps.
- **Writing the NSS database.** NSS's `modutil` as a runtime dependency (`libnss3-tools`,
  `nss-tools`, `nss`), or a writer of our own for `pkcs11.txt`? The tool knows the format and NSS's
  locking; our own writer adds no dependency but owns a format that NSS does not document as stable.
  Default: NSS's tool. Settle with the approver.
- **Profile locations.** The profile roots of Firefox (legacy and XDG, native and inside the snap
  after Firefox 147), Thunderbird, the Chromium snap's NSS database (`~/snap/chromium/current/...`
  is per revision: does a refresh carry the registration?), and which derivatives to include
  (LibreWolf, Floorp, Waterfox candidates). Settle by a finding per browser; the list is data.
- **Systems whose NSS loads p11-kit.** Is skipping native profiles there right? Mozilla's own
  Firefox on Fedora uses its bundled NSS and would then see nothing. Alternatives: register anyway and
  accept a duplicate token, or tell builds apart by the profile's last-used application. Settle by a
  finding on Fedora 44 and the approver's choice.
- **Snap bases.** Which base does the stable channel of each of the three snaps use today (core22
  has glibc 2.35, core24 2.39)? Settle by a finding. If a base is older than the module can support,
  that snap is out of scope or the module's floor moves: a person's choice.
- **Run-time sign of a stale copy.** Besides the command and the trigger, should a stale copy show
  itself where the browser displays it (for example in the token's label)? That needs the copy to
  learn the service's build identity, an API addition. Default: no. The command and the trigger are
  the guarantee.
- **The per-user trigger.** Enabled for every user by the package (default), or by the registration
  command for the user who registers? The first refreshes copies of users who never log in again
  only at their next login; the second leaves out users who registered by hand. Settle in the
  contract.
- **Packaging the sockets outside Ubuntu.** Default: every format ships them (parity), and they refuse
  every peer where AppArmor does not confine snaps. The alternative is the `.deb` only, with a
  parity exception. Settle with the approver.
- **Bounds.** The values for connections per socket, message size, handshake and idle time, and the
  rate of refusal entries. Settle in the contract, with a reason for each.
- **Classifying the state directory.** How to treat ZFS or `fscrypt` native encryption, btrfs over
  several devices, and dm-crypt reached through dm-integrity or RAID. Default: anything not proven
  to be dm-crypt is *unknown*. Settle by a finding.
- **"A signature" in the manual acceptance.** The idea asks for TLS client authentication *and* a
  signature in the real Firefox snap. Acceptance 20 reads the second as the journal entry of each
  signature. If a different signature was meant (for example a web signing application), the person
  says which.
- **Version and name of the first public release.** For the release notes. A person's choice.
