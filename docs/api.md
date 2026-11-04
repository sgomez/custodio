# Custodio client API

The interface a client sees on the system bus. Service `com.rfirma.Custodio1`, object `/com/rfirma/Custodio1`,
interface `com.rfirma.Custodio1`. `just api-contract` checks the items below (methods, arguments, results,
properties, error names, polkit actions) against the running service, the error type and the shipped policy file;
the prose is not checked.

Key ids are 1 to 59 bytes of `[A-Za-z0-9_-]` and do not end in `-cert`. Mechanisms are the PKCS#11 numbers:
`CKM_RSA_PKCS` 0x0001, `CKM_RSA_PKCS_PSS` 0x000D, `CKM_ECDSA` 0x1041; hashes (PSS only) `CKM_SHA256` 0x0250,
`CKM_SHA384` 0x0260, `CKM_SHA512` 0x0270.

## Detection

How a client finds out whether Custodio can be used. Each example below is run by `scripts/test-docs-api.sh` on a private
bus, as written, with `--system` pointed at that bus; the results shown are what it checks. Use the steps in order:

1. Connect to the system bus. Inside flatpak the bus socket is the one of `xdg-dbus-proxy`. A failure to connect is not
   a Custodio problem.
2. `NameHasOwner` of `com.rfirma.Custodio1` is `true`: Custodio is installed and running. Go on to call it.
3. `false`: look for the name in `ListActivatableNames`. If it is listed, Custodio is installed but not running: go to
   step 4. If it is not listed, Custodio is not installed, or the sandbox does not let the application see it (see
   "From a flatpak"): tell the person to install Custodio and, inside flatpak, to check the permission below.
4. Call `StartServiceByName` with the name and flags 0 (or just make the call: the bus starts the service). A result of
   `1` or `2` means it started. Treat any error as not activatable and show its name and message to the person; do not
   rely on one error name, because the name depends on the bus (see below).
5. After that, every error comes from Custodio and is one of the names under "Errors", not a detection result.

On a host where the service is not installed, the steps give this (dbus-daemon shown; `ServiceUnknown` is the error name):

```console server=absent fails=yes
$ busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s com.rfirma.Custodio1
b false
$ busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListActivatableNames | grep -qF '"com.rfirma.Custodio1"' || echo not listed
not listed
$ busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su com.rfirma.Custodio1 0
Call failed: The name com.rfirma.Custodio1 was not provided by any .service files
```

And when the service runs:

```console
$ busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s com.rfirma.Custodio1
b true
```

### The three situations

| Situation | `NameHasOwner` | `ListActivatableNames` | `StartServiceByName` |
|---|---|---|---|
| Running | `true` | lists the name | `2` (already running) |
| Installed, not activatable | `false` | lists the name | an error (see below) |
| Not installed, or blocked by the sandbox | `false` | does not list the name | `ServiceUnknown` |

What "not activatable" looks like depends on the bus, so branch only on the failure: `ServiceUnknown` or `NameHasNoOwner`
(dbus-broker), `org.freedesktop.systemd1.UnitMasked` or `org.freedesktop.systemd1.NoSuchUnit` (dbus-daemon under
systemd), or no reply at all (dbus-daemon, a unit that fails to start; the call times out after 25 s). On a bus without
systemd that runs the activation file, `org.freedesktop.DBus.Error.Spawn.ChildExited`. `GetNameOwner` fails with
`NameHasNoOwner` whenever the service does not run. The message text is for people and is not part of the interface.

### From a flatpak

A sandboxed application sees only the bus names it is allowed to talk to. Give it the permission with the
`finish-args` entry `--system-talk-name=com.rfirma.Custodio1`, or for one user:

```sh
flatpak override --user --system-talk-name=com.rfirma.Custodio1 org.example.App
```

With the permission, through the proxy every step above gives the same result as on the host, including the error
names. Without it, the name is blocked by the sandbox and absent from `ListActivatableNames`: `NameHasOwner` is `false`
and a call fails as `ServiceUnknown`, never as `AccessDenied`. A service that is absent and a service that is blocked
look the same through the proxy, so the client cannot tell them apart; when the name is missing from the list inside
flatpak, tell the person both causes and name the permission as the one to check.

## Calling with gdbus

The `org.freedesktop.Platform` flatpak runtime ships `gdbus` and `dbus-send`, not `busctl` (`docs/findings/F102.md`). With
`gdbus` the detection and a `Sign` are (`gdbus` reads the argument types from introspection; `$digest` is the GVariant
text of the bytes, such as `[byte 0x00, byte 0x00, …]`):

```sh
gdbus call --system --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.NameHasOwner com.rfirma.Custodio1
gdbus call --system --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.ListActivatableNames
gdbus call --system --dest com.rfirma.Custodio1 --object-path /com/rfirma/Custodio1 --method com.rfirma.Custodio1.Sign p256 4161 0 0 "$digest"
```

They print `(true,)`, a tuple of an array of names, and `([byte 0x…, …],)` with the signature's bytes.

## Properties

None.

## Methods

### Method `ListKeys`

`(key id, key type, DER certificate)` for every key of the caller, and no other. The owner is the uid the bus
reports for the calling connection (checked against its `ProcessFD`); no method takes an owner or a uid. The key
type is `rsa2048` or `ecdsa-p256`, as `ImportP12` returns it. Asks no polkit. If the caller cannot be identified
the call fails as `AuthorizationUnavailable`, never with an empty list. A key whose certificate cannot be read
fails the call as `Internal` instead of being left out.

One method gives everything a client lists (the PKCS#11 module needs nothing else), so there is no separate
method for certificates.

- out: `a(ssay)`
- bounds: none.

### Method `ImportP12`

Imports a `.p12` as key `id` of the caller; returns the key type. A different user may use the same `id`;
`KeyIdTaken` is only for the caller's own ids.

The order is fixed: (1) the arguments are checked against the bounds below (`InvalidArgs`); (2) the caller is
identified; (3) the caller's own ids are checked (`KeyIdTaken`); (4) polkit is asked once, with
`AllowUserInteraction`, under the action `com.rfirma.custodio.import-certificate` (`PolkitDenied`, or
`AuthorizationUnavailable` if polkit cannot be asked); (5) only after approval is the `.p12` decoded with the
password (`WrongPasswordOrBadP12`, `UnsupportedKeyType`, `CertificateMismatch`) and stored. So a wrong password
is reported as `PolkitDenied` or `AuthorizationUnavailable` when polkit refuses, and the `.p12` is never opened
without approval. Every call asks again; nothing is cached. A refused call changes nothing.

Once the caller is identified and owns no such id, every call leaves exactly one import entry in the journal (see
`docs/audit.md`), recorded before the reply. If the entry cannot be recorded, the imported key and its certificate
are removed again and the call fails with `AuditUnavailable`: a key is never kept without its entry.

- in `id`: `s`
- in `p12`: `ay`
- in `password`: `s`
- out: `s`
- bounds: `id` as above; the password is at most 1024 bytes; RSA 2048 or ECDSA P-256 with one private key and a
  certificate.
- p12 size: `1048576` bytes at most.

### Method `DeleteKey`

Deletes the caller's key `id` together with its certificate. Nothing is kept: afterwards `ListKeys` does not show
the id, `Sign` fails as `NoSuchKey`, neither file is left in the state directory and the id can be imported again.

The order is fixed: (1) `id` is checked against the bounds below (`InvalidArgs`); (2) the caller is identified
(`AuthorizationUnavailable`); (3) the id is looked up among the caller's keys only: a missing id and another user's
id both fail as `NoSuchKey`, with no polkit call; (4) polkit is asked once, with `AllowUserInteraction`, under the
action `com.rfirma.custodio.delete-certificate` (`PolkitDenied`, or `AuthorizationUnavailable` if polkit cannot be
asked); (5) the key is made unusable, the journal entry is submitted, and only then the key file is removed, then
the certificate. Every call asks again; nothing is cached. A denied or unavailable polkit leaves the key and the
certificate in place. Once polkit has been asked (and also when the caller is unknown, once `id` is valid) the call
leaves exactly one entry, whatever the outcome. If the entry cannot be submitted the call fails as
`AuditUnavailable` and the key is as it was: listed, signing, both files untouched. While the entry is pending
`Sign` and a second `DeleteKey` fail as `NoSuchKey`, `ListKeys` omits the id and `ImportP12` of it still fails as
`KeyIdTaken`.

The key goes first, so a failure never leaves a key without its certificate. If the key could not be removed,
both files stay and the call fails as `Internal`. If the certificate could not be removed after the key went, the
call fails as `Internal`; the id is no longer listed and `Sign` fails as `NoSuchKey`, but a leftover certificate
still counts as taken for `ImportP12`. A `DeleteKey` after the service restarts removes the leftover certificate (a
certificate without a key is found by the lookup), as it does for one left over some other way, such as a crash. Anything in the area that is not a plain file of the service
is never touched; such an entry keeps the id taken until an administrator removes it. A key whose removal failed
after the entry went out stays unusable (not listed, `NoSuchKey` for `Sign` and `DeleteKey`) until the service
restarts, though its files may still be there.

Deletes of one id run one at a time, from the lookup to the end: the second one waits, and asks polkit only if the
key is still there once the first has finished. Of two simultaneous deletes of one id exactly one succeeds and the
other fails as `NoSuchKey`. A `Sign` that
already found the key when the delete finishes completes with it; one that looks up later fails as `NoSuchKey`.

- in `id`: `s`
- bounds: `id` as above.

### Method `ReplaceCertificate`

Replaces the certificate stored for the caller's key `id` with another DER X.509 certificate for the same public
key. The key itself is not changed. Afterwards `ListKeys` shows the new certificate with the same id and key type.

The order is fixed: (1) `id` is checked against the bounds below, and `certificate` against the size bound and
against parsing as exactly one DER X.509 certificate, no trailing bytes (`InvalidArgs`), before the caller, any
key, any file or polkit is touched; (2) the caller is identified (`AuthorizationUnavailable`); (3) the id is
looked up among the caller's keys only: a missing id, another user's id and a key a `DeleteKey` has made unusable
all fail as `NoSuchKey`, with no polkit call; (4) polkit is asked once, with `AllowUserInteraction`, under the
action `com.rfirma.custodio.replace-certificate` (`PolkitDenied`, or `AuthorizationUnavailable` if polkit cannot be
asked); (5) the public key of the certificate is compared with the public key of the stored private key: a
certificate for another key, or for a key of another type (including P-384, Ed25519 and RSA of other sizes), fails as
`CertificateMismatch` and nothing changes; (6) the certificate is stored. Every call asks again; nothing is cached.
A refused call changes nothing. There are no chain, revocation or date checks, and no check of key usage or subject:
an expired or self-signed certificate for the key is accepted, and so is the certificate already stored.

The replacement is atomic: the new certificate is written to a temporary file, synced, and renamed over the old one,
so a concurrent `ListKeys` sees the old or the new certificate, never an error or a missing one. If anything fails
before the rename the old certificate stays and no temporary file is left; a failure of the final directory sync
comes after the rename (the new certificate is in place). Either way the call fails as `Internal`. A replace and a
`DeleteKey` of one id never run at the same time (the second waits for the first); a replace that finds the key gone
fails as `NoSuchKey` and leaves no certificate behind.

Once polkit has been asked, the call leaves exactly one journal entry (`replace_certificate`), submitted after the
store and before the reply, and the call fails as `AuditUnavailable` with the old certificate put back if the entry
cannot be submitted. If that restore fails too, the reply is still `AuditUnavailable`. See `audit.md`.

- in `id`: `s`
- in `certificate`: `ay`
- bounds: `id` as above; one DER X.509 certificate, nothing else.
- certificate size: `16384` bytes at most.

### Method `Sign`

Signs `data` with the caller's key `id`, after polkit approves this one call. The key is looked up among the
caller's keys first: a missing id and another user's id both fail as `NoSuchKey`, with no polkit call. Every call
that finds the key asks polkit; nothing is cached.

- in `id`: `s`
- in `mechanism`: `u`
- in `hash`: `u`
- in `salt_len`: `u`
- in `data`: `ay`
- out: `ay`
- bounds: `id` as above; `data` at most 1024 bytes; `mechanism` one of the three above; `hash` is 0 unless the
  mechanism is `CKM_RSA_PKCS_PSS`, where it must be one of the three hashes; `salt_len` is 0 unless PSS.

## Errors

Every failure is one of these names, with a fixed message that repeats nothing the caller sent. A client library
gives the name; `busctl` prints only `Call failed: ` and the message. The messages are different for every name, so the
`Message` of an item tells which one `busctl` showed. Branch on the name, never on the message. Unless an item says
otherwise, the call changed nothing.

- error `com.rfirma.Custodio1.Error.InvalidArgs`: a bad key id, mechanism, hash, salt length, an argument too
  large, or a `certificate` that is not exactly one DER X.509 certificate. Message `invalid arguments`.
- error `com.rfirma.Custodio1.Error.NoSuchKey`: the caller has no key with this id (also another user's id); `Sign`, `DeleteKey` and `ReplaceCertificate`. Message `no such key`.
- error `com.rfirma.Custodio1.Error.KeyIdTaken`: `ImportP12` with an id the caller already uses. Message `a key with this id already exists`.
- error `com.rfirma.Custodio1.Error.PolkitDenied`: polkit refused the call (`Sign`, `ImportP12`, `DeleteKey` or `ReplaceCertificate`). Message `not authorized`.
- error `com.rfirma.Custodio1.Error.AuthorizationUnavailable`: polkit could not be asked or the caller could not
  be identified. Message `authorization unavailable`.
- error `com.rfirma.Custodio1.Error.WrongPasswordOrBadP12`: the `.p12` did not open or is not usable, including a
  `.p12` with no private key, several private keys, or a key without a certificate. Message `wrong password or unreadable .p12 file`.
- error `com.rfirma.Custodio1.Error.UnsupportedKeyType`: the key is neither RSA 2048 nor ECDSA P-256. Message `unsupported key type`.
- error `com.rfirma.Custodio1.Error.CertificateMismatch`: the certificate does not belong to the private key (`ImportP12`, `ReplaceCertificate`). Message `certificate does not match the key`.
- error `com.rfirma.Custodio1.Error.AuditUnavailable`: the audit record could not be written, so nothing was done (an imported key is removed again; a key being deleted is restored; a replaced certificate is put back). Message `audit unavailable`.
- error `com.rfirma.Custodio1.Error.TpmFailed`: `ImportP12` only: the TPM is present but failed or cannot be used (it could not be opened, answered with an error, or its owner hierarchy is unusable). Nothing was stored, and the key was not stored in a weaker form instead. Message `the TPM failed or cannot be used`.
- error `com.rfirma.Custodio1.Error.CredentialsUnavailable`: `ImportP12` only: the credential service is down or refused to encrypt the key, so it was not stored. Message `the credential service is unavailable`.
- error `com.rfirma.Custodio1.Error.Internal`: any other failure (store, key, signing, a delete that could not remove a file, a replace that could not store the certificate). Message `internal error`.

## Polkit actions

Every call that changes a key or signs asks polkit once, and asks again on the next call: nothing is cached. The
question is asked with interaction allowed, so the person's polkit agent shows an authentication dialog (`auth_self`:
the person proves who they are; no administrator is needed). `ListKeys` asks nothing and shows no dialog. A call that
fails on its arguments or on an unknown key id fails before polkit is asked, so it shows no dialog either.

| Method | Action | Dialog |
|---|---|---|
| `ListKeys` | none | no dialog |
| `ImportP12` | `com.rfirma.custodio.import-certificate` | dialog on every call |
| `DeleteKey` | `com.rfirma.custodio.delete-certificate` | dialog on every call |
| `ReplaceCertificate` | `com.rfirma.custodio.replace-certificate` | dialog on every call |
| `Sign` | `com.rfirma.custodio.sign` | dialog on every call |

- action `com.rfirma.custodio.sign`: asked on every `Sign`, `auth_self`, never kept.
- action `com.rfirma.custodio.import-certificate`: for importing a certificate, `auth_self`, never kept.
- action `com.rfirma.custodio.delete-certificate`: for deleting a certificate, `auth_self`, never kept.
- action `com.rfirma.custodio.replace-certificate`: for replacing a certificate, `auth_self`, never kept.

If the person cancels or fails the dialog the call fails as `PolkitDenied`; if polkit cannot be asked at all, as
`AuthorizationUnavailable`. Neither is a reason to retry in a loop: each retry shows a new dialog.

## Ownership

Every key belongs to the uid the bus reports for the calling connection. No method takes an owner or a uid argument,
so a client cannot name one. Consequences for a client:

- `ListKeys` shows the caller's keys only. Another user's key is neither listed nor reachable.
- Another user's id is `NoSuchKey` for `Sign`, `DeleteKey` and `ReplaceCertificate`, exactly like an id that does not
  exist, so a client learns nothing about other users' ids. Two users may use the same id; `KeyIdTaken` is only for the
  caller's own ids.
- Two programs of one user share the user's keys. A key is not tied to the program that imported it.
- The owner is the user of the process on the bus, not the user who approves in the dialog. A caller the service
  cannot identify gets `AuthorizationUnavailable`, never an empty list.

## What is journalled

Each of `sign`, `import`, `delete` and `replace_certificate` leaves an entry in the systemd journal, written by the
service before it replies, so the person who runs the machine can see what was done with their keys. An entry names
the user and process of the caller (`CUSTODIO_UID`, `CUSTODIO_PID`), the key id (`CUSTODIO_KEY_ID`), the operation,
and the outcome, and never holds a key, a password or the data signed. It also records, in `CUSTODIO_APP_ID_STATE` and
`CUSTODIO_APP_ID`, the flatpak app-id of the caller when the service could read one. The app-id is a record to search
by: it is not authenticated, and it never changes what the service allows. For a flatpak caller `CUSTODIO_PID` is the
pid of the proxy. If an entry cannot be written the call fails as `AuditUnavailable` and changes nothing. The fields,
outcomes and queries are in [audit.md](audit.md).

## Hashing stays in the client

The service signs the bytes it is given and never hashes `data`; the client prepares them for the mechanism, as with
PKCS#11. `Sign` takes at most 1024 bytes.

- `CKM_ECDSA`: `data` is the digest (for example 32 bytes of SHA-256). The result is the raw `r || s`, 64 bytes for
  P-256, not the DER form that `openssl` reads; the example below converts it.
- `CKM_RSA_PKCS`: `data` is the whole `DigestInfo` the client built: the DER prefix of the hash followed by the digest
  (for SHA-256 the 19 bytes `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`, then the 32-byte digest). The
  service adds only the PKCS#1 v1.5 padding.
- `CKM_RSA_PKCS_PSS`: `data` is the digest, `hash` names the hash that made it (its length must match) and `salt_len` is
  the salt length. MGF1 uses the same hash. The service does the PSS padding and never hashes the message.

## TPM capabilities

The service keeps a key in the TPM only when the TPM has everything the key type needs. It asks the TPM once, with
`TPM2_GetCapability` and `TPM2_TestParms` (nothing is created in the TPM), and sorts it into one of four results: *absent*
(the platform exposes no TPM device), *lacks* (the TPM answered and these items are absent, each named), *ready*, or an
*error* (a device that cannot be opened, a TPM error with its response code, or an owner hierarchy the service cannot use:
an authorization value is set, or the hierarchy is disabled). An error is never read as absent or as lacking, and it
wins when both apply. The list comes from `docs/findings/F107.md`, as the decisions "TPM parent" and "the service
pads" in `docs/decisions.md` narrow it: the parent of every TPM key is an ECC P-256 primary with AES-128-CFB and a SHA-256
name, RSA keys carry `sign|decrypt` and the service pads, P-256 keys sign with `TPM2_Sign`. SHA-384 and SHA-512 are on no
list: a TPM without SHA-512 (the hardware TPM of F111) is *ready*.

| Item | Query | Why | RSA 2048 | ECC P-256 |
|---|---|---|---|---|
| `algorithm ECC` | `GetCapability(ALGS)`, `0x0023` | the parent | yes | yes |
| `curve NIST P-256` | `GetCapability(ECC_CURVES)`, `0x0003` | the parent | yes | yes |
| `name algorithm SHA-256` | `GetCapability(ALGS)`, `0x000b` | the parent's name | yes | yes |
| `algorithm AES` | `GetCapability(ALGS)`, `0x0006` | the parent's symmetric | yes | yes |
| `parent template ECC P-256 AES-128-CFB` | `TestParms` | the parent | yes | yes |
| `command CreatePrimary` | `GetCapability(COMMANDS)` | the parent | yes | yes |
| `command Import` | `GetCapability(COMMANDS)` | importing a key | yes | yes |
| `command Load` | `GetCapability(COMMANDS)` | loading a key | yes | yes |
| `algorithm RSA` | `GetCapability(ALGS)`, `0x0001` | the key | yes | no |
| `rsa2048 null scheme` | `TestParms` | the key | yes | no |
| `command RSA_Decrypt` | `GetCapability(COMMANDS)` | the raw operation | yes | no |
| `ECDSA with SHA-256 on P-256` | `TestParms` | the key | no | yes |
| `command Sign` | `GetCapability(COMMANDS)` | the signature | no | yes |

An item made of another is not asked and not named when that one is absent: the curve is folded into `algorithm ECC`;
the parent template is folded into `algorithm ECC`, `curve NIST P-256` and `algorithm AES`; `rsa2048 null scheme` into
`algorithm RSA`; `ECDSA with SHA-256 on P-256` into `algorithm ECC`, `curve NIST P-256` and `name algorithm SHA-256`.
`TestParms` counts a combination as absent only for the response codes "type", "scheme", "hash" and "curve" (the
parameter number and the `P` bit are ignored, so `0x1C3` is a hash); any other code is an error.

## Compatibility rule

What `docs/audit.md` fixes for the journal, see [its compatibility rule](audit.md#compatibility-rule): documented names
are only added to, never changed, and a client parses fields, not `MESSAGE`. For this interface the same holds as far
as this document promises it: the method, argument, error and action names listed here keep their names and meaning,
and new ones may appear, so handle an error name you do not know as a failure of the call.

## Examples

One short `busctl` example per operation, in the order that carries state from one to the next. Each block is run by
`scripts/test-docs-api.sh` against the service on a private bus with a scripted polkit, and the lines after a command
are what it must print. On a real machine the commands read the same with the real polkit, which shows its dialog.
`<DER>` stands for a certificate: the byte count, then that many decimal bytes starting `48 130`. A key is owned by
the calling user, so run them as one user.

First the files the examples use: a P-256 key, a `.p12` for it (password `secret`), a second certificate for the
same key, and a certificate for another key.

```console
$ openssl ecparam -name prime256v1 -genkey -noout -out demo.key
$ openssl req -new -x509 -key demo.key -subj /CN=demo -days 30 -out demo.pem
$ openssl pkcs12 -export -inkey demo.key -in demo.pem -passout pass:secret -out demo.p12
$ openssl req -new -x509 -key demo.key -subj /CN=renewed -days 60 -outform der -out renewed.der
$ openssl ecparam -name prime256v1 -genkey -noout -out other.key
$ openssl req -new -x509 -key other.key -subj /CN=other -days 30 -outform der -out other.der
```

`ListKeys` with nothing imported yet: an empty array, no dialog.

```console op=ListKeys
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys
a(ssay) 0
```

`ImportP12` takes the id, the bytes of the file and the password, and returns the key type. A refused dialog is
`PolkitDenied`:

```console op=ImportP12 polkit=deny action=com.rfirma.custodio.import-certificate error=PolkitDenied
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says demo $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) secret
Call failed: not authorized
```

If polkit cannot be asked, the call fails as `AuthorizationUnavailable`:

```console op=ImportP12 polkit=unreachable action=com.rfirma.custodio.import-certificate error=AuthorizationUnavailable
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says demo $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) secret
Call failed: authorization unavailable
```

A wrong password is only reported after the person approved, as `WrongPasswordOrBadP12`:

```console op=ImportP12 polkit=approve action=com.rfirma.custodio.import-certificate error=WrongPasswordOrBadP12
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says demo $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) wrong
Call failed: wrong password or unreadable .p12 file
```

A bad id is `InvalidArgs`, before polkit is asked (no action):

```console op=ImportP12 polkit=approve error=InvalidArgs
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says 'bad id' $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) secret
Call failed: invalid arguments
```

The import that works:

```console op=ImportP12 polkit=approve action=com.rfirma.custodio.import-certificate
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says demo $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) secret
s "ecdsa-p256"
```

The same id again is `KeyIdTaken`, also before polkit is asked:

```console op=ImportP12 polkit=approve error=KeyIdTaken
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ImportP12 says demo $(wc -c < demo.p12) $(od -An -v -tu1 demo.p12) secret
Call failed: a key with this id already exists
```

`ListKeys` now shows the key with its certificate (`<DER>`):

```console op=ListKeys
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys
a(ssay) 1 "demo" "ecdsa-p256" <DER>
```

`ReplaceCertificate` takes the id and one DER certificate for the same key. A certificate for another key is
`CertificateMismatch`:

```console op=ReplaceCertificate polkit=approve action=com.rfirma.custodio.replace-certificate error=CertificateMismatch
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ReplaceCertificate say demo $(wc -c < other.der) $(od -An -v -tu1 other.der)
Call failed: certificate does not match the key
```

The right certificate returns nothing:

```console op=ReplaceCertificate polkit=approve action=com.rfirma.custodio.replace-certificate
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ReplaceCertificate say demo $(wc -c < renewed.der) $(od -An -v -tu1 renewed.der)
```

`Sign` with `CKM_ECDSA` (4161): the client makes the SHA-256 digest with `openssl`, the service signs those 32 bytes, and
the client turns the raw `r || s` into the DER signature that `openssl` verifies against the certificate `ListKeys`
returned. The check succeeds only if the service did not hash the digest again.

```console op=Sign polkit=approve action=com.rfirma.custodio.sign
$ printf 'hello' > message.bin
$ digest=$(openssl dgst -sha256 -binary message.bin | od -An -v -tu1)
$ sig=$(busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 Sign suuuay demo 4161 0 0 32 $digest)
$ echo "$sig" | cut -d' ' -f1,2
ay 64
$ set -- $sig; shift 2
$ printf 'asn1=SEQUENCE:s\n[s]\nr=INTEGER:0x%s\ns=INTEGER:0x%s\n' "$(printf '%02x' "${@:1:32}")" "$(printf '%02x' "${@:33:32}")" > sig.cnf
$ openssl asn1parse -genconf sig.cnf -noout -out sig.der
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys | awk '{ for (i = 6; i <= NF; i++) printf "\\%03o", $i }' | xargs -0 printf > listed.der
$ openssl x509 -inform der -in listed.der -pubkey -noout > pub.pem
$ openssl dgst -sha256 -verify pub.pem -signature sig.der message.bin
Verified OK
```

An id the caller does not have is `NoSuchKey`, before polkit is asked:

```console op=Sign polkit=approve error=NoSuchKey
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 Sign suuuay nobody 4161 0 0 32 $(openssl dgst -sha256 -binary message.bin | od -An -v -tu1)
Call failed: no such key
```

`DeleteKey`. A refused dialog leaves the key:

```console op=DeleteKey polkit=deny action=com.rfirma.custodio.delete-certificate error=PolkitDenied
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 DeleteKey s demo
Call failed: not authorized
```

An approved one removes the key and its certificate, and returns nothing:

```console op=DeleteKey polkit=approve action=com.rfirma.custodio.delete-certificate
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 DeleteKey s demo
```

Afterwards the list is empty again:

```console op=ListKeys
$ busctl --system call com.rfirma.Custodio1 /com/rfirma/Custodio1 com.rfirma.Custodio1 ListKeys
a(ssay) 0
```
