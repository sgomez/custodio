# Custodio client API

The interface a client sees on the system bus. Service `com.rfirma.Custodio1`, object `/com/rfirma/Custodio1`,
interface `com.rfirma.Custodio1`. `just api-contract` checks the items below (methods, arguments, results,
properties, error names, polkit actions) against the running service, the error type and the shipped policy file;
the prose is not checked.

Key ids are 1 to 59 bytes of `[A-Za-z0-9_-]` and do not end in `-cert`. Mechanisms are the PKCS#11 numbers:
`CKM_RSA_PKCS` 0x0001, `CKM_RSA_PKCS_PSS` 0x000D, `CKM_ECDSA` 0x1041; hashes (PSS only) `CKM_SHA256` 0x0250,
`CKM_SHA384` 0x0260, `CKM_SHA512` 0x0270.

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

Every failure is one of these names, with a fixed message that repeats nothing the caller sent.

- error `com.rfirma.Custodio1.Error.InvalidArgs`: a bad key id, mechanism, hash, salt length, an argument too
  large, or a `certificate` that is not exactly one DER X.509 certificate.
- error `com.rfirma.Custodio1.Error.NoSuchKey`: the caller has no key with this id (also another user's id); `Sign`, `DeleteKey` and `ReplaceCertificate`.
- error `com.rfirma.Custodio1.Error.KeyIdTaken`: `ImportP12` with an id the caller already uses.
- error `com.rfirma.Custodio1.Error.PolkitDenied`: polkit refused the call (`Sign`, `ImportP12`, `DeleteKey` or `ReplaceCertificate`).
- error `com.rfirma.Custodio1.Error.AuthorizationUnavailable`: polkit could not be asked or the caller could not
  be identified.
- error `com.rfirma.Custodio1.Error.WrongPasswordOrBadP12`: the `.p12` did not open or is not usable, including a
  `.p12` with no private key, several private keys, or a key without a certificate.
- error `com.rfirma.Custodio1.Error.UnsupportedKeyType`: the key is neither RSA 2048 nor ECDSA P-256.
- error `com.rfirma.Custodio1.Error.CertificateMismatch`: the certificate does not belong to the private key (`ImportP12`, `ReplaceCertificate`).
- error `com.rfirma.Custodio1.Error.AuditUnavailable`: the audit record could not be written, so nothing was done (an imported key is removed again; a key being deleted is restored; a replaced certificate is put back).
- error `com.rfirma.Custodio1.Error.Internal`: any other failure (store, key, signing, a delete that could not remove a file, a replace that could not store the certificate).

## Polkit actions

- action `com.rfirma.custodio.sign`: asked on every `Sign`, `auth_self`, never kept.
- action `com.rfirma.custodio.import-certificate`: for importing a certificate, `auth_self`, never kept.
- action `com.rfirma.custodio.delete-certificate`: for deleting a certificate, `auth_self`, never kept.
- action `com.rfirma.custodio.replace-certificate`: for replacing a certificate, `auth_self`, never kept.
