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
`KeyIdTaken` is only for the caller's own ids. Needs no polkit authorization.

- in `id`: `s`
- in `p12`: `ay`
- in `password`: `s`
- out: `s`
- bounds: `id` as above; the password is at most 1024 bytes; RSA 2048 or ECDSA P-256 with one private key and a
  certificate.
- p12 size: `1048576` bytes at most.

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

- error `com.rfirma.Custodio1.Error.InvalidArgs`: a bad key id, mechanism, hash, salt length, or an argument too
  large.
- error `com.rfirma.Custodio1.Error.NoSuchKey`: the caller has no key with this id (also another user's id).
- error `com.rfirma.Custodio1.Error.KeyIdTaken`: `ImportP12` with an id the caller already uses.
- error `com.rfirma.Custodio1.Error.PolkitDenied`: polkit refused the signature.
- error `com.rfirma.Custodio1.Error.AuthorizationUnavailable`: polkit could not be asked or the caller could not
  be identified.
- error `com.rfirma.Custodio1.Error.WrongPasswordOrBadP12`: the `.p12` did not open or is not usable, including a
  `.p12` with no private key, several private keys, or a key without a certificate.
- error `com.rfirma.Custodio1.Error.UnsupportedKeyType`: the key is neither RSA 2048 nor ECDSA P-256.
- error `com.rfirma.Custodio1.Error.CertificateMismatch`: the certificate does not belong to the private key.
- error `com.rfirma.Custodio1.Error.AuditUnavailable`: the audit record could not be written, so nothing was done.
- error `com.rfirma.Custodio1.Error.Internal`: any other failure (store, key, signing).

## Polkit actions

- action `com.rfirma.custodio.sign`: asked on every `Sign`, `auth_self`, never kept.
- action `com.rfirma.custodio.import-certificate`: for importing a certificate, `auth_self`, never kept.
- action `com.rfirma.custodio.delete-certificate`: for deleting a certificate, `auth_self`, never kept.
- action `com.rfirma.custodio.replace-certificate`: for replacing a certificate, `auth_self`, never kept.
