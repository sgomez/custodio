# Audit entries

`custodiod` writes one journal entry for every request to sign, import a key, delete a key or replace a
certificate that reaches authorization, whatever the result; `CUSTODIO_OPERATION` says which
(`sign`, `import`, `delete` or `replace_certificate`). A request refused before that leaves no entry: invalid arguments, and a key id the caller does not have
(missing, or another user's: `NoSuchKey`, no polkit call). A request whose caller the bus cannot name gets an
entry without uid and pid. This page
is the interface administrators can rely on when they search, alert on or forward these entries.

## Compatibility rule

Names, identifier and priorities are only added to, never changed: a field, outcome value or
`MESSAGE_ID` that is documented here keeps its name and meaning; new ones may appear.
The text of `MESSAGE` is for people; parse the fields instead.

## Identifier

`MESSAGE_ID` identifies the kind of entry, one per operation:

| Operation | `MESSAGE_ID` |
|---|---|
| `sign` | `29c3d30e6c4242406c6db3f120d36401` |
| `import` | `4c7163ce45d0b9faf8e7c38d098bdb22` |
| `delete` | `13d1a981ea8f64fc1a6f390bee7fd66c` |
| `replace_certificate` | `336e0b53720a735afb179ebc7f779ed6` |

A journal catalog (`/usr/lib/systemd/catalog/custodio.catalog`, shipped by the package) explains each in
`journalctl -x`. Entries written before `CUSTODIO_OPERATION` existed are signing entries without it; the
signing `MESSAGE_ID` never changed.

## Fields

| Field | Meaning | Present |
|---|---|---|
| `MESSAGE` | Text of the entry; see the shapes below | always |
| `MESSAGE_ID` | The identifier above | always |
| `PRIORITY` | Syslog priority; see the outcomes | always |
| `SYSLOG_IDENTIFIER` | `custodiod` | always |
| `CUSTODIO_UID` | User id of the calling process, decimal, as the bus reported it | absent when the bus named no caller |
| `CUSTODIO_PID` | Process id of the calling process, decimal | omitted when the bus named no caller |
| `CUSTODIO_KEY_ID` | Id of the key that was asked for | always |
| `CUSTODIO_OPERATION` | What was asked: `sign`, `import`, `delete` or `replace_certificate` | always |
| `CUSTODIO_OUTCOME` | Result, one of the values of the operation below | always |
| `CUSTODIO_MECHANISM` | Signature mechanism, one of the values below | signing entries only; omitted when it was not known |
| `CUSTODIO_KEY_TYPE` | Type of the imported key: `rsa_2048` or `ecdsa_p256` | import entries only; omitted when the file did not get far enough to have one (an unreadable file, a wrong password, a refusal before decoding) |

## Outcomes

Each operation has its own outcomes; an outcome is only written with its operation. The key id of
`CUSTODIO_KEY_ID` is the one asked for. No entry carries the `.p12` file, a password, certificate bytes,
data or a signature.

### sign

| Outcome | Priority | Meaning |
|---|---|---|
| `signed` | 6 | Authorized and signed |
| `denied` | 5 | polkit denied the request |
| `authorization_unavailable` | 4 | polkit could not decide, or the caller was unknown (including a bus reply without a `ProcessFD` that names the `ProcessID`); nothing was signed |
| `signing_failed` | 3 | Authorized, but signing failed |

### import

| Outcome | Priority | Meaning |
|---|---|---|
| `stored` | 6 | Authorized, decoded and stored |
| `denied` | 5 | polkit denied the request |
| `authorization_unavailable` | 4 | polkit could not decide, or the caller was unknown; nothing was stored |
| `wrong_password` | 4 | Authorized, but the password did not open the file; nothing was stored |
| `unsupported_key` | 4 | Authorized, but the file holds no key of a supported type; nothing was stored |
| `storage_failure` | 3 | Authorized and decoded, but the key could not be stored |

### delete

| Outcome | Priority | Meaning |
|---|---|---|
| `deleted` | 6 | Authorized and removed |
| `denied` | 5 | polkit denied the request |
| `authorization_unavailable` | 4 | polkit could not decide, or the caller was unknown; nothing was deleted |
| `storage_failure` | 3 | Authorized, but the key could not be removed |

### replace_certificate

| Outcome | Priority | Meaning |
|---|---|---|
| `replaced` | 6 | Authorized and replaced |
| `denied` | 5 | polkit denied the request |
| `authorization_unavailable` | 4 | polkit could not decide, or the caller was unknown; nothing changed |
| `certificate_mismatch` | 4 | Authorized, but the certificate does not belong to the key; nothing changed |
| `storage_failure` | 3 | Authorized, but the certificate could not be stored |

## Mechanisms

`CUSTODIO_MECHANISM` holds one of:

- `rsa_pkcs`
- `rsa_pkcs_pss_sha256`
- `rsa_pkcs_pss_sha384`
- `rsa_pkcs_pss_sha512`
- `ecdsa`

## Message text

The shape is `<what happened>: uid <uid> pid <pid> key <key id>`. Signing examples:

```text
signature made: uid 1000 pid 4242 key my-key
signing failed after approval: uid 1000 pid 4242 key my-key
signature denied: uid 1000 pid 4242 key my-key
authorization unavailable, no signature: uid 1000 pid 4242 key my-key
authorization unavailable, no signature: uid unknown pid unknown key my-key
```

Import:

```text
key imported: uid 1000 pid 4242 key my-key
import denied: uid 1000 pid 4242 key my-key
import authorization unavailable, nothing stored: uid 1000 pid 4242 key my-key
import failed, wrong password: uid 1000 pid 4242 key my-key
import failed, unsupported key: uid 1000 pid 4242 key my-key
import failed after approval, key not stored: uid 1000 pid 4242 key my-key
```

Delete:

```text
key deleted: uid 1000 pid 4242 key my-key
delete denied: uid 1000 pid 4242 key my-key
delete authorization unavailable, nothing deleted: uid 1000 pid 4242 key my-key
delete failed after approval, key not removed: uid 1000 pid 4242 key my-key
```

Replace certificate:

```text
certificate replaced: uid 1000 pid 4242 key my-key
certificate replacement denied: uid 1000 pid 4242 key my-key
certificate replacement authorization unavailable, nothing changed: uid 1000 pid 4242 key my-key
certificate replacement refused, certificate does not match the key: uid 1000 pid 4242 key my-key
certificate replacement failed after approval, nothing changed: uid 1000 pid 4242 key my-key
```

When the bus names no caller, `uid unknown pid unknown` stands for the numbers, as in the last signing example.

## Queries

The fields `_SYSTEMD_UNIT` and `_UID` are trusted: journald sets them from the sender, and
a process cannot choose them. Fields that start with `CUSTODIO_`, and `MESSAGE_ID`, are set
by the sender, so any process can write them. A query that must match only entries of
`custodio.service` therefore names the unit and the service user.
`_UID` is that of the `custodio` system user (declared in `data/sysusers.d/custodio.conf`);
`id -u custodio` prints it.

All signing entries of the service:

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401
```

By operation (`sign`, `import`, `delete` or `replace_certificate`):

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_OPERATION=sign
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_OPERATION=import
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_OPERATION=delete
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_OPERATION=replace_certificate
```

By the uid of the caller:

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_UID=1000
```

By key:

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_KEY_ID=my-key
```

By outcome (add `-o json` for the fields):

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) CUSTODIO_OUTCOME=denied
```

## Not guaranteed

- **Identity of a person.** `CUSTODIO_UID` and `CUSTODIO_PID` name the calling process only.
  They do not say who sat at the keyboard, and a shared account looks like one user.
- **Pid reuse.** A process id is reused after the process exits; `CUSTODIO_PID` may no longer
  belong to the process that asked when you read the entry. Use it with the timestamp.
- **Rate limiting.** journald may drop or delay entries when a service logs too much
  (`RateLimitBurst=`), and Custodio does not retry. The caller is told when an entry could not be
  handed over, but a dropped entry inside journald is not reported.
- **Volatile storage.** If `/var/log/journal` does not exist, the journal lives in memory and
  is lost at reboot. Forward or persist it if you need a record.
- **Imitation by other processes.** Any process can write a journal entry with the same
  `MESSAGE_ID` and `CUSTODIO_*` fields. Only the fields that start with an underscore are set by
  journald; always include `_SYSTEMD_UNIT` and `_UID` in a query, as above.
