# Audit entries

`custodiod` writes one journal entry for every signing request, whatever the result. This page
is the interface administrators can rely on when they search, alert on or forward these entries.

## Compatibility rule

Names, identifier and priorities are only added to, never changed: a field, outcome value or
`MESSAGE_ID` that is documented here keeps its name and meaning; new ones may appear.
The text of `MESSAGE` is for people; parse the fields instead.

## Identifier

`MESSAGE_ID` is `29c3d30e6c4242406c6db3f120d36401` for every entry. A journal catalog
(`/usr/lib/systemd/catalog/custodio.catalog`, shipped by the package) explains it in
`journalctl -x`.

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
| `CUSTODIO_OUTCOME` | Result, one of the values below | always |
| `CUSTODIO_MECHANISM` | Signature mechanism, one of the values below | omitted when it was not known |

## Outcomes

| Outcome | Priority | Meaning |
|---|---|---|
| `signed` | 6 | Authorized and signed |
| `denied` | 5 | polkit denied the request |
| `authorization_unavailable` | 4 | polkit could not decide, or the caller was unknown; nothing was signed |
| `signing_failed` | 3 | Authorized, but signing failed |

## Mechanisms

`rsa_pkcs`, `rsa_pkcs_pss_sha256`, `rsa_pkcs_pss_sha384`, `rsa_pkcs_pss_sha512` and `ecdsa`,
written as `CUSTODIO_MECHANISM`:

- `rsa_pkcs`
- `rsa_pkcs_pss_sha256`
- `rsa_pkcs_pss_sha384`
- `rsa_pkcs_pss_sha512`
- `ecdsa`

## Message text

The shape is `<what happened>: uid <uid> pid <pid> key <key id>`. Examples:

```text
signature made: uid 1000 pid 4242 key my-key
signing failed after approval: uid 1000 pid 4242 key my-key
signature denied: uid 1000 pid 4242 key my-key
authorization unavailable, no signature: uid 1000 pid 4242 key my-key
authorization unavailable, no signature: uid unknown pid unknown key my-key
```

## Queries

The fields `_SYSTEMD_UNIT` and `_UID` are trusted: journald sets them from the sender, and
a process cannot choose them. Fields that start with `CUSTODIO_`, and `MESSAGE_ID`, are set
by the sender, so any process can write them. A query that must match only entries of
`custodio.service` therefore names the unit and the service user.
`_UID` is that of the `custodio` system user (declared in `data/sysusers.d/custodio.conf`);
`id -u custodio` prints it.

All entries of the service:

```sh
journalctl _SYSTEMD_UNIT=custodio.service _UID=$(id -u custodio) MESSAGE_ID=29c3d30e6c4242406c6db3f120d36401
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
