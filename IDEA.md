Milestone: M3

M3 turns the `com.rfirma.Custodio1` interface into an API that any client can build on, rFirma
included, whose side waits for M5. Import asks polkit, as signing does, instead of letting any
process of any uid import; each key belongs to the uid that imported it, and listing and signing
only see the caller's keys. Custodio only runs in test VMs and nothing is usable before M5, so there
is no migration: keys from earlier trials are purged, and the state format can change freely. Clients can delete a key and replace the certificate of a renewed one keeping
the key. When the caller is a flatpak, the journal entry also names its app-id, read from the
`xdg-dbus-proxy` process's `/.flatpak-info`: a record, not an authorization. The CLI gains
`custodio list` and `custodio delete` and talks to the service only through the public API, as a
client would. The API is documented for clients: how to detect the service, and import, list,
delete, sign and their errors.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F63.
