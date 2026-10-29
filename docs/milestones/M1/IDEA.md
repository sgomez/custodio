Milestone: M1

M1 makes Custodio work with PKCS#11 clients as they are, so that people signing with rFirma and
LibreOffice on Linux can use a protected key without workarounds in the client. The module gains the
composed mechanisms (SHA-256/384/512 with RSA PKCS#1 v1.5, ECDSA with SHA-2), hashing and building
the `DigestInfo` itself while the service still receives only the hash, and accepts `C_Login` as a
no-op. Every signature leaves one journal entry
with the caller's uid and pid, the key and whether it was approved, never key material or hash
contents, so an administrator can audit who signed with which key. Acceptance is repeated by hand
with a P-256 key as well as RSA 2048.

Earlier milestones are archived in docs/milestones/; build on the code that already exists.
Number this milestone's features from F19.
