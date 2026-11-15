# F195 blocked: SPEC Design 4 "(b) with any password" cannot hold for MAC-bearing unusable files

`docs/findings/F195.md` proves it: for a file with a MAC and encrypted contents (every file OpenSSL, NSS or Firefox writes),
`Pkcs12Archive::from_pkcs12` with a wrong password fails with `MAC tag mismatch` before any bag is read, so a file with
no key, no certificate or two keys looks exactly like a good file with a wrong password. Of the contract's twelve
(b) cells, the three MAC-bearing wrong-password ones (no key, no certificate, two keys) can only be (a); the MAC-less
ones with a shrouded key and a wrong password are (c) (same finding). With the right password every case is (b).

The contract tells me to record a `pending` entry in `SPEC_DEVIATIONS.md` and amend, but that file does not exist and I
must not invent its format. Questions:
1. How should `SPEC_DEVIATIONS.md` start (format of its header and entries)?
2. Is the narrow replacement acceptable: MAC-bearing unusable file + wrong password = (a); MAC-less shrouded unusable file +
   wrong password = (c); everything with the right password, and plain-bag MAC-less files and non-PKCS#12 bytes, = (b)?

State of the work: step 1 half done and committed (fixtures `good-nomac`, `nokey[-nomac]`, `nocert[-nomac]`, `notp12.bin` in
`gen.sh`, finding written). Missing: the two-keys fixture (needs a small generator; NSS cannot export two certificates in one file).
No product code changed.
