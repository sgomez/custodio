# Progress

Each session appends one entry at the bottom. Keep entries short: the next session reads them
with an empty context.

## Template

```
### <date> — <feature id> — <attempt n>
- Done:
- Decisions (also in docs/decisions.md if lasting):
- Not done / known issues:
- Next session should:
```

## Sessions

### 2026-11-03 — F104 — attempt 1
- Done: `scripts/with-swtpm.sh` + `just with-swtpm *cmd` (swtpm socket mode, `--flags not-need-init`, `tpm2_startup -c`,
  `TPM2TOOLS_TCTI=swtpm:path=<state>/swtpm.sock`, cleanup on EXIT/INT/TERM/HUP, exits with the command's status).
  `scripts/check-tpm-install-sync.sh` (exempt jobs by name: ci `commits`, `ci`; mutants `report`) and its test
  `scripts/test-tpm-install-sync.sh` with negative controls; `scripts/test-with-swtpm.sh` (missing-tool cases run now;
  real-TPM cases print SKIP, or fail when `CI` or `WITH_SWTPM_REQUIRE=1`). All wired into `just test-scripts`.
  Containerfile and every cargo job of ci.yml and mutants.yml install the four packages with a comment. `just quick` green.
- Not verified (tools absent in this container): the real swtpm run. The swtpm invocation, the `.ctrl` socket naming of the
  TCTI and the Debian/Ubuntu package that carries `libtss2-tcti-swtpm0` (the contract asks to name it if `libtss2-dev` and
  `tpm2-tools` do not pull it in; `apt-cache` was unavailable here) must be checked after the rebuild.
- Next session should (after the rebuild): run `scripts/test-with-swtpm.sh` with `WITH_SWTPM_REQUIRE=1` directly (it is not in
  `just quick`), the contract's "rebuilt container" evidence, and fix the recipe if swtpm/TCTI details differ. If the TCTI module
  is missing, add its package to the Containerfile, the CI steps and PACKAGES in the sync check.

### 2026-11-03 — F104 — attempt 2 (rebuilt container)
- Done: ran the real recipe on the rebuilt container. Finding: in this container `swtpm` cannot be signalled (kill gives EPERM,
  even SIGKILL), so the cleanup hung on `wait`. `scripts/with-swtpm.sh` now stops swtpm with `swtpm_ioctl --unix <sock>.ctrl -s`
  (package swtpm-tools, checked up front) and keeps the signal as fallback. Script test: stubs `swtpm_ioctl` too, and uses
  `set -m` so the SIGINT case is real (background jobs in a script start with SIGINT ignored).
- Verified: `WITH_SWTPM_REQUIRE=1 scripts/test-with-swtpm.sh` passes, sync check passes, the three `with-swtpm` verify commands
  behave, `pkg-config --exists tss2-esys` ok, `just quick` green. The TCTI needed no extra package.
- Next session: nothing left; the loop runs the verify.

### 2026-11-03 — F104 — attempt 3 (findings fix)
- Done: NEXT_FINDINGS 1: `with-swtpm.sh` keeps the caller's stdin (`exec 3<&0`, `"$@" <&3 3<&- &`); new test case
  `echo hello | with-swtpm cat` (failed before the fix). Finding 2: the wait for swtpm after the signal fallback is bounded
  (5 s), warns, and the state is removed anyway. Finding 3: stray swtpm from the earlier run is not from current code.
- Verified: `WITH_SWTPM_REQUIRE=1 scripts/test-with-swtpm.sh` passes, `just quick` green.
- Next session: nothing left; the loop runs the verify.

### 2026-11-03 — F105 — attempt 1
- Done: `custodio-it` gets `src/swtpm.rs` (std only, so no regular dependencies) and the target `tests/swtpm_fixture.rs` (9 tests).
  `Swtpm::start/tcti/tool/tool_ok/extend_pcr/restart/clear/pid/state_dir`; stop = `swtpm_ioctl -s` on the control socket,
  `Child::kill` after 2 s as fallback, bounded 5 s wait with `try_wait`; Drop removes the state dir (also on panic).
  Missing tool: error names the tool and package (checked with `PATH` holding only tpm2_* and swtpm_ioctl symlinks).
- Decisions: `tss-esapi` is `=8.0.0-alpha.4`, `default-features = false`, dev-dependency. Why: 7.x only knows `swtpm:host=,port=`
  (`NetworkTPMConfig`), not `swtpm:path=<unix socket>`, so with 7.7 the context fails with an IO error; 8.0 alpha adds
  `TpmSimulatorConfig::Unix`. It pulls `paste` (RUSTSEC-2024-0436, unmaintained proc-macro): commented ignore in `deny.toml`.
  `sha2` added as dev-dependency (PCR chain in the test). Clear evidence compares `-C o` (TPM2_Clear changes the owner seed only).
  swtpm serves one client at a time: drop a `tss-esapi` Context before running a tool on the same instance.
  Tools leave objects in the TPM's few slots: tests run `tpm2_flushcontext -t` after createprimary/readpublic.
- Next session: nothing left if `just quick` and the verify pass.

### 2026-11-03 — F106 — attempt 1
- Done: probe `crates/custodio-it/examples/tpm-probe.rs` (`parent [--tcti]`, read-only, exit 1 when the TPM is unreachable or the
  owner hierarchy unusable, 2 on usage) and `## F106` in `docs/findings.md` with the swtpm experiments (persist, restart via
  `swtpm_ioctl -i` + `tpm2_startup -c` inside `with-swtpm`, clear, owner password `0x9A2`, foreign occupant, load error `0x1DF`).
  Decision: B, primary recreated each use from the ECC P-256 TCG SRK template. `just quick` green, verify passes.
- Not done: hardware TPM run (F111). Template fields beyond the TCG deltas, and "systemd never evicts on removal", are marked inferred.
- Next session should: nothing left; the loop runs the verify.

### 2026-11-03 — F107 — attempt 1
- Done: `tpm-probe mechanisms [--tcti]` (`examples/tpm_probe/mechanisms.rs`): every mechanism both ways on transient keys, verified by
  the `openssl` CLI (never the probe's own padding), negative controls, capability queries, a second-connection `decrypt` experiment;
  exit 1 when a served signature does not verify, 2 on usage. `custodio_it::tpm_filter::TpmFilter` (std only): a proxy in front of
  swtpm that removes algorithms/curves from `GetCapability` and answers `TestParms`/`Sign`/`RSA_Decrypt` with the spec's `TPM_RC_*`
  for a lacking item; tests in `tests/tpm_filter.rs`. `## F107` in `docs/findings.md` ends with `Decision: (b)`.
- Findings: swtpm 0.7.1/libtpms 0.9.2 has no profile; PSS salt = hash length for SHA-256/384/512; (a) cannot serve `CKM_RSA_PKCS`
  with a non-`DigestInfo` payload or other salts; (b) serves all, bytes equal (a) for PKCS; P-256 needs SHA-256 only with the
  truncated hand-over; `decrypt` lets another TPM holder decrypt, `TPM2_Duplicate` still refused (0x124).
- Not done / inferred: hardware TPM run (F111); scheme and curve `TPM_RC_*` codes of the filter are from the spec (only the hash
  code 0x1C3 is measured); null-scheme decrypt on a TPM lacking PSS not run. Lasting choice (b) is for the person in F111, so not
  yet in `docs/decisions.md`. Departures to flag: `decrypt` usage on RSA keys; add "root can also decrypt" to the threat model.
- Next session should: nothing left; the loop runs the verify.

### 2026-11-03 — F107 — attempt 2 (findings fix)
- Done: NEXT_FINDINGS 1: a TPM that refuses `TPM2_Sign` PSS prints `outcome=lacks rc=<code>` per salt and the probe goes on.
  Finding 2: a refused `sign|decrypt` template prints `key: rsa2048 sign|decrypt refused <rc>`, every (b) case is `lacks` with that
  code (`way_b_refused`), (a), capabilities and the sign-only half of the `decrypt` experiment still run. Notes: the 36-byte payload is
  labelled "stand-in" (SHA-256 bytes); the ECC `TestParms ... SHA-1` line is gone; findings text updated to match.
- Also: `just quick` was red from attempt 1 (file size over 5000 tokens, inline tests in `tpm_filter.rs`): `mechanisms.rs` split into
  `mechanisms/support/wayb/caps` modules, filter tests moved to `src/tpm_filter/tests.rs`. `just quick` green, probe exit 0, filter tests 3/3.
- Not verified: the two refusal paths were not run against a TPM that refuses (swtpm accepts both); they are straight error branches.

### 2026-11-03 — F108 — attempt 1
- Done: `## F108` in `docs/findings.md`, run in the debian13 container under rootless podman (booted `degraded`: only kernel mounts and
  `systemd-modules-load` fail). `Decision: route 2` (swtpm on a unix socket, test-only drop-in in `/run/systemd/system/custodio.service.d/`).
- Route 1 (vtpm proxy): no `/dev/vtpmx`, no `tpm_vtpm_proxy` module, no root; needs a host change (load the module, pass the device in).
  Not needed, so no `BLOCKED.md`; a real `/dev/tpmrm0` stays for F109 (device questions) and F111.
- Facts for F109: a host AppArmor profile `swtpm (enforce)` confines swtpm in the container: socket and state only under `/tmp` and `/var/tmp`,
  and it cannot be signalled (stop with `swtpm_ioctl -s`). The unit's `PrivateTmp` is passed with `BindReadOnlyPaths=/tmp/f108-tpm`; the TCTI
  needs `<sock>.ctrl` next to the socket, both `mode=0666` for the dynamic user. The shipped sandbox let `tpm2_getcap` through (33 algorithms).
  The F107 filter has no CLI: a scratch wrapper (not committed) ran it; F109 should add an example to `custodio-it`.
- Evidence in the finding: PCR 16 extend equals the precomputed value, read by the shell and by the unit; restart gives PCR zero (as expected)
  with a persistent handle and its name unchanged; clear removes it and changes the owner seed; drop-in negative control and `dpkg -L` = 0
  against the real deb. Other targets are inferred, with the F109 check for each.
- Not done: other targets, SELinux, hardware. `just quick` green, the `verify` passes.

### 2026-11-03 — F109 — attempt 1
- Done: `## F109` in `docs/findings.md`, run as real units under each of the six e2e containers' own systemd (stand-in (a) `/dev/null` as
  `/dev/tpmrm0`, (b) a `root:tss 0660` regular file). `Decision:` keep `PrivateDevices=yes`, add `DeviceAllow=/dev/tpmrm0 rw`,
  `BindPaths=-/dev/tpmrm0`, `SupplementaryGroups=tss`; score 0.7 (threshold 1.0), `PrivateDevices=no` would be 0.8. No `BLOCKED.md`.
- Findings: plain `BindPaths=` makes the unit fail 226/NAMESPACE without a TPM, hence the `-`; a missing `tss` group fails the unit (216/GROUP),
  so the packages must depend on `tpm-udev`/`tpm2-tss` (or sysusers `g tss -`); owner is `tss:tss` on the Debian family, `root:tss` elsewhere;
  group access works under `PrivateUsers=yes` on all six.
- Not verified (left to F147): `DeviceAllow=` effect (the control C0 still opens in rootless containers, so *inferred*), a real node's owner,
  SELinux on fedora44/alma10. Nothing in `data/`, recipes or Containerfiles changed; applying the Decision is for a later feature.

### 2026-11-03 — F110 — attempt 1
- Done: `## F110` in `docs/findings.md`, run as a real probe unit (shipped text, F109 directives, static `custodio` uid) on the six e2e containers, plus the dev container
  (`unshare -m --map-root-user --map-users=auto`, `systemd-socket-activate -a --fdname=varlink`, `setpriv` uid 42, `just with-swtpm` for the explicit-device TPM cases). Six `Decision:` lines.
- Findings: scope `user` + Varlink works without polkit on 257/259/262 (no `--user`/Varlink on ubuntu2404 255); system scope or another uid needs polkit; the Varlink daemon picks the key
  (`auto`) and the PCR mask itself (PCR 7 on 255/257, empty on 259/262); `withKey` (259+) in user scope yields an unscoped or null credential, so never send it; `--tpm2-pcrs=` = no PCR (all six);
  `tpm2` = TPM alone, `host+tpm2` = both. A container never uses the TPM through the daemon (`running in a container`), so the Varlink TPM case is *inferred* from source and left to F147.
- Deviations (pending, `SPEC_DEVIATIONS.md` `## F110`): debian13, alma10 (PCR 7 on a TPM machine, not changeable per call), ubuntu2404 (TPM-alone only). Not security rules of CLAUDE.md.
- Not done / not run: strace inside the unit (needs `ptrace`; run as the uid with `setpriv` instead), strace in the dev container (not installed; the evaluator's note said it was), real TPM, SELinux.
- Next session should: nothing left; the loop runs the verify. F120 uses the Decisions and the read-back guard.

### 2026-11-03 — F115 — attempt 1
- Done: `creds` module in custodiod (`creds.rs` access-point trait + two errors, `creds/systemd.rs` real client, `creds/header.rs` PCR read-back guard);
  host-bound over Varlink, TPM-bound via CLI with explicit `--tpm2-pcrs=`; decrypt returns secrecy/zeroize memory. Three files added to the `mutants` recipe.
- Evidence: `just quick` green; `cargo test -p custodiod --test creds` 12/12; `just mutants-diff F115`: 213 mutants, 149 caught, 64 unviable, 0 missed; each of the three files has caught mutants.
- This session fixed two clippy errors in `creds/systemd/tests.rs` (underscore binding, slicing) and rustfmt.
- Not verified: Varlink+TPM (daemon refuses a TPM in a container) is left to F147, as the contract says.

### 2026-11-03 — F111 — manual
- Done: probes on a hardware TPM (Dell XPS 13 9305, STM, rev 1.38, fw 1.258), `docs/findings.md` `## F111`; the person
  approved parent B (ECC P-256 primary per use) and parity (b) with `decrypt`, both in `docs/decisions.md` 2026-11-03.
- Not done: the threat model must say that root controlling the machine can also decrypt with a TPM RSA key (SPEC is
  not edited by agents).
- Next session should: F112 queries no SHA-512 (the STM TPM lacks it). F119 states the decrypt point in the client
  documentation, next to "root can use a TPM key".

### 2026-11-04 — F112 — attempt 2
- Done: `tpm` module in custodiod (`classify`, `list`, `open`, `esys`), capability table in `docs/api.md`, decisions recorded, `custodio-it` filter extended
  (commands removed from `TPM_CAP_COMMANDS`, fault rules), integration target `tpm_access` (16 tests), five files in the `mutants` recipe.
- Fixed the NEXT_FINDINGS hang: the filter served clients serially with no timeouts, so a lingering client blocked its thread (and `Drop`'s join) and held
  the one swtpm connection. Now `serve` polls with a 100 ms read timeout that checks the stop flag, 10 s limits mid-message, and connects upstream lazily.
  `Swtpm::tool` runs under `timeout`, and `swtpm` starts under `setpriv --pdeathsig KILL`.
- Paging is tested (`EsysSession::open_paged`, page size 1) which also removed the `listed` survivors; ENOTDIR/non-socket tests killed the `open.rs` ones.
- Evidence: `just quick` green; `tpm_access` 16/16, repeated; `just mutants-diff F112`: 105 mutants, 82 caught, 23 unviable, 0 missed.
- Note: pdeathsig fires when the spawning thread exits; fine here (each test owns its `Swtpm`). One run of `tpm_access` took 13 s instead of 3 s once; not reproduced.

### 2026-11-04 — F112 — attempt 3
- Fixed the verify failure (`tpm2_changeauth` timing out after 60 s in `tpm_access`, `nothing_left_loaded` and others). Cause, found by reproducing under load (several
  test binaries at once) and mapping socket peers in `/proc`: libtss2 opens its TCTI sockets without close-on-exec, so a `swtpm` that another test forked while
  its connection was open kept the client end alive; the single-client `swtpm` of that test never saw the connection close and the next tool waited forever
  (the 10-13 s runs were the filter's 10 s limit on the same stall). `Swtpm::spawn` now starts `swtpm` through `bash`, which closes every descriptor above stderr first.
- Also: the filter's control-channel pump connects upstream on the client's first bytes (not on accept), so a TCTI that only connects no longer holds `swtpm`'s control
  channel; `tool_ok` errors now show the arguments.
- Evidence: 36 parallel runs of `tpm_access` (6 at a time), all 16/16 in under 3.5 s (before: about 1 in 9 hung); `custodio-it` tests green; `just quick` green;
  `just mutants-diff F112`: 105 mutants, 82 caught, 23 unviable, 0 missed.

### 2026-11-04 — F113 — attempt 1
- Done: `tpm` module gains `key` (PKCS#8 → RSA 2048 / P-256 only, secrets in `SecretSlice`), `wrap` (outer wrap to the parent by ECDH, KDFe/KDFa, AES-128-CFB, HMAC),
  `blob` (`Blob`, `Imported` = blob + parent name only, bounded parsing), `import` (`import_pkcs8`, `import`, `check_parent`, `ImportError`), `esys/primary.rs`
  (SRK-template parent created and flushed per call, `TPM2_Import`). `Session` got `parent_name` and `import_key`. Wrap choice: outer wrap, no session, new deps `aes`, `hmac`
  (already in `Cargo.lock`, so deny/machete see no new crate); research in `docs/findings.md` `## F113`. `custodio-it` filter got `Recorder` (`Lacks::record`) and `cc::FLUSH_CONTEXT`.
  Parent check sends CreatePrimary + FlushContext only, never `TPM2_Load`. Five files added to the `mutants` recipe.
- Decisions: `adminWithPolicy` set with empty policy (TPM accepts; duplicate fails `TPM_RC_AUTH_TYPE`), `sensitiveDataOrigin` clear, P-256 scheme pinned to ECDSA/SHA-256, RSA scheme null.
- Unit tests (run in `just quick`): `tpm::tests::import::{result_fields, key_path_types, name_comparison, blob_parsing_bounds, refusal_before_any_tpm_call, debug_and_display_hold_no_key_bytes, limits_and_messages, kdfs_follow_the_construction, aes_cfb_with_a_zero_iv, the_public_area_follows_the_decisions}`.
- Evidence: `just quick` green; `tpm_import` 10/10; `just mutants-diff F113`: 124 mutants, 93 caught, 31 unviable, 0 missed.
- Deviation from the contract text: the commands of an import are CreatePrimary, Import, Flush (no session, no read-public), so `nothing_left_loaded` faults those. Test files carry a justified `allow` for unwrap/expect/indexing.
- Known: `cargo deny check bans` fails on duplicate `getrandom` (0.2 via tss-esapi, 0.4); it fails the same without my changes (not caused by F113).

### 2026-11-04 — F113 — attempt 2
- Fixed NEXT_FINDINGS: (1) wire test now searches the seed, `symKey` and `hmacKey` (test seam `wrap::Tap`, `TestTcti::with_tap`, `EsysSession::with_tap`; nothing in production sets it),
  with a planted-buffer control per secret; (2) RSA prime, (3) P-256 scalar copies and (4) the ECDH shared x are now `Zeroizing` (the `p256` affine point has no zeroizing drop; commented).
- Notes taken: unit `Debug` check also covers upper-case hex, raw-as-text and decimal. `authorization policy` is not printed by `tpm2_readpublic`/`tpm2_print` when empty (checked), so
  `Some("")` fails; the test now also asserts the authPolicy size bytes (10..12) of the stored TPM2B_PUBLIC are zero.
- Evidence: `just quick` green; `tpm_import` 10/10; `just mutants-diff F113`: 129 mutants, 93 caught, 36 unviable, 0 missed.
- Known, not F113: `cargo deny check bans` fails on duplicate `getrandom` (0.2 via tss-esapi, 0.4) with or without these changes; the checkpoint will hit it.

### 2026-11-04 — F113 — attempt 3
- Fixed NEXT_FINDINGS: `wrap::sensitive` no longer builds the secret through `sized` (a plain `Vec`); the size prefixes are written straight into two
  `Zeroizing` buffers reserved at full capacity. `cfb_encrypt` wipes its feedback block. `with_tap` (esys.rs, open.rs) docs say never to wire it into the daemon.
- Not done: the `hmac`/`kdfa` internal state wiping (depends on the crates; the keys passed in are `Zeroizing` in our code).
- Unit tests in `just quick`: `tpm::tests::import::{result_fields, key_path_types, name_comparison, blob_parsing_bounds, ...}`.
- Evidence: `just quick` green; `tpm_import` 10/10; `just mutants-diff F113`: 135 mutants, 98 caught, 37 unviable, 0 missed.

### 2026-11-04 — F113 — attempt 4 (human-supervised fix of the 3rd rejection)
- Fixed NEXT_FINDINGS: the ECDH product (`ProjectivePoint`) and the shared `AffinePoint` are `Zeroizing`. Enabled `aes/zeroize` (key schedule), `hmac/zeroize` and
  `sha2/zeroize`. `Hmac` in hmac 0.13.0 never implements `ZeroizeOnDrop`, even with its feature; its keyed state is two SHA-256 cores, which wipe on drop only with
  `sha2/zeroize` (that also covers the `kdfe` hasher over `Z`). `key_path_types` asserts `Aes128`, the SHA-256 core, `Sha256` and both `Zeroizing` points.
- Note taken: `wrap::Tap` stores `Zeroizing<Vec<u8>>`.
- Evidence: `just quick` green; `tpm_import` 10/10; `just mutants-diff F113`: 135 mutants, 98 caught, 37 unviable, 0 missed.
- Builds need the `custodio-dev` container (the host has no tss2 libs).

### 2026-11-04 — F114 — attempt 1
- Done: `tpm::sign` (request/errors/`sign`), `sign/block.rs` (key type from the blob, validation with the bounds of `sign::sign`, PKCS#1 v1.5 and EMSA-PSS blocks,
  ECDSA left-pad/truncate), `sign/check.rs` (the RSA result is checked with the blob's public key: canonical and `s^e mod n == block`), `esys/signing.rs`
  (one parent per call, name compared before `TPM2_Load`, load, `RSA_Decrypt` null scheme / `Sign` ECDSA-SHA256, flush key then parent on every path).
  `Session::sign` added. Lacks = `TPM_RC_COMMAND_CODE` (0x143) on Load/RSA_Decrypt/Sign, or a scheme/hash/type refusal on Sign; any other code stays a TPM error; Load refusals
  other than 0x143 are `LoadFailed(rc)`. `rsa` gets the `hazmat` feature (public op for the check). `SignError` derives `Clone, Copy`. Filter (`custodio-it`) gained `Lacks.flips`.
- Finding: `sign::sign` accepts any non-empty ECDSA digest (the 16-byte minimum in the evaluator notes does not exist in ecdsa 0.17); parity is kept, so 1..=15 bytes are signed (left-padded) and tested with `openssl`.
- Tests: unit `tpm::tests::sign::*` (15); `tpm_sign` 10 tests (note 2: `a_wrong_rsa_result_is_not_returned` via a filter flip -> `BadResult`).
- Deviation from the contract text: with `FLUSH_CONTEXT` faulted both parent and key leak and `swtpm` has 3 slots, so the test clears the leak with `tpm2_flushcontext -t` (what the kernel RM does on close) before the later signature.
  `openssl pkeyutl -verify` caps raw input at 64 bytes, so payloads >64 bytes use `-verifyrecover`; ECDSA digests >64 are verified over their leftmost 32 bytes.
- Evidence: `just quick` green; `tpm_sign` 10/10; `just mutants-diff F114`: 92 mutants, 81 caught, 11 unviable, 0 missed.

### 2026-11-04 — F114 — attempt 2
- Fixed NEXT_FINDINGS: `unused mut` in `custodio-it/src/tpm_filter/tests.rs`. Also `tests/sign.rs` was over 5000 tokens (size gate in `just quick`): the second half moved to `tests/sign/later.rs` (child module, `use super::*`).
- Evidence: `just quick` green; `tpm_sign` 10/10; `just mutants-diff F114`: 92 mutants, 81 caught, 11 unviable, 0 missed.

### 2026-11-04 — F114 — attempt 3
- Fixed NEXT_FINDINGS: (1) the `tpm2_flushcontext -t` step in `nothing_left_loaded` is now an approved-pending amendment in `contracts/F114.md` (3 transient slots, a faulted flush leaves parent and key loaded; the test is unchanged); (2) the `allow` in `tpm/tests/sign/later.rs` carries its justification.
- Evidence: `tpm::tests::sign` 15/15. No production or integration test code changed, so the `tpm_sign` and mutants results of attempt 2 stand (`just mutants-diff F114`: 92 mutants, 0 missed).

### 2026-11-04 — F116 — attempt 1 (sessions 1-3)
- Inventory / transition plan: callers of the store were `import.rs`, `dbus.rs` (list, sign), `dbus/{delete,replace}.rs`, `main.rs`, and the rigs in
  `crates/custodiod/{src,tests}` and `crates/custodio-it/{tests,examples}`. All moved to the new API in this one change (the old byte API is gone, not kept `pub(crate)`).
  M3 id rules: a key id may end in `-cert`, so `a` + `a-cert` is ambiguous by name; `store/legacy.rs` groups by the fixed rule in its module doc (a name is a certificate when its stem is a non-certificate file; an orphan certificate stands for its stem).
- Done: `store/{kind,record,legacy,error,files}.rs` (kind with pinned wire strings `tpm`, `encrypted-tpm`, `encrypted-host` and tags 1-3; `Protected` with only `from_imported`/`from_sealed`;
  `Record` with bounded `encode`/`decode`; `Sealed`'s fields private with accessors; `creds::memory::MemoryCreds` as the fake credential service for tests/examples).
  `put` re-checks the framing (credential header vs kind, blob parse + public area) before it writes. `Custodio::with_key_credentials` carries the `Credentials` access point; sign decrypts through it; a TPM record answers `Internal` until F118.
- Interim wiring (until F117): production import encrypts in every case (encrypted TPM-bound or host-bound via `creds::seal`), never TPM kind. This is a gap before F117, not the final behaviour.
- Tests: unit `store::tests::{record_round_trip, kind_wire_strings_are_pinned, put_refuses_plaintext_as_*, kind_binding_mismatch, framing::*, legacy_files::*, rules::*, ...}`; integration target `state_format` (25 tests: api grep with a seeded negative control, no_plaintext_anywhere with planted-key control, framing readers on a real swtpm blob, modes under umask 0/077/022, symlinks, FIFO, loose modes, concurrent put/remove, replace atomicity and race, legacy).
- Not done / notes: the `compile_fail` doctest is not added (not counted as proof). The rename negative control for `concurrent_put_one_id` was dropped (the evaluator called it redundant). `creds/memory.rs` is test support and not in the `mutants` list.
- Lint fixes for `just quick`: `store/error.rs` and `store/files.rs` split out of `store.rs` for the size gate; one justified `allow(too_many_lines)` on the cryptoki fixture.
- Evidence (session 4): `just quick` green; `cargo test -p custodiod --locked` and `-p custodio-it --locked` green; `state_format` 25/25; `just mutants-diff F116`: 208 mutants, 171 caught, 37 unviable, 0 missed. Store files added to the `mutants` list.

### 2026-11-04 — F117 — attempt 1
- Done: `import/choice.rs` (pure `choose`: Ready→Tpm, Lacks→EncryptedTpm, Absent→EncryptedHost, Error→refusal) and `import/protect.rs`
  (`protect` takes `ParsedP12` by value, assesses, imports to the TPM or seals, checks the credential binding against the kind, drops the key before it returns;
  the record's kind is the chosen one, never re-labelled). `store_parsed`/`import_p12` take a `&dyn TpmAccess`; `Custodio::with_tpm`; `main` passes `open::from_environment()`
  (F108's seam unchanged). New `ImportError::{Tpm, BindingMismatch}`. New D-Bus errors `TpmFailed` and `CredentialsUnavailable` (client constants, `ServiceError`, `docs/api.md`):
  F119 only needs to explain them, not add them. Both map to journal outcome `storage_failure`.
- Decisions: a `Custodio` built without `with_tpm` has `open::NoTpm` (no device), so tests that only need a host-bound key stay unchanged; the daemon always passes its access point.
  Test seeding via `import_p12` passes `&NoTpm`. Control (c) of the contract (wrong chooser stub) dropped as the evaluator advised; the key-by-value property is the signature of `protect`.
- Tests: unit `import::choice::tests`; integration `storage_choice` (19): kinds (ready/lacks/absent/unserved mechanism), `fails_closed::*` (9 rows, both key types, with heal-and-reimport, `encrypt` counts,
  one `storage_failure` entry, empty store), order (polkit denied / wrong password: TPM never opened), `tpm_is_clean_after_faulted_import` (CreatePrimary seen before the fault, leak control),
  `no_plaintext_in_store_after_any_outcome`, `controls`.
- Evidence: `just quick` green; `storage_choice` 19/19; `just mutants-diff F117`: 19 mutants, 7 caught, 12 unviable, 0 missed. `src/import.rs`, `import/choice.rs`, `import/protect.rs` joined the `mutants` list.
- Not done: TPM records still answer `Internal` on sign (F118); kind in the API/list (F119); causes in the journal (F120). `just api-contract` removal check not repeated by hand beyond the test running green in `just quick`.

### 2026-11-04 — F117 — attempt 2
- Fixed NEXT_FINDINGS: the inline test module in `import/choice.rs` moved to `import/choice/tests.rs` (check-files gate).
- Evidence: `just quick` green; `storage_choice` 19/19; `just mutants-diff F117`: 19 mutants, 7 caught, 12 unviable, 0 missed.

### 2026-11-04 — F117 — attempt 3
- Fixed NEXT_FINDINGS: the three `#[allow(dead_code, unused_imports)]` in `tests/storage_choice.rs` now carry a justifying comment. Contract amended (separate commit) to strike control (c), as the contract review advised.
- Open risk kept for F118/e2e: `systemd-creds`, spawned with a plain `Command`, may inherit the TCTI descriptor with the device TCTI (inferred in `docs/findings.md`, not run).
- Evidence: `just quick` green; `storage_choice` 19/19. No production code changed, so the mutants result (19 mutants, 0 missed) stands.

### 2026-11-04 — F117 — attempt 4
- NEXT_FINDINGS was already addressed by attempt 3 (`c3342d0`: the three `allow`s in `tests/storage_choice.rs` carry the justifying comment; `bbf45c8`: control (c) struck from the contract). Checked again, no code change.
- Evidence: `just quick` green; `storage_choice` 19/19. Mutants result of attempt 1 stands (19 mutants, 0 missed).

### 2026-11-04 — F117 — attempt 5
- Fixed NEXT_FINDINGS: `import_call` destructures `ImportRequest`; `authorize_and_import` takes the `SecretString` by value and drops it right after
  `decoder.decode`, before the choice. The `.p12` stays borrowed from the bus message (doc comment says so).
- Evidence: `just quick` green; `storage_choice` 19/19; `just mutants-diff F117`: 21 mutants, 9 caught, 12 unviable, 0 missed.

### 2026-11-05 — F118 — attempt 1
- Done: sign dispatches on the record's kind in the new `dbus/sign_kind.rs` (TPM kind through `tpm::sign::sign` and the service's `TpmAccess`; encrypted kinds decrypt, sign, drop). New D-Bus names `KeyLost` (blob does not load: `ParentMismatch`/`LoadFailed`; credential `CannotDecrypt`) and `TemporarilyUnavailable` (`NoTpm`, `Tpm`, `Lacks`, `BadResult`; `CredsError::Unavailable`); `Refused`/`BadRequest`/`Internal` stay `Internal`. In `custodio-client`, `ServiceError`, `docs/api.md`. `TpmFailed`/`CredentialsUnavailable` stay "`ImportP12` only". `just api-contract` not widened (F119).
- Descriptors: `SystemdCreds::run` starts the command through `/usr/bin/bash -c '<close fds > 2>; exec "$@"'` (`LAUNCHER`, `with_launcher` for tests); exit 126/127 counts as a failed start. `docs/findings/F118.md` (reproduction: plain child sees `[0,1,2,7]`, with the launcher `[0,1,2]`), F117's last row corrected.
- Tests: `sign_kinds` (17): `signs_each_kind`, `polkit_every_signature`, `delete_each_kind`, `replace_each_kind`, `replace_lost_key`, `lost_keys::{4}`, `transient::{5 incl. missing_launcher}`, `lost_keys_stay_listed_and_deletable`, `concurrent_kinds`, `creds_child_inherits_no_descriptor` (fails with the closing removed: checked). Unit: `dbus::sign_kind::tests` (tables over every `TpmSignError`/`CredsError`). Shared rig `storage_choice/rig.rs` gained `SpyCreds` decrypt counting/failure and `Svc` polkit handles.
- Contract amended (`0fdebdf`) for evaluator notes 1-5 (folded duplicate rows, launcher commands, `missing_launcher` row).
- Evidence: `just quick` green; `sign_kinds` all pass; `just mutants-diff F118`: 22 mutants, 15 caught, 7 unviable, 0 missed. `dbus/sign_kind.rs` joined the `mutants` list.
- Not done / for the checkpoints: the packages do not list `bash` as a dependency (Essential on Debian, base on Fedora/Arch) and the run of the launcher under the real hardened unit is proven at F132/F146. Kind in the API (F119), cause in the journal (F120).

### 2026-11-05 — F118 — attempt 2
- Fixed NEXT_FINDINGS: `docs/api.md` (`KeyLost` line) and the `ERROR_KEY_LOST` doc now say `Sign` only; the `Internal` entry says a replace whose key cannot be decrypted fails `Internal` and changes nothing.
- Evidence: `just quick` green. No code changed, so `sign_kinds` 17/17 and the mutants result (22 mutants, 0 missed) stand.

### 2026-11-05 — F119 — attempt 1
- Shapes (decided in `docs/decisions.md`): `ImportP12` returns one struct `(ss)` = (key type, kind) (zbus turns a tuple into one struct argument; `busctl` prints it as `ss …`); `ListKeys` returns `a(sssay)` = (id, key type, kind, certificate). The kind is `store::Kind::wire()` read from the record (no TPM or credentials touched). `store_parsed` now returns `(KeyKind, Kind)`; `import_p12` still returns the key type. CLI `bus.rs` and the PKCS#11 backend read the new shape and ignore the kind; existing tests and the docs scripts (`test-docs-api.sh`, `test-docs-manual-m3.sh`, `manual-acceptance.md`) follow.
- `custodio-client`: `Kind` (three wire strings + `Unknown(text)`), `KNOWN_KINDS`, `ERROR_NAMES` (one exported list of the `ERROR_*` constants, checked against the literal table in the client tests).
- `docs/api.md`: `out` lines, a "Storage kinds" section (one `- kind` line per value, what each protects against, when each is chosen).
- `api_kind` (3 tests): `import_returns_kind` (3 kinds x 2 key types, raw `(ss)` signature, equals the stored record), `list_returns_kind` (3 kinds in one store created out of id order, another owner's key unlisted, no TPM open/decrypt/encrypt), `list_after_loss` (swtpm cleared + decrypt failing: same list). Rig: `KindSvc` in `storage_choice/rig.rs`.
- `api_contract` now starts a service per kind (needs `swtpm`, as `api_kind` does) and compares the document's kind lines with the live kinds and the client's list, and the client's `ERROR_NAMES` with `ServiceError::ALL` and the document; controls in `edited_copies_of_the_document_fail` (kind line removed / invented, a `Sources` with an extra live kind, client constant extra / missing, old `ListKeys` out shape).
- `just mutants` gained a `custodio-client` run on `kind.rs` (`target/mutants-client`).
- Evidence: `just quick` green; `just api-contract` 2/2; `api_kind` 3/3; `just mutants-diff F119`: 0 missed in all three runs.

### 2026-11-05 — F120 — attempt 1
- Fields (documented in `docs/audit.md`, catalog text of the sign and import entries updated): `CUSTODIO_STORAGE_KIND` (the `store::Kind::wire` string; import entries that stored a key, sign entries whenever the record was read) and `CUSTODIO_CAUSE`. Outcomes and priorities unchanged: an import failure stays `storage_failure`, a sign failure stays `signing_failed`.
- Causes (closed lists in `audit/cause.rs`, exhaustive matches in `dbus/import.rs` and `dbus/sign_kind.rs`): import `tpm_device`, `tpm_owner`, `tpm_error`, `tpm_key`, `credentials_unavailable`, `credentials_refused`, `binding_mismatch`, `store`, `internal`; sign `key_lost`, `temporarily_unavailable` (an `Internal` sign failure has none). A TPM error in the query and in the import are both `tpm_error` (same typed error). The two lists share no value.
- `OperationEntry::with_storage_kind/with_cause` only apply to an import; `Entry::with_cause` only to `SigningFailed`. `ImportAttempt` became a struct in `dbus/import.rs`; `Attempt` of sign carries the record's kind.
- Tests: unit tables `every_import_error_has_its_cause`, `operation_tests::*` (wire form), `docs_tests::{kinds_and_causes_documented, kinds_and_causes_control}` (both ways, edited-copy controls). Integration `kind_audit` (9): `import_names_kind`, `import_failure_causes` (10 failures x 2 key types, literal table), `other_import_entries_unchanged`, `sign_lost_key`/`sign_transient` (every row of `Fail::ALL`), `sign_other_entries` (Internal via a credential `BadRequest`), `no_secret_in_entries` (scanner control; each row scans Debug, message, fields and the `JournalSink` datagram for the p12, password, key DER and record bytes), `documented_queries`. `Fail`/`Case` moved to `tests/sign_kinds/case.rs` so both targets share them.
- Evidence: `just quick` green; `kind_audit` 9/9; `just mutants-diff F120`: 49 mutants, 27 caught, 22 unviable, 0 missed. `audit/cause.rs` joined the `mutants` list.
- Not done: the purge entry (F121); a real `journalctl` read (checkpoints).

### 2026-11-05 — F120 — attempt 2
- Fixed NEXT_FINDINGS: `Secrets` now also plants the TPM response codes (`0x101`, `0x143`, `0x1df` and their 8-digit forms), the credential bytes `SpyCreds` produced on failed imports (`produced()`), and the decoder's own text for the wrong-password and unsupported-key rows. Lost-key sign rows now compare the record taken after `break_it()`. `ImportError::TooLarge` now has cause `internal` (table test changed with it).
- Evidence: `just quick` green; `kind_audit` 9/9; `just mutants-diff F120`: 49 mutants, 27 caught, 22 unviable, 0 missed.

### 2026-11-05 — F121 — attempt 1
- Done: `KeyStore::remove_legacy` (area lock, `is_record` check = the checked open, no symlink followed, current-format files never removed, dir synced; `legacy`/`legacy_all`/`remove_legacy` now live in `store/legacy.rs`).
  New operation `purge` (`Operation::Purge`, `PurgeOutcome::Purged`, priority 4, `MESSAGE_ID` `8e1f…e902`, field `CUSTODIO_OWNER_UID`, no uid/pid, app-id state `none`), documented in `docs/audit.md` and the catalog.
  `Operation::requests()` is the four caller-driven operations (the app-id tests loop over it); `Operation::all()` has five.
  New `src/startup.rs`: `purge_legacy` (list everything, then per key entry first, removal second; stops on the first refusal) and `start` (purge, then `connect` future is polled, serve, request name). `main` calls only `start`; its own `serve`/`build_service` are gone.
- Tests: unit `store::tests::legacy_files::remove_legacy_*` (4), `startup::tests` (2), `audit::docs_tests::purge` (control with edited copies), operation_tests purge row, `main_tests::wiring::a_legacy_key_is_purged_by_the_start_up_path` (new; `main` has no serve path of its own, so the start-up function being in `mutants-diff` is its mutation proof).
  Integration `purge` (9): `state_is_empty_after_start`, `purged_keys_are_not_listed` (proof is the `Sign` row: `NoSuchKey`), `one_entry_per_key`, `entries_reach_the_journal_with_the_documented_fields`, `entries_hold_no_key_bytes`, `same_ids_import_again`, `no_call_before_purge_complete` (blocks on the first and on the last entry; also checks entry-before-removal on disk and `ListNames`), `refuses_and_does_not_start` (symlink in the last owner's area leaves all other owners' keys; failing sink at entry 0 and 2), `second_start_purges_nothing`.
- Foreign-owner case proven by the store unit test (`file_uid` seam), as the contract says.
- Evidence: `just quick` green; `purge` 9/9; `just mutants-diff F121`: 52 mutants, 37 caught, 15 unviable, 0 missed. `startup.rs` joined the `mutants` list.
- Not done: upgrade from a real M3 package and real `journalctl` read (checkpoints); CLI wording (F123).

### 2026-11-05 — F122 — attempt 1
- Re-check: `grep -rn -i "digestinfo\|digest_info" crates/custodiod/src` finds only a comment (`dbus.rs:47`), a doc (`sign.rs:7`) and test data (`tpm/tests/sign.rs`); no parser, so no `digest_info` target. `tpm_sign_input` drives `block::prepare_with` instead.
- Targets in `crates/custodiod/fuzz` (new dep `arbitrary` for the last): `tpm_blob` (`Blob::parse` and `from_parts`; accepted → `public_area` ok and `to_bytes` parses to an equal blob), `cred_frame` (`inspect`; shorter than `MASK_OFFSET + 8` errors unless the first 16 bytes are a known key id), `record_decode` (decode → encode → decode, same owner/id/kind/certificate), `tpm_sign_input` (all kinds × mechanisms, `salt_len` a full `usize`, the bound check in `prepare_with` is the guard; RSA block 256, digest 32). `fuzz-smoke` default list gained the four names.
- Seeds (built from the unit-test helpers `rsa_blob`, `p256_blob`, `host()`, `tpm()` of the record tests, by a throwaway test not committed; credential headers and sign inputs by hand): `cargo +nightly-2026-10-26 fuzz run <t> <seed-dir> -- -runs=0` exits 0 for all four. A temporary `panic!("PROBE")` in the accepting branch of `tpm_blob`, `record_decode` and `tpm_sign_input` crashed on those seeds (probes removed), so the round-trip assertions do run.
- Evidence: `just fuzz-build`, `just lint-fuzz`, `just fuzz-smoke` (10 targets), the 8-name run: exit 0; negative control (`… no_such_target`) exit 1 with `target no_such_target is missing or did not run`; `just quick` green.

### 2026-11-05 — F123 — attempt 1
- `Importer::import_p12` returns `(key type, custodio_client::Kind)`; `run_import` prints a `Storage:` line per kind (`kind_text` in `lib.rs`): tpm (cannot be copied), encrypted-host (weaker, no TPM, root and anyone with a copy of `/var/lib`), encrypted-tpm (weaker, the TPM lacks a capability the key type needs, root while the machine runs, points to `docs/api.md` "TPM capabilities"; the reason comes from the kind alone), unknown (escaped text, "does not know", no weaker/stronger claim). The key type is now escaped too. Delete reminder unchanged and only after success.
- `KeyEntry` has `kind: Kind`; `write_entry` prints `  kind: <escaped wire>` after `type:` (blocks are five lines). `bus.rs`: `key_entry` maps the `ListKeys` tuple (unit test `a_list_element_keeps_each_field_in_its_place`); `custodio-it` `cli.rs`/`list.rs` follow the new shapes (rig stores `encrypted-host`).
- Tests: `crates/custodio-cli/tests/storage_kind.rs` (8): `import_tpm`, `import_encrypted_host`, `import_encrypted_tpm`, `weaker_reasons_differ`, `import_unknown_kind`, `failed_import_prints_no_kind`, `list_shows_each_kind` (ids and kinds out of kind order), `list_escapes_kind`.
- Evidence: `just quick` green; `storage_kind` 8/8; `cargo tree -p custodio-cli -e normal` has no `custodiod`.

### 2026-11-05 — F124 — attempt 1
- Step 1 note: F110's Decisions need no unit directive for the credential service (Varlink socket under `/run`, `AF_UNIX` already allowed, `/run` readable under `ProtectSystem=strict`); none added. Caveat for F147: the ubuntu2404 path (`systemd-creds --with-key=tpm2`) was run by the service uid under `setpriv`, outside the sandbox, and F110 probed under the unit minus `Type=dbus`/`BusName=`/`After=`/`Requires=`; F147 must still show it works under the unit.
- `data/custodio.service` gained exactly `DeviceAllow=/dev/tpmrm0 rw`, `BindPaths=-/dev/tpmrm0`, `SupplementaryGroups=tss` plus a comment. Exposure 0.7 SAFE at threshold 10.
- `scripts/check-unit-hardening.sh` expects `PrivateDevices=yes` and the three directives exactly once; refuses raw-TPM access (tpm0, wildcards, char-misc, 10:224, binding `/dev`) in DeviceAllow/BindPaths/BindReadOnlyPaths, any TCTI mention in Environment*/PassEnvironment (incl. `CUSTODIOD_TEST_SWTPM_TCTI`, quoted), and any `EnvironmentFile=`/`PassEnvironment=`. Cases in `scripts/test-check-unit-hardening.sh` (each failed before the change).
- Evidence: `just quick` and `just system-gates` green, test script green.

### 2026-11-05 — F125 — attempt 1
- Table (`scripts/package_expected.py`): `TSS_NEEDED` (three sonames → deb/rpm/arch package, merged into `NEEDED`), `TSS_GROUP` (`tpm-udev` deb, `tpm2-tss` rpm and arch), `TSS_DLOPEN` (deb `libtss2-tcti-device0t64`), `SYSTEMD` bounds, `TSS_LIBS` and `DEPS` built from them. New `scripts/package_table.py` loads the table for `check_packages.py` and `check_tss_deps.py`; `CUSTODIO_PACKAGE_EXPECTED=<copy>` makes both read that copy.
- Names: debian13 confirmed in the dev container (`dpkg -S`, `apt-cache depends`); ubuntu noble and resolute confirmed on packages.ubuntu.com (same t64 names, `tpm-udev` exists). `libtss2-tctildr0t64` depends on `libtss2-tcti-device0t64` and `tpm-udev` (debian13 `apt-cache depends`; noble page), and the deb declares both anyway. **Inferred, not run:** the rpm and Arch name `tpm2-tss` owns every `libtss2-*.so.0` and the tcti-device (F109 only proved it owns the rules and `tss`).
- systemd bounds: deb `Pre-Depends: systemd (>= 255)` (F110 ubuntu2404 line: plain CLI; the deb also serves debian13 at 257); rpm `systemd >= 257` (F110 alma10 line, Varlink user scope); Arch `systemd>=257` (F110 arch line "as ubuntu2604"). Added `*-systemd-too-old` and unversioned cases for all three.
- `scripts/check-tss-deps.sh` + `check_tss_deps.py`: exit 1 missing dependency/unknown soname, 3 no libtss2 soname, 2 bad input or missing tool. Tests in `test-check-packages-deps.sh` (ELF fixtures built with `cc` and stub sonames; positive control is a fixture, the real binary is left to `verify`; shared-table case uses the env override on both scripts). `nfpm_edit.py` gained `predep-set`.
- `docs/install.md` "TPM2 Software Stack" section; `test-docs-install.sh` compares each format line with `scripts/lib/tss_names.py` (table + nfpm.yaml) with edited-copy controls.
- Evidence: `test-check-packages-deps.sh` and `test-docs-install.sh` pass; `check-tss-deps.sh target/release/custodiod packaging/nfpm.yaml` exit 0.

### 2026-11-05 — F126 — attempt 1
- Table: `tpm_sign/oracle.rs` now holds the mechanism table (`rsa_rows` 15 rows, `p256_rows` 5, `Row::accepts` = the independent check, `salt_lengths`, `opaque_inputs`, `ECDSA_LENGTHS`, `ecdsa_digest`). `tpm_sign/every.rs` uses the lists and signs/checks every row (10 tests, same number as before).
- `kinds_suite` (`tests/kinds_suite.rs`, `kinds_suite/{cell,signs,lifecycle}.rs`): six cells; the encrypted-TPM cell is `Lacks` of `lacks_mechanism(rsa)` with the filter kept in place (never swapped out). Tests: `import_each_kind` (six distinct (kind, type) cells), `list_each_kind` (two keys, kind and certificate; "none after delete" lives only in `delete_each_kind`), `sign_every_mechanism_verifies` (every row verified, rejected with a same-type other key's certificate, the other type's certificate and a flipped byte; accepted count asserted per key type: 3 × RSA rows and 3 × P-256 rows), `delete_each_kind`, `replace_each_kind`. Opaque `CKM_RSA_PKCS` rows are checked by `oracle::recovered` (payload byte for byte).
- Evaluator notes: the ECDSA rows are all five digest lengths (1, 16, 32, 48, 64), a superset of SHA-256/384/512; PKCS#11 composed mechanisms stay with the PKCS#11 front end.
- Control run: using the wrong key type's lack in the lacking cell made `import_each_kind`, `list`, `delete` and `replace` fail.
- Evidence: `just quick` green; `kinds_suite` 5/5; `tpm_sign` 10/10.

### 2026-11-05 — F127 — attempt 1
- `scripts/check-no-plaintext.sh <state-dir> <p12>` (password on stdin; `openssl` reads it through `-passin env:`, never argv) derives with `openssl`: PKCS#8, the `.p12` itself, and for RSA PKCS#1 plus d, p, q, dp, dq, qinv (leading zeros dropped; the CRT values are searched too), for EC SEC1 and the scalar (the exact-size OCTET STRING of the SEC1 DER, so no sign or padding byte). `scripts/check_no_plaintext.py` searches every regular file (symlinks not followed, hidden and nested included): raw, hex (both cases, plain and `:`-separated), base64 and base64url at all three alignments; the text forms are also matched with whitespace (and `:`) removed, so wrapped PEM matches. Legacy `.p12` is read by retrying with `-legacy` (proved by `legacy_p12_is_read`).
- Exit codes: 0 clean, 1 match (files named on stdout), 2 bad usage / unusable input / unreadable file, 3 derivation failed (wrong password, not a `.p12`).
- Tests `crates/custodiod/tests/no_plaintext.rs` (+ `no_plaintext/`): `clean_after_import_each_kind` (six cells, asserts key files exist), `plaintext_key_in_store_is_found`, `planted_encoding_is_found` (10 encodings x 8 forms incl. raw, hex lower/upper/colon, base64 at offsets 0/1/2, wrapped PEM; flat, nested, hidden), `every_file_is_named_and_symlinks_are_not_followed`, `legacy_p12_is_read`, `certificate_is_not_a_match`, `bad_input_is_not_clean`, `password_only_on_stdin` (argv-recording shim). The test derives encodings with the `rsa`/`p256` crates (`TestKey`) plus `openssl` for PKCS#1/SEC1, not with the script's path. `Svc::state_dir()` added to the storage_choice rig.
- Controls: limiting the script to base64 offset 0, or to lower-case hex, made `planted_encoding_is_found` fail.
- Not here: e2e `noplain-*` cases and manual steps (they reuse the script); real `systemd-creds` cells.

### 2026-11-05 — F128 — attempt 2
- `crates/custodiod/tests/tpm_duplicate.rs` (reuses `storage_choice/rig.rs` `KindSvc`/`Svc` and `tpm_import/support.rs` `Rig` through `#[path]`). The service imports through the bus on `swtpm` (RSA, P-256, a second key, an id deleted via `DeleteKey` and re-imported: four). `tpm_records` walks the owner areas on disk and `KeyStore::list`/`get`, keeping `kind == tpm`; the count must be exactly those four ids and the stale (deleted) blob must be absent.
- Tests: `checks_every_stored_key` (stored bytes loaded unchanged, readpublic key in the stored certificate's key, control: a store with no TPM key has none), `stored_auth_policy_is_empty` (`tpm2_readpublic` leaves the `authorization policy` line out when empty; the parse requires a real public area; control: a created key with a policy shows 64 hex digits), `stored_key_cannot_be_duplicated` (policy session on `Duplicate`, `-G null`, new parent; exact code `0x99D` = `TPM_RC_POLICY_FAIL` on session 1; control: same command line duplicates a key with the `PolicyCommandCode` policy and no `fixedTPM`), `stored_blob_does_not_load_in_another_tpm` (second `Rig`, own seed; "integrity"; control loads on the service's TPM).
- Note: the stored key has `adminwithpolicy` and no `fixedtpm`; duplication is blocked by the empty policy, as in F113.
- Evidence: `cargo test -p custodiod --test tpm_duplicate` 4/4; `just quick` green.

### 2026-11-05 — F129 — attempt 1
- `crates/custodiod/tests/tpm_lifecycle.rs` (+ `tpm_lifecycle/world.rs`; shares `kit`, `rig`, `support`, `env`). Each `#[test]` builds its own store of four through the bus: `tpm` RSA/P-256 (TPM serving everything) and `encrypted-tpm` RSA/P-256 (TPM behind a filter that lacks `Import`, credentials by the real `systemd-creds` on the `swtpm`; the filter is dropped afterwards). Every test that clears the TPM signs with all four first and checks that no `key_lost` entry exists yet.
- `Svc` (storage_choice/rig.rs) gained `restart_service` (closes the service connection, opens a new store and a new service object on the same state, sink, polkit, creds and TPM access), `name_owner` and `call_error` (error name and message). The fields `_bus`/`_service` were renamed `bus_daemon`/`service_conn` because they are now read.
- Tests: `imports_four_keys` (ids, types, kinds, four files, real credential header with empty mask, the wrapper log shows exactly two real `encrypt` calls, control: the `MemoryCreds::tpm` credential is rejected by the same check), `signs_after_pcr_extension` (PCRs 0,2,4,7,16 differ; control: a real `--tpm2-pcrs=7` credential decrypts before and fails after), `signs_after_restarts` (swtpm restart with the old service up, PCRs read equal to the values before the extension, the PCR 7 credential decrypts again, then service restart: new bus-name owner, same list and files, one polkit request and one entry per signature; control: a service on an empty store gives `NoSuchKey`), `cleared_tpm_sign_fails_documented` (`KeyLost` with the message parsed from `docs/api.md`, one `signing_failed`/`key_lost` entry per attempt with kind, key id, uid; no password or key bytes in the fields), `cleared_keys_stay_listed` (list, file names and bytes unchanged after the failed signs and after a service restart), `cleared_keys_can_be_deleted` (four `deleted` entries, empty list and store, then `NoSuchKey`).
- Note: `SystemdCreds::decrypt` refuses PCR-bound credentials by design, so the PCR 7 control runs the real tool through the daemon's wrapper.
- The journal outcome of a lost key is `signing_failed` with cause `key_lost` (as F120), not an outcome named `key_lost`.
- Evidence: see the commit; `just quick` and `cargo test -p custodiod --test tpm_lifecycle`.

### 2026-11-05 — F130 — attempt 1
- `crates/custodiod/tests/tpm_resources.rs` (rig from `KindSvc`/`sign_kinds::kit`/`tpm_import::support` through `#[path]`; the fault filter is swapped in with `Counting::swap`). Slot count from `tpm2_getcap properties-fixed` (`parse_slots`; `MAX_SLOTS` named constant), calls = `3 * slots + MARGIN`.
- Tests: `slot_count_is_reported` (controls: name line or value line removed, empty text → error), `signatures_exceed_slots` (all verified by `openssl`, nothing loaded after; control: `slots` leaked primaries make `Sign` fail, a flush fixes it), `imports_exceed_slots` (kind `tpm`, `ListKeys` shows all, nothing loaded after the whole run, last key of each type signs and verifies), `failed_signatures_leave_no_slot_used`, `failed_imports_leave_no_slot_used` (class one `Respond(0x101)` repeated `slots + 1` times, the filter record shows the fault fired; class two drops and `FlushContext` fault: error, handles left behind (asserted), stand-in `tpm2_flushcontext -t`, nothing loaded; one long run after the last fault; failed imports leave `ListKeys` and the files unchanged).
- Errors on the bus: sign with `0x101` is `TemporarilyUnavailable`, except a failed `Load`, which is `KeyLost`; import is `TpmFailed`. A failed flush does reach the bus as an error, so no amendment was needed.
- Evidence: `just quick` green; `cargo test -p custodiod --test tpm_resources` 5/5.

### 2026-11-05 — F131 — attempt 1 (steps 1-3a of the amended contract; not finished)
- `e2e/run.sh`: `E2E_TPM` (`swtpm` default, `none`, `lacking`; anything else, empty included, refused before the engine is called). `all` with the variable unset runs every target with `swtpm`, then `none`; set, only that mode. The guest gets `-e E2E_TPM=<mode>`; record and log are `target/e2e/<target>.<mode>.record|log`; the guest must report `tpm=<mode>` and the host checks it equals the request. Failed runs are named `<target> (<mode>)` and do not stop the next. The recipes needed no change (`just` passes the environment; the host tests cover `run.sh`).
- Tests: `test-e2e-host.sh` (new F131 section, incl. a control with a `run.sh` that ignores the variable), `test-e2e-targets.sh` (each Containerfile installs `swtpm`, `tpm2-tools`, `swtpm-tools`; controls), stub in `scripts/lib/e2e-host-fixtures.sh` (`STUB_NOTPM`, `STUB_TPM_REPORT`, `STUB_FAIL_TPM`). Record names in the refusal/select tests follow.
- Guest: `e2e/tpm-lib.sh` (swtpm start/stop, drop-in under `/run/systemd/system/custodio.service.d/`, `tpm_observe` runs `tpm2_getcap` in a transient unit built from the installed unit's own properties and TCTI, `tpm_unit_problems`), `e2e/tpm-selftest.sh` (planted drop-ins are found), new case `tpm-installed-unit-clean` (checked before the setup and after the teardown), per-target `files.sh` (package file list; none for the refusal-only ubuntu2404, whose guest only reports `tpm=<mode>`). One exit trap in `guest.sh` (polkit + TPM teardown).
- Ran: `just e2e-cases debian13 pkcs11-tool-approve-rsa` in `swtpm`; `E2E_TPM=none` and `swtpm` with `tpm-installed-unit-clean` also selected: pass, 1/2 cases accounted. Findings in `docs/findings/F131.md`.
- Contract amended (separate commit): step 3 split into debian13 (done) and the other targets (3b).
- Open: 3b (images and confinement on ubuntu2604, fedora44, alma10, arch, ubuntu2404 by running each), step 4 (`lacking`: `TpmFilter` example for `custodio-it`, sockets mode, `tpm2_testparms` check, `guest.sh` accepts it), step 5 (CI jobs; a runner that cannot run the container must fail the job, never echo and pass), step 6.
- Pre-existing failures on the base commit, not from this work: `test-e2e-appid.sh`, `test-e2e-catalog.sh`, `test-e2e-jo.sh` (not in `just quick`'s path here; seen when running every `test-e2e-*.sh`).
- (same attempt, later) Step 4 `lacking`: example `crates/custodio-it/examples/tpm-filter.rs` (`UPSTREAM LISTEN alg=ID|curve=ID...`, sockets chmod 0666, prints `ready`), built by `just e2e-tpm-filter` (inside `e2e-packages`, only when `E2E_TPM=lacking`), mounted at `/e2e-bin/tpm-filter:ro` only in that mode (`E2E_TPM_FILTER` overrides the path; a missing file is refused before the engine is called). The guest runs swtpm on `upstream.sock` and the filter (RSAPSS lacking) on `swtpm.sock`; `tpm_observe lacking` shows from the unit's sandbox: `rsapss` not listed, `tpm2_testparms rsa2048:rsapss:null` fails with `0x1d2`, `rsa2048:rsassa:null` works, and swtpm itself accepts RSAPSS. `E2E_TPM=lacking just e2e-cases debian13 pkcs11-tool-approve-rsa tpm-installed-unit-clean` passes (2/2).
- Step 5 CI: job `e2e` (matrix 6 targets x `swtpm`/`none`, `E2E_TPM` and `E2E_ENGINE=docker` in the job env, `just e2e "$TARGET"`), on `ubuntu-24.04` like `package` (glibc ceiling), in `ci`'s `needs`. No fallback step: a runner that cannot run the privileged container fails the job. `scripts/test-ci-e2e.sh` parses the workflow (matrix expanded) with controls (no `none` jobs, `continue-on-error`, echo/`|| true`, not in `needs`, no variable). actionlint and zizmor clean. **Not run on a real runner.** `E2E_ENGINE` added to `run.sh` for it.
- The F131 host tests moved to `scripts/test-e2e-tpm-host.sh` (the old file hit the 5000-token limit).
- (same attempt, end) Step 3b: every other target ran `pkcs11-tool-approve-rsa tpm-installed-unit-clean` with `swtpm` and `none` (ubuntu2404, refusal-only, ran its own case): all pass; table in `docs/findings/F131.md`. Fedora ships `/usr/lib/systemd/system/service.d/10-timeout-abort.conf` for every service, so `tpm_unit_problems` ignores that directory only. SELinux could not be exercised here (no `/sys/fs/selinux`); recorded as inferred, no deviation.
- Step 6: manual controls (misspelt `CUSTODIOD_TEST_SWTPM_TCT`, wrong bind path in the drop-in) make the swtpm run fail at the unit-sandbox check; reverted. The `verify` ran: `just quick` green, and `pkcs11-tool-approve-rsa` passes on debian13 with `swtpm`, `none` and `lacking` (1 case accounted, record `tpm=<mode>`). Not run: the CI job on a real runner, the full `just e2e`, `lacking` on other targets.

### 2026-11-05 — F132 — attempt 1 (sessions 1-5, written by the operator; every session was cut)
- Done: steps 1-2. Fixes committed: `40cb0b9` (getrandom pair skipped in `deny.toml`, the new journal fields in
  `e2e/jo.py`, catalog text), `b1bf7fa` (upgrade accounts check reads the one-record-per-key store). `just check`,
  `api-contract`, `fuzz-smoke` (and its negative control) green on `b1bf7fa`.
- e2e seen passing on `b1bf7fa`: swtpm on all six targets (session 4, one record per target); none on alma10, arch,
  debian13 (session 3). Not yet run on `b1bf7fa`: none on fedora44, ubuntu2404, ubuntu2604. `package-gates` not run.
- Why it stalled: each session reran the baseline, then `just e2e` (about 60 minutes) and was cut at 45 minutes, before
  writing here or ticking steps. Contract amended: one target and mode per command, the loop runs the `verify`.
- Known issue: rootless podman lost its pause process twice (`podman info` fails, script tests fail); `timeout 120 podman
  system migrate` fixes it.
- Next session should: not rerun steps 1-2; run `E2E_TPM=none` on fedora44, ubuntu2404, ubuntu2604, then
  `just package-gates`, then step 5. Commit and update this entry after each run.
- (session 6) Env: `podman info` ok, swtpm 0.7.1. Contract base commit for the diff checks: `d54a614` (HEAD at session start; code unchanged since `b1bf7fa`).
  e2e passed on d54a614: `none` on fedora44 (5m47), ubuntu2404 (refusal-only, 21s), ubuntu2604 (5m35). With the earlier
  sessions: swtpm on all six, none on alma10, arch, debian13, fedora44, ubuntu2404, ubuntu2604. Step 3 done.
  Next: `just package-gates`, then the final rerun from a cleared `target/e2e/`.
  `just package-gates` was red only on namcap: five information lines for the new tpm2-tss dependency (F125), the same
  kind as glibc/libgcc. Added five entries with a reason to `packaging/lint/namcap.txt`; `just package-gates` exit 0
  (1m38s), step 4 done. Remaining: the final rerun (step 5) from a cleared `target/e2e/`, one target and mode per command
  (12 runs, ~5 min each; ubuntu2404 21s); record each pass below.
- (session 6, final rerun from a cleared target/e2e/, on the namcap-fix commit) passed: alma10 swtpm, alma10 none,
  arch swtpm, arch none, debian13 swtpm. debian13 none was running when this was written (see the next line).
  Still to rerun: debian13 none, fedora44, ubuntu2404, ubuntu2604 (each mode).
- (session 6) debian13 none passed on the same commit (4m54, alone; the earlier one was cut by the shell's background
  limit, not by a failure). Final rerun so far: alma10, arch, debian13 in both modes. Still to rerun: fedora44,
  ubuntu2404, ubuntu2604 in both modes (swtpm runs not yet repeated after the namcap-list change, which touches no e2e file).
- (session 6) Final rerun also passed: fedora44 swtpm, fedora44 none, ubuntu2404 swtpm, ubuntu2404 none. Left: ubuntu2604
  swtpm and none (the 2604 none run passed earlier this session on d54a614).
- (session 6, end) Final rerun complete from a cleared target/e2e/: twelve records, `tpm=swtpm` x6 and `tpm=none` x6, every
  `just e2e <target>` exit 0 (alma10, arch, debian13, fedora44, ubuntu2404, ubuntu2604 in both modes). All contract steps
  ticked. Diff base for the "no gate weakened" check: `d54a614`; the only change since is `packaging/lint/namcap.txt`
  (five tpm2-tss information entries, each with a reason). No root-only skips were checked here (`just check` ran in
  earlier sessions). The loop runs the whole `verify`.

### 2026-11-05 — F133 — attempt 1
- Done: cases `tpm-kind-import-rsa`, `tpm-kind-import-ec`, `tpm-kind-api-list`, `tpm-kind-cli-list`, `tpm-kind-journal`. Judgements in
  `e2e/tpmkind.py` (exact kind `tpm`, key types `rsa2048`/`ecdsa-p256`, `Storage: tpm.` line, one `import` entry per key in `custodio.service`,
  outcome `stored`), fixtures checked with `openssl` (`tpmkind-lib.sh`), self-test `tpmkind-selftest.sh`, host test `scripts/test-e2e-tpm-kind.sh`
  (in the `justfile` script-test list). Guest step `phase_runs tpm-kind` after cli (`tpmkind-run.sh`/`tpmkind-user.sh`: own agent dir, keys deleted);
  `owner-call.py list` prints ListKeys rows. `select.sh`: group `tpm-kind` before `tpm-*`.
- Placement (planned departure from the `features.json` wording): the ids are in `e2e/targets/debian13/cases.list` and on its `skip.list`, not in
  `e2e/cases.list`; `run.sh` adds the target list, so they are owed on debian13. Under `none`/`lacking` the guest reports them skipped.
- No skip under swtpm: `check-cases.sh` reads `CHECK_TPM_MODE` (set by `run.sh`) and rejects a `tpm-kind-*` skip in `swtpm` even when the skip list names it.
- Runs: `just e2e-cases debian13 'tpm-kind-*'` swtpm: 5 run (68 s wall, whole run); `E2E_TPM=none`: 5 skipped, accounted.
- Negative control (2) dropped, as the evaluator allowed (it repeats the host control on `encrypted-host`).
- (attempt 2) Fixed NEXT_FINDINGS: the 7 mutants in `scripts/test-e2e-tpm-kind.sh` run in parallel (host test ~2 s wall, was 6.3 s); dropped the checks that grep script text (guest.sh order, run.sh string, `judge` strings); `shellcheck disable` moved below the header. `check-cases.sh` no longer warns "skip list entry matches no skipped case" for `tpm-kind-*` under `CHECK_TPM_MODE=swtpm`. Not done (optional notes): delete-entry kind check in the journal judgement. `just quick` green.

### 2026-11-05 — F134 — attempt 1
- Done: cases `sign-kind-matches-mode`, `sign-rsa-pkcs`, `sign-rsa-pss-sha{256,384,512}`, `sign-rsa-composed`, `sign-ec-ecdsa`, `sign-ec-composed` (debian13 `cases.list`, group `sign` in `select.sh`, never skipped: `check-cases.sh` rejects a `sign-*` skip in any mode). Jobs and judgements in `e2e/sign.py` (openssl verification per mechanism/hash/salt with failing controls, exact request count per group, refusals `CKR_DATA_INVALID` with empty output), self-test `sign-selftest.{sh,py}` (signatures made by openssl, 19 bad-evidence mutants, fixture size/curve), host test `scripts/test-e2e-sign.sh`. Guest: `sign-run.sh` / `sign-user.sh` after `tpm-kind`; signatures of a group run at once, groups one after another.
- Findings (`docs/findings/F134.md`, contract amended in its own commit): `pkcs11-tool` cannot do PSS with this module (no public key object) so `e2e/p11-pss.py` (ctypes client of the module) makes PSS and the over-long RSA-PKCS payload; under `lacking` (RSAPSS removed) both keys are `tpm` (removing RSA instead fails the import with `CredentialsUnavailable`: no TPM-sealed systemd-creds in the container, F138's).
- Runs on this commit: `just e2e-cases debian13 'sign-*'` in `swtpm`, `none`, `lacking`: 8 cases run each, ~47 s per run. `just quick` green. The full `just e2e` and the other targets are not run (checkpoint).
- Also: `tk_make` takes a name (tpmkind-lib.sh), `import-user.sh` prints the import output when an import fails. Negative control (3) dropped (evaluator note 4).
- Evaluator notes 1 (CKR name identical across modes): the refusals must give `CKR_DATA_INVALID` in every mode, judged in each run. Note 2: exact total per group only.

### 2026-11-05 — F134 — attempt 2 (BLOCKED)
- Evaluator rejected amendment (2) (`lacking` == `tpm`). Withdrawn in the contract (own commit); evidence/step wording for the dropped negative control (3) fixed; wrong-salt control is in the guest judging (`e2e/sign.py`).
- Tried `alg=0x1` in the filter: import fails with `CredentialsUnavailable`; cause is that the root `systemd-creds@.service` refuses the TPM in a container (`docs/findings/F134.md`, last section). Needs a person: `BLOCKED.md`.
- Code unchanged otherwise; the `sign-*` run step is unticked.

### 2026-11-05 — F134 — attempt 3
- Done: the person chose option C of BLOCKED.md. Deviation in `SPEC_DEVIATIONS.md` (F134, also covers F138's `lacking` half), contract amendment (5): `lacking` keeps the RSAPSS filter
  and expects `tpm`/`tpm`, as `e2e/sign.py` already does. Finding extended: no container passes systemd's container check (PID namespace, no override in 257, Varlink `Encrypt` has no key
  choice), checked under rootful docker with the host TPM and a vTPM module present. BLOCKED.md removed. Code unchanged.
- Next session should: wait for the evaluator to review amendment (5) and the deviation, then run the unticked step (the three `sign-*` runs, `just quick`) and tick it.

### 2026-11-05 — F134 — attempt 4
- Ran on `9cd5dc7` (code unchanged since attempt 1): `just quick` green; `just e2e-cases debian13 'sign-*'` exit 0 in `swtpm` (71 s), `none` (50 s) and `lacking` (52 s),
  each "8 cases accounted for", records `tpm=<mode>`. Last step ticked. Kinds under `lacking` are `tpm`/`tpm` per amendment (5) and the deviation in `SPEC_DEVIATIONS.md`.
- Negative controls (1) and (2) are host tests in `scripts/test-e2e-sign.sh` (part of `just quick`). Not run: full `just e2e`, other targets (checkpoint).

### 2026-11-05 — F134 — attempt 5
- Fixed NEXT_FINDINGS: the deviation and amendment (5) now say what covers `encrypted-tpm` signing (kinds_suite F126 with a credential double; sign_kinds failure rows with real systemd-creds, RSA-PKCS/ECDSA only), the PSS gap, that `lacking` adds no kind coverage over `swtpm`, that the proof is for debian13, and that the person must confirm option C. Code unchanged; no step unticked.

### 2026-11-06 — F135 — attempt 1
- Done: cases `noplain-rsa`, `noplain-ec`, `noplain-no-key-file` (debian13 `cases.list`, group `noplain` in `select.sh`, never skipped: `check-cases.sh` rejects a `noplain-*` skip). `e2e/noplain.py` (kind and no-key-file judgements; `openssl` probes with `-passin pass:wrong-password` and stdin from /dev/null), `noplain-run.sh`/`noplain-user.sh` (alice imports RSA then EC, root scans after each; `noplain-ec` also scans the RSA `.p12`; no-key-file runs after both imports; planted-copy control; deletes), host test `scripts/test-e2e-noplain.sh` (in the justfile list). The script reaches the guest by a read-only mount of both `scripts/check-no-plaintext.sh` and `check_no_plaintext.py` (`e2e/run.sh`), unchanged.
- Deviation (F134 entry) extended to F135 with the F127 `encrypted-tpm` cell named (own commit). Finding `docs/findings/F135.md`.
- Runs on this code: `just e2e-cases debian13 'noplain-*'` exit 0 in `swtpm` (~61 s), `none` (42 s), `lacking` (43 s), "3 cases accounted for", kinds tpm / encrypted-host / tpm. `just quick` green. Full `just e2e` not run (checkpoint).

### 2026-11-06 — F135 — attempt 2
- Fixed NEXT_FINDINGS: `e2e/noplain.py` runs the (file, read) openssl probes in a thread pool; `noplain-run.sh` runs the ec scan, the rsa re-scan, the files judgement and the planted-copy control as background jobs joined with `wait` (each scan still follows its own import; per-job output files); host test judges the planted forms in parallel. Measured phase 21 s (swtpm), 21 s (none), 22 s (lacking): dominated by the two imports and the scripts' own openssl/python calls, so it stays above the 10–20 s estimate. All three `just e2e-cases debian13 'noplain-*'` exit 0, "3 cases accounted for"; `just quick` green.

### 2026-11-06 — F136 — attempt 1
- Done: cases `tpm-dup-authpolicy-empty`, `tpm-dup-duplicate-fails`, `tpm-dup-other-tpm` (debian13 `cases.list`; `none` skips on `skip.list`; group `tpmdup` in `select.sh`, step after noplain in `guest.sh`). `e2e/tpmdup.py` (record reader and judgements as functions of files), `tpmdup-run.sh`/`-user.sh`/`-cases.sh`, host test `scripts/test-e2e-tpmdup.sh` (in the justfile list; `check-cases.sh` refuses a `tpm-dup-*` skip in swtpm and lacking). `tpm_swtpm_start SOCK STATE` takes a state directory for the second swtpm. Finding `docs/findings/F136.md`.
- Evaluator notes: (1) commands of the second swtpm and its stop are in the finding; (2) both parents come from `mk_parent` and `samepub` compares their public areas; (3) every `tpm` record is judged (the run had four), and `inventory` requires `td-rsa` and `td-ec` among them; (4) the guest control key made with a policy must show `authorization policy:` with tpm2-tools 5.7, or the case fails; host test uses the real 0x99D/0x1DF lines; (5) the second parent's name is only a log line; (6) phase time below.
- Record reading agrees with the real encoder: `checks_every_stored_key` in `tpm_duplicate.rs` runs `tpmdup.py scan` on `Record::encode` output.
- Runs: `just e2e-cases debian13 'tpm-dup-*'` exit 0 in swtpm (phase 22 s), lacking (25 s), none (3 skipped, accounted). Full run not made (checkpoint): expect +22 s on the debian13 swtpm run, against ~50 s of headroom.

### 2026-11-06 — F137 — attempt 1
- Done: cases `pcr-extended-signs`, `pcr-restarted-signs`, `pcr-signs-every-key` (debian13 `cases.list`; `none` skips on `skip.list`; `check-cases.sh` refuses a `pcr-*` skip in swtpm and lacking; group `pcr` in `select.sh`, step after tpmdup in `guest.sh`). `e2e/pcr.py` (judgements as functions of files), `pcr-run.sh`/`pcr-user.sh`/`pcr-cases.sh`, `tpm_swtpm_restart` in `tpm-lib.sh`, host test `scripts/test-e2e-pcr.sh` (in the justfile list, 1.4 s). Finding `docs/findings/F137.md`; deviation F134 extended to F137 in its own commit.
- Evaluator notes: (1) `pcr-signs-every-key` is the only post-restart signing proof; `pcr-restarted-signs` judges the restart facts and the listed keys; (2) the restart judgement compares with the first reading; (3) no later journal count is affected (finding); (5) readiness is new MainPID + is-active + bus Ping; (6) the helper waits for no process on the state directory.
- Runs on this code: `just e2e-cases debian13 'pcr-*'` exit 0 in swtpm (48 s, phase 23 s), lacking (46 s, phase 25 s), none (3 skipped, accounted). Full debian13 run grows by ~23 s on top of F135's and F136's (budget 430 s): not measured here (checkpoint).

### 2026-11-06 — F138 — attempt 1
- Done: cases `fallback-host-import-rsa`, `fallback-host-import-ec`, `fallback-host-says-weaker-why`, `fallback-host-cli-list` (run in mode `none`: kind `encrypted-host` from `ListKeys`, one `Storage:` line, "weaker than a TPM key", reason "no TPM", the `custodio list` row of each key) and `fallback-tpmbound-import`, `fallback-tpmbound-cli-list` (skipped in every mode). Judgements in `e2e/fallback.py`, `fallback-run.sh`/`-user.sh`/`-cases.sh`, group `fallback` in `select.sh` (after pcr in `guest.sh`), ids in the debian13 `cases.list`/`skip.list`, host test `scripts/test-e2e-fallback.sh` (in the justfile list; it is also the self-test of the judgements). `check-cases.sh`: a `fallback-tpmbound-*` case reported run is refused in every mode, a `fallback-host-*` skip is refused in `none`.
- **Read this plainly:** under `E2E_TPM=lacking` the verify passes with 6 skipped and nothing run. That is acceptable only because of the F134 deviation (the container cannot make `encrypted-tpm`); it is NOT kind coverage. The `encrypted-tpm` text and list row are covered only by `custodio-cli` `storage_kind::import_encrypted_tpm` and `list_shows_each_kind`, the kind by `kinds_suite` (F126). The deviation entry now names this (own commit).
- `just quick` green. Runs: `E2E_TPM=none just e2e-cases debian13 'fallback-*'` exit 0 (45 s wall, phase 21 s; "6 cases accounted for", 4 run, 2 skipped); `lacking` exit 0 (21 s, 6 skipped). Full run grows by ~21 s in `none` (budget risk noted for the checkpoint; no swtpm cost). Later steps unchanged: own agent dir, both keys deleted.

### 2026-11-06 — F139 — attempt 1
- Done: cases `tpmfail-device-unopenable`, `tpmfail-tpm-error`, `tpmfail-credentials-down-tpm-lacking`, `tpmfail-credentials-down-host` (debian13 `cases.list`/`skip.list`; group `tpmfail` in `select.sh`, step after fallback in `guest.sh`; run in swtpm only, skipped in none and lacking). `e2e/tpmfail.py` (the five facts as functions of files), `tpmfail-lib.sh` (drop-in repoint + restart until ready, credential socket stop/start, restore trap), `tpmfail-stub.py` (swtpm proxy: `fail-capability` and `lack-rsa`), `tpmfail-run.sh`/`-user.sh`/`-cases.sh`, host test `scripts/test-e2e-tpmfail.sh` (in the justfile list, includes a stub test against a fake upstream). `check-cases.sh`: `tpmfail-*` skipped in swtpm refused, reported run in none/lacking refused. Finding `docs/findings/F139.md`.
- Causes (evaluator notes 2, 3): stale socket -> `TpmFailed`/`tpm_device`; failing GetCapability -> `TpmFailed`/`tpm_error`; judged exactly. Stopping `systemd-creds.socket` is enough (socket file stays: refused). The CLI prints `unknown error (com.rfirma.Custodio1.Error.TpmFailed)`: no CLI text for these two errors; not changed here.
- Departure from the contract: the filter program is mounted only in mode `lacking` (tested by `test-e2e-tpm-host.sh`), so "TPM lacks RSA" in swtpm uses the stub's `lack-rsa` mode instead of `alg=0x1`. No contract step changes.
- Cost: attempts and restore imports use per-case ids and the step deletes all its keys at once in one session at the end (a polkit-authorised call is ~5 s). Runs on this code: `just e2e-cases debian13 'tpmfail-*'` swtpm exit 0 (82 s wall, phase 62 s), none and lacking exit 0 (21 s, 4 skipped, accounted). `just quick` green. Budget sum (note 7): the full debian13 swtpm run grows by ~62 s on top of F135 (~20), F136 (~22), F137 (~23): not measured in full (checkpoint); budget 430 s against 360 s measured before them, so it will probably pass 430 s and needs a decision at the checkpoint. Later steps' counts: none read journal counts after this step (guest.sh only greps the journal for the password); keys deleted, drop-in and credential socket restored.

### 2026-11-06 — F140 — attempt 1
- Done: cases `tpm-clear-sign-fails`, `tpm-clear-keys-listed`, `tpm-clear-delete` (debian13 `cases.list`; `none` skips on `skip.list`; `check-cases.sh` refuses a `tpm-clear-*` skip in swtpm and lacking; group `tpmclear` in `select.sh`, before the `tpm-*` catch-all; step after tpmfail in `guest.sh`). `e2e/tpmclear.py` (judgements as functions of files), `tpmclear-sign.py` (D-Bus Sign with the error text), `tpmclear-run.sh`/`-user.sh`/`-cases.sh`, host test `scripts/test-e2e-tpmclear.sh` (justfile list, ~2.7 s). Finding `docs/findings/F140.md`. Deviation F134 extended to F140 for `encrypted-tpm` with the contract amendment (own commit; the negative control reworded: the re-imported key signs on the same cleared TPM).
- Isolation: a second swtpm (behind the filter in `lacking`), the e2e drop-in pointed at it with `tf_point`, restored by a trap; the main TPM is never cleared. `tpm2_clear` works as is on swtpm and through the filter (exit 0).
- Evaluator notes: (2) a successful Sign leaves the state directory unchanged (control in `tpm-clear-sign-fails`); (3) one `pkcs11-tool --sign` makes two service `Sign` calls (6 approvals = 6 entries per round), so entries are compared with the agent's approvals; (4) the second TPM is observed lacking before the keys are imported; (5) fixed template, no unique data; (7) no extra case added; (8) the placement check is a list-file assertion, not a document grep.
- Runs on this code: `just e2e-cases debian13 'tpm-clear-*'` swtpm exit 0 (55 s whole run, phase 31 s), lacking exit 0 (57 s, phase 32 s), none exit 0 (24 s, 3 skipped, accounted). Budget sum: the full debian13 swtpm run grows by ~31 s on top of F135 (~20), F136 (~22), F137 (~23), F139 (~62); not measured in full (checkpoint; F139 already noted it will probably pass 430 s). Later steps: the keys are deleted, the drop-in, service and TPM are as before; no journal count read by later steps (guest.sh only greps for the password).

### 2026-11-06 — F141 — attempt 1
- Done: cases `upgrade-kinds-before`, `-kept`, `-signs` (run in every mode) and `upgrade-kinds-tpmbound` (skipped in every mode, `skip.list` names F134), in the debian13 `cases.list` only (group `upgrade` in `select.sh`). They ride on the one N to N+1 run of `upgrade.sh` and the keys `upgrade-accts.sh` seeds: `e2e/upgrade-kinds.sh` (enabled only for id `upgrade`, only where the target's `cases.list` has them, never under `E2E_NO_ACCOUNTS`), judgements in `e2e/upgradekinds.py` (the kind is judged absolutely: swtpm/lacking `tpm`, none `encrypted-host`), `kinds PHASE` in `upgrade-accts-user.sh` (ListKeys + `custodio list`, no polkit), `guest.sh` passes `E2E_TPM` to `upgrade.sh`. `check-cases.sh`: a skip of the three run cases refused in any mode, `upgrade-kinds-tpmbound` reported run refused. Host test `scripts/test-e2e-upgradekinds.sh` (justfile list, ~4 s; placement, accounting, judgements per mode incl. every wrong-kind pair, a stub-driven run of `upgrade-kinds.sh` and a mutant that leaves the judgement out).
- Evaluator notes: (1) certificates are not compared a second time (`upgrade-keys-listed` does it); `kept` pairs ids, owners, types and kinds of the API and CLI rows. (2) `encrypted-tpm` cover: new `state_format` `reload::kinds_owners_and_certificates_survive_a_reopen` (three kinds, two owners, shared id, certificates) plus the existing `tpm_lifecycle` `signs_after_restarts`; named in the skip reason. (3) F134 deviation extended with the F141 sentence, contract amendment in its own commit (ede09f6). (4) `lacking` is a sanity repeat, not kind evidence. (5) the signing round's entries are read after a journal cursor taken just before `user_run sign`; the count must equal the agents' requests (alice 3 + 3, bob 3 = 9), host control has an extra entry from before the cursor.
- Runs: `just e2e-cases debian13 'upgrade-*'` swtpm, `E2E_TPM=none` and `E2E_TPM=lacking` all exit 0, "16 cases accounted for", kinds tpm / encrypted-host / tpm. Upgrade phase 31 s with the cases against 30 s without (wall 96 s both). Full `just e2e` and other targets not run (checkpoint). Budget sum: F141 adds ~1 s to the debian13 run on top of F135–F140's growth noted above.
- Known, not mine: `scripts/test-e2e-select.sh` fails on HEAD (its hard-coded group list lacks groups added since F133); it is not in `just quick`.

### 2026-11-06 — F141 — attempt 2
- Fixed NEXT_FINDINGS: `scripts/test-e2e-upgradekinds.sh` is now mode 755 (it runs in `test-scripts`, part of `just check`, not `just quick`; the contract's "in `just quick`" wording was wrong). `upgrade-kinds.sh` captures each judgement before reporting (`p=$(uk …) || fail`), so a crashed `upgradekinds.py` stops the run; new host control with a crashing stub. `guest.sh`: `E2E_TPM` dropped from the old-path line, set on the N→N+1 line. Host test measures ~7.5 s wall alone (the contract's 5 s was an underestimate; it runs in parallel with the other script tests).

### 2026-11-06 — F142 — attempt 1
- Done (steps 1–3): `scripts/package-m3.sh` (tag `v0.5.0` via `git archive` into `target/m3-build/tree`, the tag's own `just package version=0.0.9`, output `target/packages-m3`, stamp = tag commit + version + script hash, rebuilt when an output file is missing; run from `e2e-packages`). Measured: cold 23 s, warm 0.01 s; the packaged daemon's sha256 equals the tag build's and differs from this tree's; deb 0.0.9-1 < N 0.1.0-1 (`dpkg --compare-versions`). Guest: mode `m3` in `guest.sh` (`/pkg-m3`, after the service step), `run.sh` mounts it and makes the m3 run for `upgrade-m3-*` (selection or full run), `e2e/upgrade-m3.sh` + `upgrade-m3-user.sh` (own seed: alice rsa1/ec1, bob rsa1/bobonly through the M3 CLI; journal cursor taken right before `install.sh`; judgements in `e2e/upgradem3.py`, crash of a judgement stops the run), cases in `e2e/cases.list` (group `other-mode`, no skips anywhere), CI e2e job checks out with `fetch-depth: 0` for the tag. Host tests: `test-e2e-m3.sh`, `-judge.sh`, `-run.sh` (justfile list); fixtures/stub podman and `test-e2e-host.sh` updated for the extra mount and container.
- `just quick` green. Pre-existing failures at HEAD, unchanged by this work: `test-e2e-host.sh`, `-host-oldpath.sh`, `-select-host.sh`, `-jobs-host.sh`, `-select.sh`, `-tpm-host.sh` (stub reports none-mode skips as run).
- Real runs on 9b4a0bd (all exit 0, "4 cases accounted for"): `just e2e-cases debian13 'upgrade-m3-*'` swtpm (wall 67 s, m3 phase 43 s), `E2E_TPM=none` debian13 (68 s), fedora44 swtpm (112 s, phase 44 s), alma10 swtpm (115 s, phase 43 s; the other-format check). fedora44 `none` not run (proves nothing new). The first guest run passed with no fix needed.
- Budget: the full `just e2e` adds one m3 guest run (~45 s phase plus boot, ~10 s) to each target-mode, in parallel with the others; debian13 swtpm was at 360 s of 430 s before F135–F140 growth (already flagged by F139), so the checkpoint decides; the full run was not made here.
- Not done: nothing in the contract; full `just e2e` and the package gates are the checkpoint's.

### 2026-11-06 — F142 — attempt 2
- Fixed NEXT_FINDINGS: the re-import now checks polkit. `upgrade-m3-user.sh import` writes the agent's request count to `reimported/import/USER.requests`; `upgradem3.py reimport` requires 2 per user. Host controls: `test-e2e-m3-judge.sh` (count 0, count missing) and `test-e2e-m3-run.sh` (`SIM_REQUESTS=0`); the `for` indent is fixed. `test-e2e-m3*.sh` pass.
- Correction to attempt 1: `E2E_TPM=none just e2e-cases fedora44 'upgrade-m3-*'` was run by the evaluator (exit 0, 4 cases accounted, 96 s); I had not run it. `test-e2e-m3*.sh` are in `test-scripts` (part of `just check`), not `just quick`.
- Runs: `just e2e-cases debian13 'upgrade-m3-*'` swtpm exit 0 (68 s wall) with the new check; `just quick` green. The six host tests red at base (`test-e2e-host` etc.) are not touched here.

### 2026-11-06 — F143 — attempt 1
- Done: cases `tpm-slots-sign-rsa`, `-sign-ec`, `-import`, `-no-leak` (debian13 `cases.list`; `none` skips on `skip.list`; `check-cases.sh` refuses a `tpm-slots-*` skip in swtpm and lacking; group `tpmslots` in `select.sh` before `tpm-*`, step after tpmclear in `guest.sh`). `e2e/tpmslots.py` (judgements as functions of files), `tpmslots-run.sh`/`-user.sh`/`-cases.sh`, host test `scripts/test-e2e-tpmslots.sh` (justfile list). Finding `docs/findings/F143.md` (property is the reported *minimum*, so only `tpm-slots-no-leak` is the leak proof).
- Evaluator notes: (1) the two signing runs are parallel jobs (`TS_SERIES=1` runs them in series); no failure from overlap seen, so no fallback; (2) in the finding; (3) the "before" snapshot of `handles-transient` and `handles-loaded-session` is taken after a Ping and before any call of the step; (4) the count is judged from the call records the guest logs after each call (`calls`/`imports` need records >= slots+3, numbered 1..n); (5) the placement check stays in the host test (check-cases.sh has only the skip rule, no placement rule); (6) budget below.
- Slots seen: 3 (swtpm and lacking), so N = M = 6. Control: `tpm2_createprimary` leaves 1 transient handle, the judgement reports it, flush returns to the first snapshot. Deletes run as parallel jobs in alice's one session (42 s -> 7 s).
- Runs: `just e2e-cases debian13 'tpm-slots-*'` swtpm exit 0 (74 s wall, phase 50 s), lacking exit 0 (77 s, phase 51 s), none exit 0 (24 s, "4 cases accounted for", 4 skipped). Phase: import 11 s, sign 2 s, 6 imports ~31 s, rest ~7 s.
- Budget: the full debian13 swtpm run grows by ~50 s on top of F135 (~20), F136 (~22), F137 (~23), F139 (~62), F140 (~31), F142 (m3, parallel); 360 s was measured before those, budget 430 s, so the sum (~570 s) is well past it. Not measured in full (checkpoint); needs a budgets decision there. Later steps: all keys deleted, service and TPM as before, no journal count read by later steps.

### 2026-11-06 — F144 — attempt 1
- Done: cases `journal-kind-import`, `-purge`, `-owner`, `-key-lost`, `-temporarily-unavailable` (debian13 `cases.list`; group `journalkind` in `select.sh`, step after tpmslots in `guest.sh`; `check-cases.sh` refuses a skip of any `journal-kind-*` case in any mode, no `skip.list` line). `e2e/journalkind.py` (extractor of the document's queries and the judgement as functions of files), `journalkind-run.sh`/`-user.sh`/`-cases.sh`, host test `scripts/test-e2e-journalkind.sh` (justfile list; 2 s; five mutations of the judgement killed). Finding `docs/findings/F144.md`. Contract amended (every injection exists in every mode: no skips).
- Injections: purge = old-format files placed as root for alice and bob + service restart (the packaged start-up path); `key_lost` = last byte of the record flipped and put back; `temporarily_unavailable` = missing TPM path via `tf_point` (swtpm, lacking) or credential socket stopped (none). Each gave its cause in all three modes.
- Entries per query (all modes): kind of the mode 2 (others 0), purge 4, owner 2 + 2, key_lost 1, temporarily_unavailable 1. Forged entries by root and alice (import per kind, purge per uid, both causes) are in the window and never returned; an approved and a denied sign are in the window and not returned.
- Runs: `just e2e-cases debian13 'journal-kind-*'` swtpm exit 0 (42 s wall, phase 18 s), lacking exit 0 (44 s, phase 18 s), none exit 0 (42 s, phase 18 s), "5 cases accounted for" each.
- Later steps: all keys of the step deleted, bob's area removed, service and TPM as before, the step's agent has its own directory, so no journal or request count a later step reads changes except the extra service entries in the journal (the journal count steps run before this one).
- `just quick` green. Budget: the step adds ~18 s to the full debian13 swtpm run, on top of F135 (~20), F136 (~22), F137 (~23), F139 (~62), F140 (~31), F143 (~50); the sum was already past 430 s (F143 entry); not measured in full (checkpoint), where `budgets.tsv` needs a decision.

### 2026-11-06 — F145 — attempt 1
- Done: `docs/manual-acceptance.md` sections 20 to 23 (M4 acceptance 13 hardware TPM with the event table, 14 VM without a TPM, 15 state directory copy, result form; title and intro extended). `scripts/tpm-record-check.sh STATE KEY_ID` (exit 0 pass / 1 check failed or a command broke / 2 usage or no tpm record; prints `authPolicy: empty|NOT empty`, `tpm2_duplicate: failed with TPM_RC_POLICY_FAIL|succeeded|failed with another error`). `scripts/test-docs-manual-m4.sh` (in `test-scripts`), split into `scripts/lib/docs-manual-m4-{check,swtpm,controls}.sh` because of the 5000-token file limit. Finding `docs/findings/F145.md`.
- The test runs the page's own helper line and `tpm2_pcrread`/`tpm2_pcrextend` lines under `scripts/with-swtpm.sh`: (i) key without policy passes; (ii) duplicable key exits 1 and reports a non-empty authPolicy AND a duplicate that succeeds (evaluator note); (iii) altered private area exits 1 as a load failure; (iv) unknown id and a wrong option exit 2 with usage; PCR 7 changes with the page's extend, not with the PCR 8 control. The kind_text notice is compared across the `\` continuation (both pieces).
- Measured: `scripts/test-docs-manual-m4.sh` ~24 s wall alone (the contract's 12 s was low: ~170 controls at ~0.1 s each), under the 60 s script budget.
- GAP FOR A PERSON (not changed here): `custodio list` prints `kind: encrypted-host` and no "weaker" sentence, while SPEC acceptance 14 says it does. The page says so and leaves the decision to the approver.
- Not run: hardware TPM, fwupd (`fwupdmgr` is not in the container), reboot, Firefox, LibreOffice: marked unverified on the page.
- Attempt 2 (fixes of NEXT_FINDINGS): (1) case (iv) inserts `--bogus` after the script name, no longer depending on `TMPDIR`; `TMPDIR=/tmp scripts/test-docs-manual-m4.sh` passes. (2) The ~170 controls now run in parallel subshells (`bg`, at most `nproc` at once, each with its own fixture `$fx`); the api/audit controls run as one sequence in one subshell; a failing control fails the test (checked with a void control). Measured: ~6.5 s wall for the whole test (not 24 s). It runs in sequence with the other script tests in `test-scripts`. Section 22 of the page now says the VM runs only the `rsa2048.p12` check.

### 2026-11-06 — F146 — attempt 1 (session 1)
- Done: step 2 (F145 gap). `custodio list` prints a `note:` line under a key of kind `encrypted-host` or `encrypted-tpm`: the reason of `kind_text` (`weaker_note` in `custodio-cli/src/lib.rs`); `tpm` and unknown kinds get none. Test first (`storage_kind::list_says_weaker_for_the_two_weaker_kinds_only`: host-key phrase and "no TPM" for host, "lacks a capability"/"bound to this TPM" and no "host key" for tpm; failed before the change); `list_shows_each_kind`'s `!contains("weaker")` removed (contradicted SPEC acceptance 14). `custodio-it` `list.rs` expected blocks gain the `note:` line. `docs/manual-acceptance.md` step 3 of the acceptance 14 section (numbered 21 in the page) shows the note; `docs-manual-m4-{check,controls}.sh` compare the note with `kind_text`; `scripts/test-docs-manual-m4.sh` passes; `just quick` green.
- Not done yet: step 1 (baseline `just check`, api-contract, fuzz-smoke), steps 3–5 (e2e per target, package gates), BLOCKED.md for budgets. Note for them: Evidence line on BLOCKED.md times means lone-run estimates, not measurements.
- Step 1 done on commit after cd4b90a (`fix(F146): bring the stale e2e host tests up to date with M4`): the seven red script tests were stale expectations of the tests, not product defects: the stub guest (`scripts/lib/e2e-host-fixtures.sh`) now skips the cases its mode cannot run (same rules as `check-cases.sh`) like the real guest; `test-e2e-select-host.sh` expects the M3 container and the noplain mounts; `test-e2e-jobs-host.sh` expects the m3-upgrade phase line (13 lines); `test-e2e-lifecycle.sh` reports the skip-list cases as skipped; `test-e2e-select.sh` knows the new groups and phases. No control removed. `CHECK_FORCE=1 just check` exit 0 (script tests 166 s); `just api-contract` exit 0; `just fuzz-smoke` exit 0 (10 targets run; `cargo fuzz list` of both crates shows the same 10; `just fuzz-smoke "a b c"` exits 1). `podman info` ok, swtpm 0.7.1.
- Step 3 (part): the common cases ran guest steps of the M4 cases on every target, but only debian13's `cases.list` owes them, so alma10 and arch failed the accounting ("unknown case tpm-kind-…"). Fixed at the cause: `select.sh` `owed_group`, `phase_runs` runs the ten M4 steps only on the target whose own list names a case of the group (control in `test-e2e-select.sh`; `just quick`/`test-e2e-select.sh` ok). Runs on that code, `E2E_TPM=swtpm timeout 1700 just e2e T`, lone runs (estimates against `budgets.tsv`): debian13 exit 0, 160 cases accounted, 605 s (ran before the fix; unaffected, it owes the cases); alma10 exit 0, 103 cases, 357 s; arch exit 0, 103, 307 s; fedora44 exit 0, 103, 303 s. Still to run: ubuntu2404, ubuntu2604, `E2E_TPM=none` debian13; package gates; final rerun.
- F146 session 2: step 3 finished. `E2E_TPM=swtpm just e2e` ubuntu2404 exit 0 (5 cases, 5 s; needed `podman system migrate` first, as F132), ubuntu2604 exit 0 (112 cases, 295 s); `E2E_TPM=none just e2e debian13` exit 0 (160 cases, 416 s); debian13 swtpm rerun after the select.sh fix exit 0 (160 cases, 605 s). `target/e2e/` holds 7 records: six `tpm=swtpm`, one `tpm=none`. Times are lone-run estimates. `just package-gates` exit 0 (68 findings, all excepted, 0 stale). `BLOCKED.md` written for the debian13 budget (lone 605 s vs 430 s; none 416 s). Step 5: only debian13 swtpm ran before the last fix, and it was rerun; final `just quick` run after this entry.

### 2026-11-06 — F146 — attempt 1 (session 3)
- Final `just quick` after the last fix (`7fd867e`) and the person's budget decision (debian13 700 s, `BLOCKED.md` answered and removed): exit 0. Every contract step is ticked; no code changed in this session. The e2e times above are lone-run estimates; the loop's `verify` is the gate.

### 2026-11-06 — F146 — attempt 2 (session 1)
- The loop's `verify` failed only on arch (swtpm), in the parallel `just e2e`: lifecycle `remove`, the pacman hook "Reloading system bus configuration" gave `Job for dbus-broker.service failed`, so `removal-not-activatable` failed ("still activatable"). Seen twice in the parallel run (654 s / 638 s wall for debian13), never in a lone arch run (`E2E_TPM=swtpm just e2e arch` exit 0, 103 cases, 308 s) nor with 14 CPU burners (`e2e-cases arch 'removal-*'` exit 0). The `chroot() environment: Permission denied` lines also appear in passing runs, so they are not the cause.
- Added to `e2e/lifecycle.sh`: when the tool's output has a failed `Job for ...`, the journal of dbus-broker/dbus is printed (diagnostic only, no assertion changed). Next: rerun the whole `just e2e` to read the journal, then fix the cause.
- Parallel `just e2e` rerun with the diagnostic: arch passed this time; alma10 and debian13 (swtpm) failed in `cli-run.sh`, case `cli-import-pkttyagent-wrong-password`: `import-wrong` result `timeout` (the `timeout 150` of `e2e/cli-user.sh:46` around `cli-pty.py`, recorded by `rec_pty import-wrong` in `e2e/cli-pty-user.sh:49`), "pkttyagent did not report a failed authentication". All other targets passed (timings: alma10 341 s failed, debian13 328 s failed, others passed). So the lone runs pass and the 6-at-once run shows load-dependent flakes in two different places (arch bus reload; pty wrong-password). The cause of each is not found yet. Next session: read `e2e/cli-pty.py` (`--repeat`, expect handling) and find what makes the wrong-password dialogue hang under load (a race between the repeated prompt and the expect step); lone reproduction: `just e2e-cases debian13 'cli-*'` under CPU burners. Then the arch bus-reload flake (journal now printed on a failed hook job).

### 2026-11-06 — F146 — attempt 3 (session 1)
- Could not reproduce the `cli-import-pkttyagent-wrong-password` timeout (24 burners on 12 CPUs, `just e2e-cases debian13 'cli-import-pkttyagent*'` passes); the failed run's transcript was not kept, so the cause is a hypothesis: the answer to the repeated `Password: ` prompt is lost under load (tty input flush when the agent switches echo off). Hardening, not a proven fix: `e2e/cli-pty.py` answers a repeat prompt left unanswered for 15 s again (max 3 times, logs `resend` in the events file); `cli_agent_outcome_problems` now prints the last 300 bytes of the transcript on failure, so a next failure shows the cause. The arch bus-reload flake (journal printed since attempt 2) is not touched and still unexplained. `just quick` green. The loop's `verify` is the gate.

### 2026-11-06 — F146 — after attempt 3 (with a person)
- Cause of the parallel-only e2e failures found (`docs/findings/F146.md`): the host's `fs.inotify.max_user_instances` (128) runs out with 6 containers at once; dbus-broker reloads fail (`dirwatch_new: Too many open files`). The person raised it to 1024 on the host.
- `e2e/run.sh` refuses to start below 32 per run at once + 64 (`E2E_INOTIFY_LIMIT_FILE` overrides the path; the stub fixtures point it at a large value); controls in `scripts/test-e2e-jobs-host.sh`. `e2e/lifecycle.sh` prints the bus journal for dnf5's `>>> Job for ... failed` too. The pty resend of fe681c4 is reverted (wrong hypothesis); its transcript on failure stays.
- `test-e2e-jobs-host`, `-host`, `-select-host`, `-tpm-host`, `-host-oldpath`, `-m3` pass. `just quick` in the person's host shell fails only in `custodiod --test creds` (`Unavailable`), the same on HEAD without these changes (host environment, not the harness container).
- Next: `rm -f .harness/state/F146.attempts && just harness run`.

### 2026-11-06 — F146 — attempt 4 (session 1)
- NEXT_FINDINGS.md was the failure from before the host's `fs.inotify.max_user_instances` went from 128 to 1024 (fedora44 `removal-not-activatable`, dbus-broker `Job ... failed`; cause in `docs/findings/F146.md`). No code change. With the limit at 1024: `just quick` exit 0; whole parallel `just e2e` from a cleared `target/e2e/` exit 0, all seven runs passed (six swtpm, debian13 none), 160 cases accounted for debian13, wall 681 s for 7 runs.

### 2026-11-06 — F146 — attempt 5 (session 1)
- NEXT_FINDINGS.md is the same fedora44 `removal-not-activatable` failure that attempt 4 already traced to the host's inotify limit (`docs/findings/F146.md`); its timestamp (16:30) predates the fix. Host limit is 1024 now; `just quick` exit 0. No code change; the loop's `verify` is the gate.

### 2026-11-06 — F146 — attempt 6 (session 1)
- NEXT_FINDINGS: two script tests over budget in the parallel `just check` (`test-shell-scripts.sh` 92 s of 80, `test-arch-lifecycle-real.sh` 97 s of 95). Lone runs were 63 s and 49 s. `test-shell-scripts.sh` now runs its clean and its dirty shellcheck at once on two copies (63 s -> 33 s lone; one shellcheck call over all files stays, since batching changes what it follows). `test-arch-lifecycle-real.sh` runs the ten mutants at once in subshells (49 s -> 37 s lone); a surviving mutant still fails the test (checked with a mutant edited to a no-op).

### 2026-11-06 — F146 — attempt 7 (session 1)
- NEXT_FINDINGS.md (`test-e2e-upgrade.sh` 65 s of 60 s) is older (21:19) than the person's budget decision: `budgets.tsv` now has 90 s for it (commit fa1ba0b, approved in 83ce403). No code change; the loop's `verify` is the gate.

### 2026-11-06 — F146 — attempt 8 (session 1)
- NEXT_FINDINGS: the verify passed; four budgets exceeded in the parallel run: e2e alma10 478/470 s, arch 420/410 s, debian13 707/700 s, `test-install-real.sh` 88/60 s. The e2e overages are 2 % (run-to-run noise at seven containers at once). `test-install-real.sh` takes 11 s alone (measured now), so the 88 s is contention in the parallel `just check`. No code change; `BLOCKED.md` asks a person for the budgets. `budgets.tsv` untouched.
