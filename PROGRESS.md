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
