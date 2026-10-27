## [0.1.0] - 2026-10-27

### 🚀 Features

- *(F01)* Add Cargo workspace and lint baseline
- *(F05)* Add key store with 0700/0600 permissions
- *(F06)* Add .p12 import (RSA 2048 / P-256), fuzz target and just fuzz-build
- *(F07)* Add signing primitives for RSA_PKCS, RSA_PKCS_PSS and ECDSA
- *(F08)* Add polkit authorization behind a trait and the sign policy file
- *(F09)* Add D-Bus service with polkit-guarded Sign, integration tests and fuzz target
- *(F10)* Add import CLI reading the password from the terminal
- *(F11)* Add PKCS#11 module forwarding signatures to the service over D-Bus
- *(F15)* Add systemd unit, D-Bus policy and hardening score gate
- Automate planning: planner, initializer, contracts and approval gates
- Add just recipes and a status command for the harness
- Add `just milestone` and `just release`

### 🐛 Bug Fixes

- *(F05)* Harden key store: owner check, O_NOFOLLOW, real umask test
- *(F05)* Test open owner/file-type checks, reject FIFO keys, exact dir mode under umask
- *(F06)* Require certificate to match key, count keys without localKeyId, no orphan cert, robust fuzz-build
- *(F15)* Static service user for the bus policy, check the policy and unit in check
- *(F15)* Clean up the private dbus-daemon from inside try_own
- *(F17)* Make the end-to-end suite pass under a live systemd
- Say why the spec or feature list counts as unapproved

### 📚 Documentation

- Add Milestone 0 spec
- *(F18)* Answer the open questions in docs/findings.md
- *(F18)* Narrow thread-measurement claims to what the test shows
- *(M01)* Record manual acceptance run (rFirma and Firefox pass, fingerprint unverified)

### 🚜 Refactor

- *(F12)* Lint the fuzz harness, guard the fuzzing feature, move harness into ffi
- *(F14)* Forbid unsafe code in crap, clarify crap recipe arguments

### 🧪 Testing

- *(F12)* Run the FFI layer under Miri and ASan, add PKCS#11 argument fuzz target
- *(F13)* Add mutation testing for the authorization path and key store
- *(F14)* Add coverage report and CRAP gate
- *(F14)* Fix flaky password-leak assertion in CLI test
- *(F17)* Add end-to-end suite (systemd container, polkit agent, pkcs11-tool and NSS); not run, see BLOCKED.md
- *(F18)* Measure helper threads, confirm polkit ProcessFD use, record decisions

### ⚙️ Miscellaneous Tasks

- Add README, EUPL-1.2 licence and gitignore
- *(F03)* Add CI workflow with actionlint and zizmor in just check
- *(F13)* Install cargo-mutants in CI
- Install actionlint and cargo-fuzz outside install-action
- Pass sysusers an absolute path so unit-verify works on systemd 255
- Disable commit and PR attribution for the loop's Claude sessions
- Enforce conventional commits
- Check full history when the push base is unknown
- Lint commits with commitlint and generate the changelog with git-cliff
- Run the slow checks in parallel jobs with caching and shard mutants
- *(M01)* Mark as passing (manual acceptance)

### ◀️ Revert

- Ci: run the slow checks in parallel jobs with caching and shard mutants

### 💼 Other

- Add build loop harness for Milestone 0
- Map host user to dev in rootless podman
- *(F02)* Add justfile, lefthook and taplo/typos config
- *(F04)* Add cargo-deny policy and cargo-machete to just check
- *(F07)* Drop unused signature dependency, refresh Cargo.lock
- *(F16)* Add .deb package with cargo-deb
- Pin development tools with mise and add `just setup`
