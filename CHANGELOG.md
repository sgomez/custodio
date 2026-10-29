## [0.3.0] - 2026-10-29

### 🚀 Features

- *(F19)* Add composed-mechanism hashing, digestinfo and mapping
- *(F20)* Add composed mechanisms to listing, sign init and single-part sign
- *(F21)* Add multi-part sign update and final for composed mechanisms
- Let an agent apply the answer to BLOCKED.md
- *(F22)* Add C_Login and C_Logout as no-ops
- *(harness)* Add fix action for an interactive session on a stopped feature
- *(harness)* Point status to fix when the evaluator sent a contract back
- *(F24)* Add audit sink interface and native journal writer
- *(F25)* Record one audit entry per sign call, failing closed
- *(F26)* Document the audit interface and ship the journal catalog entry
- *(F27)* Mutate the pkcs11 module mechanism code and cover fuzz tests in coverage
- *(F28)* Add composed, multi-part and login cases to the e2e suite
- *(F29)* Check the service journal for audit entries and leaked secrets in e2e

### 🐛 Bug Fixes

- Satisfy shellcheck 0.10 in the unblock script
- *(F21)* Return operation-not-initialized for raw multi-part calls
- *(harness)* Skip claude onboarding and trust prompts in the fix session
- *(F24)* Give the struct-literal compile_fail doctest all fields
- *(F25)* Bound the child client, verify the signature and scan a sentinel password
- *(F26)* Drop the language tag from the catalog header and list mechanisms once
- *(F26)* Restore the contract text and ship the catalog with an en and a default entry
- *(F28)* Ask polkit once in composed deny cases and check login order everywhere

### 📚 Documentation

- Open milestone M1
- *(F19)* Add contract
- *(F19)* Revise contract after review
- *(F19)* Wrap long contract lines
- *(F19)* Point truncation test at tests/sign.rs
- *(F19)* Revise contract after second review
- *(F20)* Add contract
- *(F20)* Revise contract after review
- *(F20)* Assert no signature bytes on denied call
- *(F21)* Add contract
- *(F21)* Revise contract after review
- *(F21)* Settle busy rule and return codes in contract
- *(F21)* Tighten contract after approval notes
- *(F21)* Add fd, thread-stop and denied-retry evidence to contract
- *(F21)* Return operation-not-initialized for raw multi-part calls
- Answer the blocked question
- *(F21)* Record the multi-part conflict rule and finish the contract
- *(F22)* Add contract
- *(F22)* Revise contract after review
- *(F22)* Fix harness and fuzz evidence in contract
- *(F22)* Revise contract after second review
- *(F22)* Address evaluator notes in contract
- *(F23)* Add contract
- *(F23)* Revise contract after evaluator review
- *(F23)* Revise contract after second evaluator review
- *(F23)* Remove duplicate sentence and fix permutation examples in the contract
- *(F23)* Revise contract after third evaluator review
- *(F23)* Revise contract after fourth evaluator review
- *(F24)* Add contract
- *(F24)* Revise contract after first evaluator review
- *(F24)* Revise contract after second evaluator review
- *(F25)* Add contract
- *(F25)* Revise contract after review
- *(F25)* Note an intermittent hang in leaks::child_client
- *(F26)* Add contract
- *(F26)* Revise contract after review
- *(F26)* Fix wording in contract
- *(F26)* Tick contract steps and record verification
- *(F27)* Add contract
- *(F27)* Revise contract after review
- *(F27)* Record shard timings and the planted-survivor check
- *(F27)* Record why miri runs only the ffi tests and fix its comment
- *(F27)* Hand off attempt 3
- *(F28)* Add contract
- *(F28)* Address evaluator findings in contract
- *(F28)* Revise contract after evaluator review
- *(F28)* Revise contract for login spy and size query
- *(F28)* Tolerate the signature size query in the provider evidence
- *(F28)* Relax context login order and add pkcs11-tool research step
- *(F28)* Add research evidence and small-file rule for login cases
- *(F29)* Add contract
- *(F29)* Revise contract after review
- *(F29)* Address evaluator review of contract
- *(F30)* Add contract
- *(F30)* Revise contract after review
- *(F30)* Answer the M1 questions on SO login, caller detail and refused calls
- *(F32)* Add contract
- *(F32)* Revise contract after review
- *(F32)* Add manual acceptance steps for acceptance 11 to 13
- *(F33)* Record the manual rfirma run for acceptance 11
- *(F34)* Record the manual acceptance run
- *(F35)* Record the manual acceptance run

### 🚜 Refactor

- Keep only the unblocker's own rules in its prompt

### 🧪 Testing

- *(F21)* Tighten multi-part evidence after review
- *(F22)* Prove a login with a pin leaves the session unchanged
- *(F23)* Cover composed, multi-part and login entry points under miri, asan and fuzzing
- *(F24)* Kill surviving mutants in size limit, display and getter
- *(F25)* Fill the journal socket queue whatever max_dgram_qlen the host has

### ⚙️ Miscellaneous Tasks

- Update docs
- Update docs
- Add feature list drafted by the initializer

### 💼 Other

- *(harness)* Tell the builder to re-run only the mutants it is fixing
- *(harness)* Let the evaluator reuse the loop's verify run instead of repeating it
- Run miri only on the ffi tests, where the unsafe code is
- *(harness)* Run just check-slow before every release
- *(harness)* Pass the evaluator its verify log and keep check-slow out of verify
- *(harness)* Bake the pinned stable and nightly toolchains into the image
- *(harness)* Add just log to follow the running agent session
- *(harness)* Let milestone pass commit pending docs changes
## [0.2.0] - 2026-10-27

### 🚀 Features

- Group the harness commands under `just milestone` and `just harness`
- Archive PROGRESS.md with its milestone

### 🐛 Bug Fixes

- Count a milestone as released when a tag contains its last feature
- Create target/ before cargo-mutants writes its output there
- Run the systemd and bus gates through one recipe in the lint job
- *(crap)* Count guards through syn 3 guard patterns
- Key the ci caches on the lockfiles and the toolchain again

### 📚 Documentation

- Close milestone M0
- Archive the M0 progress log
- Scope decisions.md to decisions and trim it

### 🚜 Refactor

- Move inline tests to their own files and split oversized modules

### ⚙️ Miscellaneous Tasks

- Update skills
- Update docs
- Split the slow checks into parallel jobs by build family
- Run only the fast jobs on a pr; coverage and nightly on main, full mutants on release tags
- Split check into lint and test jobs and build without debuginfo
- Add a security policy and weekly dependabot updates
- Cancel the older run on main as well
- Pin the nightly toolchain and key the caches on our own toolchains
- Pin ci tools to mise.toml, drop the pre-push hook and tighten the fuzzing guard

### 💼 Other

- *(deps-dev)* Bump the npm group with 2 updates
- *(deps)* Bump syn
- Fail lint on files over 5,000 tokens or with inline test modules
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
- Simplify the harness README

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
