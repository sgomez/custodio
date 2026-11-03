## [0.5.0] - 2026-11-03

### 🚀 Features

- *(F63)* Run a chosen subset of end-to-end cases on one target
- *(F64)* Add client crate and the deps-check
- *(F65)* Give each failure its own d-bus error name
- *(F66)* Add client api document and the api contract check
- *(F69)* Add polkit actions for import, delete and replace certificate
- *(F70)* Store keys per owner uid
- *(F70)* Tick contract steps and record mutants result
- *(F71)* Remove the upgrade from the cargo-deb package of m1
- *(F72)* Scope list, sign and import to the caller's uid
- *(F73)* Ask polkit before decrypting the .p12 on import
- *(F74)* Name the operation in every journal entry
- *(F75)* Leave one journal entry per import and fail closed
- *(F76)* Delete a key with its certificate after polkit approves
- *(F77)* Leave one journal entry per delete and fail closed
- *(F78)* Replace the certificate of a key after polkit approves
- *(F79)* Leave one journal entry per replace and fail closed
- *(F80)* Parse and validate the flatpak app-id from a scope name
- *(F81)* Read the app-id of the pinned process within bounds
- *(F82)* Name the flatpak app-id in journal entries
- *(F83)* Add fuzz targets for delete, replace certificate and app id, and fuzz-smoke
- *(F85)* Test the module on the documented api with two uids, replace and delete
- *(F86)* Show each import error name as its own message with typed failures and exit status
- *(F87)* Add custodio list with id, key type, subject and end of validity
- *(F88)* Add custodio delete with a terminal confirmation
- *(F89)* Start pkttyagent for the cli process around the polkit call
- *(F90)* Declare util-linux for setpriv in the rpm and arch packages
- *(F91)* Add owner-* e2e cases with two real accounts
- *(F92)* Add ops-polkit e2e cases for import, delete and replace certificate
- *(F93)* Add replace-* and delete-* e2e cases for certificate replacement and key deletion
- *(F94)* Add journal-ops e2e cases for sign, import, delete and replace entries
- *(F95)* Add appid-* e2e cases with fake flatpak callers and hostile scopes
- *(F96)* Check keys, owners and certificates of two accounts across the upgrade
- *(F97)* Add cli-* e2e cases for list, delete and pkttyagent on a terminal
- *(F98)* Add complete client documentation with busctl examples run by a test
- *(F99)* Add m3 manual acceptance steps, test flatpak manifest and their test

### 🐛 Bug Fixes

- Plan the markdown-only case on a file that still exists
- *(F63)* Check the ubuntu 24.04 precondition against its e2e target
- *(F70)* Test the key file owner check and import via dbus in leak test
- *(harness)* Read the evaluator verdict when it is not on the first line
- *(F78)* Split the replace integration tests under the file-size gate
- *(F78)* Check the other uid's area after a replace and loop polkit answers
- *(F79)* Split the replace audit tests under the file-size gate
- *(F81)* Find the cgroup tree below the container prefix
- *(F81)* Take the stuck-thread slot before spawning the worker
- *(harness)* Include untracked files in the mutants-diff diff
- *(F82)* Cover the catalog copy, the negative control and secrecy with an id
- *(F82)* Cover the pending-delete refusal and all operations on the wire
- *(F85)* Verify a signature after the replace and drop a stale doc comment
- *(F85)* Compare only the scenario lines in the two-uids signing check
- *(F88)* Split the delete integration tests into modules
- *(F88)* Accept '--' before an id and check the store files in delete tests
- *(F89)* Prove the agent is reaped with a subreaper and tidy the stdin cases
- *(F90)* Resolve the sleep binary before reading it in the upgrade script test
- *(F98)* Check each documented error message against its own variant
- *(F100)* Compare files by checksum in guest scripts, diffutils is not on every image
- *(F99)* Use gdbus in the test flatpak, its runtime has no busctl

### 📚 Documentation

- Rescope m3 to the client api and settle the tpm pin and pcr questions
- *(F44)* Accept the rpm-ostree removal deviation
- Close milestone M2
- Open milestone M3
- Add spec drafted by the planner
- *(F63)* Add contract
- *(F63)* Amend contract after review
- *(F63)* Amend contract after second review
- Answer the blocked question
- *(F63)* Record the passing verify run
- *(F64)* Add contract
- *(F64)* Revise contract after evaluator notes
- *(F65)* Add contract
- *(F65)* Revise contract
- *(F66)* Add contract
- *(F67)* Add contract
- *(F67)* Address evaluator findings in contract
- *(F67)* Research how custodiod can read the caller's app-id
- *(F67)* Note the pid difference and the unread proxy source
- *(F68)* Add contract
- *(F68)* Address evaluator findings in contract
- *(F68)* Research service detection through xdg-dbus-proxy
- *(F68)* Fix spawn conflict claim and inline the setup script
- *(F69)* Add contract
- *(F69)* Address evaluator notes in contract
- *(F70)* Add contract
- *(F70)* Address evaluator notes in contract
- *(F70)* Require dbus owner tests in contract
- *(F70)* Add progress entry
- *(F71)* Add contract
- *(F71)* Revise contract after review
- *(F71)* Revise contract after second review
- *(F71)* Add control id to step 3 and harness readme to docs grep
- *(F71)* Amend contract to refuse a refusal-only id on ubuntu2604
- *(F71)* Amend contract to anchor the pkg-old grep
- *(F71)* Amend contract to anchor the packages_old grep
- *(F72)* Add contract
- *(F73)* Add contract
- *(F73)* Revise contract for the agent session of the imports
- *(F74)* Add contract
- *(F74)* Amend contract to add evidence commands and the catalog field decision
- *(F75)* Add contract
- *(F75)* Amend contract after evaluator review
- *(F76)* Add contract
- *(F77)* Add contract
- *(F77)* Revise contract after evaluator review
- *(F77)* Correct leftover certificate wording after failed removal
- *(F78)* Add contract
- *(F79)* Add contract
- *(F80)* Add contract
- *(F81)* Add contract
- *(F81)* Address contract review notes
- *(F82)* Add contract
- *(F83)* Add contract
- *(F83)* Amend contract after review
- *(F85)* Add contract
- *(F86)* Add contract
- *(F87)* Add contract
- *(F87)* Revise contract after review
- *(F88)* Add contract
- *(F88)* Revise contract after review
- *(F89)* Add contract
- *(F89)* Revise contract after review
- *(F89)* Revise contract after second review
- *(F89)* Settle kill mechanism and evidence after review
- *(F89)* Amend contract to --fallback and setpriv after research
- *(F90)* Add contract
- *(F90)* Amend contract after review
- *(F91)* Add contract
- *(F91)* Amend contract after review
- *(F91)* Amend contract to call the service with python3 gio instead of busctl
- *(F92)* Add contract
- *(F92)* Amend contract after review
- *(F93)* Add contract
- *(F94)* Add contract
- *(F94)* Revise contract
- *(F95)* Add contract
- *(F95)* Revise contract
- *(F95)* Amend contract to a 256-byte caller and the session facts of the guest
- *(F96)* Add contract
- *(F96)* Revise contract
- *(F96)* State the cross-account signature check in the evidence
- *(F97)* Add contract
- *(F97)* Amend contract to the Containerfile path and the evaluator's notes
- *(F98)* Add contract
- *(F98)* Amend contract to the runner's error check and the evaluator's notes
- *(F99)* Add contract
- *(F99)* Revise contract after evaluator review
- *(F100)* Add contract
- *(F100)* Fix skip list path in contract
- *(F100)* Tick contract steps and record checkpoint results
- *(F101)* Record the ubuntu2604 client api manual acceptance run
- *(F101)* Record the repeat of acceptance 14 by a person
- *(F102)* Record the fedora44 test flatpak manual acceptance run (fail)
- *(F102)* Record the passing repeat of acceptance 15 with gdbus on fedora44
- *(F102)* Record the repeat of acceptance 15 by a person
- *(F103)* Record the fedora44 manual acceptance 16 run (pass)
- *(F103)* Record the repeat of acceptance 16 by a person

### ⚡ Performance

- Leave progress.md out of the just check stamp

### 🚜 Refactor

- *(F95)* Split the appid judgements into modules under the file size gate
- *(F103)* Move the bus registration out of run into a tested serve

### 🧪 Testing

- Plan the markdown-only case on a temporary file
- *(F70)* Cover io errors on a broken root
- *(F74)* Kill the missed OperationEntry::caller mutant
- *(F74)* Check the sign operation on the journal datagram
- *(F100)* Expect the docs and source mounts in the host selection test
- *(F100)* Make the state-only mutant deterministic, drain stdin instead of a SIGPIPE race
- *(F20)* Report a worker panic at once in the state lock test
- *(F103)* Stop grep -q from failing the manual page checks under load
- *(F103)* Cover wait_for_close and the import error messages

### ⚙️ Miscellaneous Tasks

- Run the jobs on ubuntu 26.04 for a bus with processfd
- Tell a failing mutants baseline apart from missed mutants
- Update idea
- Update spec
- Add feature list drafted by the initializer
- Run slow gates only where a feature reaches them, full suites at checkpoints
- Drop feature list to regenerate it
- Add feature list drafted by the initializer
- *(F103)* Ignore the profraw files coverage leaves in the crates

### 💼 Other

- Verify only the custodio unit, not the host's units
- Pin shellcheck 0.11.0 in the dev container
- Gate each feature on the changed checks, not the full just check
- *(harness)* Run light tests per feature and the full suites at checkpoints
- *(harness)* Allow short sleeps and bounded wait loops in the no-background hook
## [0.4.0] - 2026-11-01

### 🚀 Features

- *(F36)* Add nfpm file list, lifecycle scripts and their fixture test
- *(F36)* Add package gate for file list, modes, owners and unit path
- *(F36)* Add package gate for dependencies, sonames, scripts and versions
- *(F36)* Add package recipe with version override and gate
- *(F36)* Remove cargo-deb and lint maintainer scripts by shebang
- *(harness)* Report loop status to herdr-core via osc 7501
- *(F37)* Add package parity and glibc ceiling gates
- *(F38)* Add package linters with justified exception lists
- *(F38)* List the decided findings on the daemon path as literal pairs
- *(F39)* Refuse sign calls whose bus credentials lack a matching ProcessFD
- *(F40)* Prove pidfd mismatch is refused like missing processfd and pin unit hardening
- *(F42)* Check at install time that the system bus provides processfd
- *(F43)* Add lifecycle scripts of the deb for install, upgrade, remove, purge
- *(F44)* Add lifecycle scriptlets of the rpm for install, upgrade, erase
- *(F58)* Add lifecycle scripts and restart hook of the arch package
- *(F45)* Add per-target e2e harness with debian13 and skip lists
- *(F59)* Add ubuntu 26.04 e2e target and the journal catalog check
- *(F46)* Add fedora 44 and alma 10 e2e targets
- *(F47)* Add arch e2e target and correct its bus daemon in the findings
- *(F48)* Add the upgrade case to the e2e suite on every target
- *(F60)* Add the upgrade from the last cargo-deb .deb to the e2e suite on debian13
- *(F49)* Add removal, purge and reinstall cases to the e2e suite on every target
- *(F50)* Add the end-to-end refusal on ubuntu 24.04 with dbus-daemon
- *(F51)* Add administrator guide for installing and removing
- *(F52)* Add manual acceptance steps for the M2 machines
- *(F61)* Put the service binary where each distribution wants it

### 🐛 Bug Fixes

- Skip binaries and features.json in the file size check
- *(F36)* Stop gate writing bytecode and run shell-scripts-test in ci
- *(F36)* Check and document the system packages the package tests need on the host
- *(harness)* Send a feature with no open steps to the gate instead of another builder session
- *(F38)* Address evaluator findings on postinst reload, host version and list tests
- *(harness)* Stop without a verdict when agent_stop cuts a session short
- *(F40)* Handle spaced settings in the hardening gate and fail on a failed pidfd clone
- *(F44)* Gate rpm user() and group() provides, drop stale blocked pointers
- *(F58)* Gate the decision table, check the unit stays disabled, trim the decision
- *(harness)* Leave test-changed-checks out of the plans it checks
- *(harness)* Shellcheck every script when one changes, as just lint does
- *(F45)* Read the user name from passwd and free each rpm lifecycle root
- *(F59)* Run the stub e2e test on every target and make the catalog control real
- *(F52)* Check every verify word in the manual acceptance test
- *(F52)* Make the manual acceptance test independent of grep -q sigpipe
- *(harness)* Show why the loop stopped in just status

### 📚 Documentation

- Close milestone M1
- Add the polkit custodian report and plan non-exportable keys
- Mark M1 done and add Arch packaging to M2
- Rescope M2 to building and testing packages
- Open milestone M2
- Set the supported distributions for M2
- Add spec drafted by the planner
- *(F36)* Add contract
- *(F36)* Revise contract after evaluator review
- *(F36)* Revise contract after second evaluator review
- *(F36)* Revise contract after third evaluator review
- *(F36)* Fix step order and references after fourth evaluator review
- *(F36)* Fix recipe wording and step references after fifth evaluator review
- *(F37)* Add contract
- *(F37)* Revise contract after evaluator review
- *(F37)* Address evaluator review of contract
- *(F37)* Revise contract after second evaluator review
- *(F38)* Add contract
- *(F38)* Revise contract after evaluator review
- *(F38)* Address evaluator review of contract
- *(F38)* Address second evaluator review of contract
- *(F38)* Research linter pins and block on missing container runtime
- *(F38)* Record sudo and nested rootless podman answer in findings
- Answer the blocked question
- *(F38)* Record raw linter findings, add linter images and block on the lintian path finding
- *(F38)* Allow one literal lintian exception for executable-in-usr-lib
- Answer the blocked question
- *(F38)* Amend contract to allow the fortify tag on the daemon path, rootless user and namcap -m
- *(F38)* Amend contract body for two path entries, podman user and namcap -m
- *(F38)* Block on findings that name the daemon path
- *(F38)* Amend contract to list the person-approved pairs on the daemon path
- *(F38)* Record the session that applied the person's answer
- Answer the blocked question
- *(F38)* Record the re-verification session
- *(F39)* Add contract
- *(F39)* Revise contract after evaluator findings
- *(F40)* Add contract
- *(F40)* Revise contract after evaluator findings
- *(F40)* Revise contract after second evaluator review
- *(F41)* Add contract
- *(F41)* Revise contract after evaluator review
- *(F41)* Revise contract after second evaluator review
- *(F41)* Require proof of the first good polkit release and scope the support grep
- *(F41)* Require step 1 to brief the later-tag reading and tie the minimum to the pinned tag
- *(F41)* Record that polkit 124 reads ProcessFD from the bus (outcome A)
- *(F41)* Amend contract to skip outcome B steps and exclude harness paths from the diff
- *(F41)* Record that outcome B steps are skipped
- *(F42)* Add contract
- *(F42)* Add real-tool install evidence to contract
- *(F42)* Block on pacman ignoring a failing pre_install
- *(F42)* Amend contract for Arch warn-on-install, abort-on-upgrade
- Answer the blocked question
- *(F42)* Let arch warn on first install and refuse upgrades and reinstalls
- *(F43)* Add contract
- *(F43)* Revise contract after review
- *(F43)* Fold in evaluator notes
- *(F43)* Pre-depend on systemd and cover remaining script paths
- *(F44)* Add contract
- *(F44)* Revise contract after review
- *(F44)* Amend contract to use plain Requires, nfpm has no Requires(pre)
- *(F44)* Accept that rpm-ostree uninstall cannot print the removal notice
- *(F44)* Record rpm-ostree removal notice as a spec deviation
- Answer the blocked question
- *(F44)* Record full verify run and tick last contract step
- *(F58)* Add contract
- *(F58)* Amend contract after evaluator review
- *(F58)* Fold in evaluator notes on the contract
- Add research on the fnmt configurador
- *(F45)* Add contract
- *(F45)* Require the real e2e run in the contract
- *(F45)* Amend contract to drop the package build from step 4
- *(F45)* Ask for a restart of the dev container
- *(F45)* Record the real e2e run and tick the last step
- Answer the blocked question
- *(harness)* Test only the diff between steps and probe the environment in contracts
- *(F59)* Add contract
- *(F59)* Amend contract after review
- *(F46)* Add contract
- *(F46)* Revise contract after review
- *(F47)* Add contract
- *(F47)* Revise contract after review
- *(F47)* Revise contract after second review
- *(F48)* Add contract
- *(F48)* Revise contract after review
- *(F60)* Add contract
- *(F60)* Fold evaluator notes into contract
- *(F60)* Address evaluator notes in contract
- *(F49)* Add contract
- *(F49)* Fold evaluator notes into contract
- *(F49)* Address evaluator notes in contract
- *(F50)* Add contract
- *(F51)* Add contract
- *(F51)* Address evaluator findings on contract
- *(F51)* Restore contract and apply evaluator findings
- *(F51)* Dedupe contract and address evaluator findings
- *(F52)* Add contract
- *(F52)* Put the ubuntu2404 install command in its own block
- *(F53)* Record the end-to-end matrix and gates run on a podman host
- *(F54)* Record the fedora44 selinux manual acceptance run
- Fix the ausearch window in the manual acceptance steps
- *(F55)* Record the bazzite layered rpm manual acceptance run
- *(F55)* Trace the init_t domain to the lib_t label of custodiod
- List firefox flatpak as an unassigned investigation
- *(F55)* Explain the uid 65534 owner of the state directory
- *(F61)* Add contract
- *(F61)* Revise contract after review
- *(F61)* Clarify before/after paths in the contract
- *(F61)* Add old-path e2e upgrade case to the contract
- *(F61)* Limit old-path upgrade case to targets that can run it
- Record acceptance 6 with libfprint's virtual fingerprint device
- *(F56)* Record the omarchy manual acceptance run
- *(F56)* Document registering the module in firefox without the p11-kit proxy
- *(F57)* Record the ubuntu2404 dbus-broker manual acceptance run
- *(F57)* Point to the polkit 124 ProcessFD reading of F41
- Settle the ubuntu 24.04 and polkit 124 open questions
- *(F62)* Record the fedora44 and bazzite selinux domain runs after the move

### ⚡ Performance

- Run the script tests of check in parallel, slowest first
- Skip just check and test-changed on a tree that already passed

### 🎨 Styling

- *(F61)* Disable sc2329 instead of sc2317 for indirectly called functions

### 🧪 Testing

- *(F38)* Assert 0:0 user only without a subuid range
- *(F38)* Make the per-linter list cases able to fail and cover namcap list sorting
- *(F39)* Make the other-process pidfd test fail when the pidfd cannot be opened
- Delete each case's root and drop directory sizes from the arch snapshot

### ⚙️ Miscellaneous Tasks

- *(harness)* Create the milestone branch on milestone open
- Update milestone definition
- Add feature list drafted by the initializer
- Split rpm/arch scripts, ubuntu e2e target and cargo-deb upgrade into own features
- Drop just test-scripts from the verify commands
- Update features

### 💼 Other

- Drop typos
- *(harness)* Let builders amend contracts with evaluator approval
- *(harness)* Add mutants-diff and use it for new verify gates
- *(harness)* Block contracts only on blocking points and re-review against the last review
- *(harness)* Let builders skip conditional steps and stop after two idle sessions
- *(harness)* Have the initializer split by area and settle open questions first
- *(harness)* Record proven-impossible spec requirements as deviations instead of blocking
- *(harness)* Keep a stopped builder's leftovers for the next session
- *(harness)* Ask contracts and evaluator for proportionate evidence
- *(harness)* Stream each claude session to the console
- Check only shellcheck and file size on commits of harness scripts
- *(harness)* Open a herdr terminal for each claude session
- Follow sourced files in the commit shellcheck of harness scripts
- *(F45)* Let the dev container run privileged systemd containers
- *(harness)* Group herdr terminals by feature and keep the main console short
- *(F45)* Replace --privileged with the three options nested systemd needs
- *(harness)* Run only the checks a change can break between steps and on commit
- Exclude the justfile from the file size limit
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
