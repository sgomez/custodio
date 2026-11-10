## [0.7.0] - 2026-11-10

### 🚀 Features

- *(F150)* Add vm-host-check, vm tools in the dev container and the kvm finding
- *(F151)* Record the swtpm, tpm-crb and OVMF boot of the 26.04 minimal image
- *(F152)* Record how to make the virtual tpm lack rsa, with an swtpm 0.10 profile
- *(F153)* Record systemd 259 credential header and key ids
- *(F154)* Require libtss2-rc0t64 in the deb and systemd 257 everywhere
- *(F155)* Keep only the user-scoped varlink route in the credential client
- *(F156)* Drop the ubuntu2404 e2e target; install.md states the systemd 257 floor
- *(F157)* Add the harness's credential reader and its self-test
- *(F158)* Download and verify the ubuntu 26.04 minimal cloud image
- *(F159)* Add the vm launcher and its stub-based self-test
- *(F159)* Add the lacking mode, the modes self-test and the container swtpm 0.10.2
- *(F160)* Add the vm case list, the vm accounting and the vm-only judges
- *(F160)* Add the vm mode of the guest script
- *(F160)* Add the vm host driver and the e2e-vm recipes
- *(F160)* Tick the host, guest and vm-only steps; keep guest.sh greppable paths
- *(F160)* Ship the packages and the e2e tree on a read-only payload drive
- *(F160)* Fix the payload drive, the guest session and the judges from the real probe
- *(F161)* Drop TPM2_Sign from the lacking profile and probe it in a real guest
- *(F161)* Judge the tpm kinds per vm mode and read the stored credential
- *(F161)* Judge the tpmbound fallback cases in both vm modes
- *(F161)* Add the vm-silent cases with the library hidden and restored
- *(F161)* Fix the hiding and the has-tpm2 reading from the real lacking guest
- *(F162)* Make sign and noplain runners aware of the VM modes with the reader in lacking
- *(F162)* Record the real-guest runs and tick the contract
- *(F163)* Make the pcr cases VM-aware with a two-half run around the power cycle
- *(F163)* Split the vm run around the power cycle for the pcr cases
- *(F163)* Make the tpm-clear cases VM-aware with the guest's own tpm
- *(F163)* Make the upgrade-kinds cases VM-aware and check the real payload
- *(F163)* Make the upgrade-kinds cases VM-aware and check the real payload
- *(F164)* Add the vm e2e workflow for the release pull request and its test
- *(F165)* Add the pcr mask steps for debian 13 and their test

### 🐛 Bug Fixes

- *(F121)* Purge the top-level key files of the M0–M2 layout
- *(F81)* Take the cgroup prefix up to the last system.slice
- *(F150)* Verify kvm on the linux host and keep the image cache
- *(F152)* Remove p-256 by dropping tpm2_sign, correct the api.md reading and the leftovers
- *(F158)* Run the self-test controls at once and record the missing gpg-agent
- *(F160)* Fix the test-tool guard and a self-test race; block on the serial copy rate
- *(F160)* Make the good-run payload check fail the self-test
- *(F161)* Run the real scripts in the self-tests and fail when the keys were never imported
- *(F162)* Check the sign job list against a fixed table with salt and mechanism controls
- *(F163)* Take the expected state owner from the state directory in a vm upgrade
- *(F163)* Import the setup keys again after the vm tpm clear
- *(F163)* Cover the setup key restore with fixtures, pin the vm state owner and drop debug output
- *(F168)* Keep the package-tool word out of the guest.sh comment
- *(harness)* Give the dev container's cgroup back to dev for nested systemd
- *(harness)* Point just status and milestone close to close, then release
- *(F168)* Read the vm gap table from e2e/vm/gaps.md, not the contract

### 📚 Documentation

- Mark M4 as done in the milestones
- Accept the M4 spec deviations and plan M4.1
- Close milestone M4
- Number the encrypted fallback milestone M5 and the public release M6
- Plan M5 on one ubuntu 26.04 minimal vm and move pending items to unassigned
- Open milestone M5
- Update IDEA.md
- Add spec drafted by the planner
- Trim the M5 spec and set systemd 257 as the floor
- *(F150)* Add contract
- *(F150)* Revise contract
- *(F150)* Mark the first evidence block as the pre-rebuild container
- *(F151)* Add contract
- *(F152)* Add contract
- *(F153)* Add contract
- *(F154)* Add contract
- *(F154)* Revise contract
- *(F155)* Add contract
- *(F155)* Tick the contract and record progress
- *(F156)* Add contract
- *(F157)* Add contract
- *(F157)* Revise contract after evaluator
- *(F158)* Add contract
- *(F158)* Amend contract to build test keys without gpg-agent
- *(F159)* Add contract
- *(F159)* Amend contract to follow the evaluator's notes
- *(F159)* Unblock after rebuilding the dev container with swtpm 0.10.2
- *(F159)* Record the evidence rerun after the container rebuild
- *(F160)* Add contract
- *(F160)* Revise contract after evaluator review
- *(F160)* Amend contract to condense the cost paragraph under the token limit
- *(F160)* Amend contracts for a read-only payload drive instead of the serial copy
- Answer the blocked question
- *(F161)* Add contract
- *(F161)* Take the evaluator's notes
- *(F161)* Revise contract for p-256 encrypted-tpm in lacking
- *(F162)* Add contract
- *(F163)* Add contract
- *(F163)* Record the real-guest probe and settle the clear route and PCR equality
- *(F163)* Add the progress entry for the probe
- *(F163)* Amend contract to settle the mapping rows and the equality control
- *(F163)* Record the file split and the open quick run
- *(F163)* Amend contract to record dpkg upgrade, payload test location and costs
- *(F163)* Amend contract to install n+1 with apt in the vm and fix the upgrade install
- *(F163)* Record the final recheck of the verify scripts
- *(F164)* Add contract
- *(F165)* Add contract
- *(F165)* Revise contract after review
- *(F165)* Fold in evaluator notes
- *(F166)* Record the manual acceptance run
- *(F167)* Add contract
- *(F167)* Revise contract
- *(F167)* Amend contract to name the real tests
- *(F167)* State the Debian 13 PCR 7 reading in api, install and F110
- *(F168)* Add contract
- *(F168)* Tick the baseline and checker steps
- *(F168)* Record the baseline, vm runs and the container blocker
- *(F168)* Record coverage, tick the passing steps
- *(F168)* Record the passing container e2e run and tick the step
- Answer the blocked question
- *(F168)* Tick the final step and record the recount
- *(F168)* Ask for the alma10 e2e budget, the dnf metadata download varies
- Answer the blocked question
- *(F168)* Record the alma10 and fedora44 times after the dnf cache
- *(F169)* Record the manual acceptance run
- Close milestone M5

### 🧪 Testing

- *(F121)* Take a foreign uid from the store, not a fixed 1001
- *(F115)* Put the creds socket where other namespace uids can reach it
- *(F156)* Add a ghost-target control to the e2e workflow test
- *(F160)* Add the vm host self-test with a stub vm, the guest and the vm-only sections
- *(F163)* Print the token mechanisms when the rsa signature after the upgrade fails
- *(F163)* Print the d-bus error and the journal when the rsa signature after the upgrade fails
- *(F168)* Add the gap table checker and its self-test

### ⚙️ Miscellaneous Tasks

- Build packages on ubuntu 26.04 and install nextest for the mutants diff
- Run e2e on 24.04 with tpm2-tss 4.1.3 and allow user namespaces for the creds tests
- Skip the mutants diff on prs labelled skip-mutants and on pr merges
- Sign off gates locally and release milestones through their pr
- Move e2e and the mutants diff to their own workflows
- Skip what check-slow covers on a signed-off milestone pr
- Name signoffs after the checks they replace and run every gate on prs
- Run at most 8 mutants shards at once, print every outcome, drop the tag trigger
- Add feature list drafted by the initializer
- *(budgets)* Drop the ubuntu2404 row and add the vm full and lacking budgets

### 💼 Other

- *(F159)* Unpack swtpm 0.10.2 under /opt/swtpm and report an swtpm without --profile
- *(F168)* Cache dnf metadata in the alma10 and fedora44 images
## [0.6.0] - 2026-11-07

### 🚀 Features

- *(F104)* Add with-swtpm recipe and tpm packages in container and ci
- *(F105)* Add tss-esapi and an swtpm fixture for rust tests
- *(F106)* Add tpm-probe parent and the parent key finding
- *(F107)* Add tpm-probe mechanisms, a lacking-tpm filter and the parity finding
- *(F115)* Add encrypted key storage with systemd-creds
- *(F112)* Add tpm access point and capability query in custodiod
- *(F113)* Import a key into the tpm with TPM2_Import under the srk parent
- *(F114)* Sign inside the tpm with every mechanism
- *(F116)* Add the new state format with the storage kind
- *(F117)* Choose the storage kind at import and fail closed
- *(F118)* Sign by stored kind with key-lost and unavailable errors
- *(F119)* Report the storage kind in import and list, document it in the api
- *(F120)* Name the storage kind and the cause of a failure in the journal
- *(F121)* Purge pre-m4 keys before answering any call
- *(F122)* Add fuzz targets for tpm blob, credential header, record and sign input
- *(F123)* Show the storage kind in custodio import and list
- *(F124)* Give the unit the tpm resource manager node and the tss group
- *(F125)* Declare the tpm2 software stack in the packages
- *(F126)* Run the lifecycle suites under each storage kind
- *(F127)* Add the no-plaintext check script and its integration target
- *(F128)* Check stored tpm keys cannot be duplicated or loaded elsewhere
- *(F129)* Check pcr extension, restarts and tpm clear for stored keys
- *(F130)* Test more signatures and imports than tpm object slots
- *(F131)* Add e2e tpm modes swtpm and none with a unit check on debian13
- *(F131)* Add the lacking tpm mode, the filter example and the e2e ci jobs
- *(F131)* Run the tpm modes on every target and record the findings
- *(F133)* Add tpm-kind e2e cases for import, list and journal
- *(F134)* Add sign e2e cases for every mechanism under each kind
- *(F134)* Run sign cases in all three tpm modes
- *(F135)* Run no-plaintext cases in all three tpm modes
- *(F136)* Add tpm-dup end-to-end cases for stored TPM keys
- *(F137)* Add pcr end-to-end cases for keys surviving a PCR change and restarts
- *(F138)* Add fallback end-to-end cases for the host-bound kind and the CLI text
- *(F139)* Add end-to-end cases for injected tpm and credential failures
- *(F140)* Add end-to-end cases for signing after the tpm is cleared
- *(F141)* Add end-to-end cases for kinds kept across an upgrade
- *(F142)* Add end-to-end cases for the upgrade from an M3 build
- *(F143)* Add tpm-slots cases for more calls than TPM object slots
- *(F144)* Add journal-kind cases for the kind, purge and load-failure queries
- *(F145)* Add M4 manual acceptance steps and their test
- *(F146)* Make custodio list say a host or tpm-bound key is weaker

### 🐛 Bug Fixes

- *(F104)* Stop swtpm over its control socket
- *(F104)* Pass stdin to the command and bound the swtpm stop wait
- *(F107)* Keep probing when the tpm refuses pss or sign|decrypt, split the probe
- *(harness)* Fail hung tests and kill what a session leaves running
- *(F112)* Stop swtpm inheriting tcti sockets from sibling tests
- *(F113)* Search the seed on the wire and zero key copies
- *(F113)* Write the sensitive area into zeroizing buffers only
- *(F113)* Zeroize the ecdh point, aes key schedule and sha-256 states
- *(F114)* Drop an unused mut and split the sign unit tests
- *(F114)* Justify the allow in the second sign unit test file
- *(test)* Stop a killed test binary's swtpm through a guardian shell
- *(quick)* Check new files too in check-files
- *(test)* Start test children with no inherited descriptors
- *(F117)* Move choice unit tests to their own file
- *(F117)* Justify the allows in the storage_choice test target
- *(F117)* Drop the import password right after decoding
- *(F118)* Document key lost as sign only
- *(F120)* Plant response codes, credential bytes and decoder text in the no-secret rows
- *(F132)* Skip the getrandom pair, judge the new journal fields and sync the catalog text
- *(F132)* Check the one-record-per-key store in the upgrade accounts check
- *(F132)* Except the tpm2-tss information lines in the namcap list
- *(harness)* List the features in status when stopped by agent_stop
- *(harness)* List the features in status even before they are approved
- *(F133)* Run the tpm-kind mutants in parallel and drop script-text checks
- *(F141)* Stop the run when the kinds judgement crashes and make the host test executable
- *(F142)* Require polkit approval for the re-import in the judgement
- *(F145)* Make the wrong-option case path-independent and run the controls in parallel
- *(F146)* Bring the stale e2e host tests up to date with M4
- *(F146)* Run the M4 guest steps only on the target whose own list owes their cases
- *(F146)* Refuse a parallel e2e run when the host's inotify instance limit is too low
- *(harness)* Commit new docs files in milestone pass

### 📚 Documentation

- Accept the F89 spec deviation
- Close milestone M3
- Mark M2 and M3 as done
- Update README.md
- Open milestone M4
- Write milestone M4 idea
- Add spec drafted by the planner
- *(F104)* Add contract
- Answer the blocked question
- *(F105)* Add contract
- *(F106)* Add contract
- *(F106)* Apply evaluator notes to contract
- *(F107)* Add contract
- *(F107)* Apply evaluator notes to contract
- *(F108)* Add contract
- *(F108)* Add the finding on how swtpm reaches the e2e containers
- *(F109)* Add contract
- *(F109)* Amend contract after evaluator review
- *(F109)* Revise contract after evaluator review
- *(F109)* Add the finding on how the service reaches the tpm under its unit
- *(F110)* Add contract
- *(F110)* Add the finding on how the service uses systemd-creds without root
- *(F115)* Add contract
- *(F115)* Revise contract after evaluator review
- *(F111)* Record the manual acceptance run
- *(F111)* Note the decrypt threat-model point for F119
- *(F112)* Add contract
- *(F112)* Revise contract after evaluator review
- *(F113)* Add contract
- *(F113)* Revise contract after evaluator review
- *(F114)* Add contract
- *(F114)* Amend contract to clean up after a faulted flush with flushcontext -t
- *(F114)* Record attempt 3
- *(F116)* Add contract
- *(F116)* Revise contract after evaluator review
- *(F117)* Add contract
- *(F117)* Amend contract to drop control (c)
- Split findings per feature and prune obsolete ones
- *(F118)* Require no inherited descriptors for systemd-creds
- *(F117)* Record attempt 4 hand-off
- *(F118)* Add contract
- *(F118)* Settle lacks class and add launcher evidence
- *(F118)* Amend contract to fold duplicate rows and name the launcher evidence
- *(F119)* Add contract
- *(F120)* Add contract
- *(F121)* Add contract
- *(F122)* Add contract
- *(F123)* Add contract
- *(F123)* Address evaluator notes in contract
- *(F124)* Add contract
- *(F124)* Address evaluator notes in contract
- *(F124)* Tick contract steps
- *(F125)* Add contract
- *(F125)* Address evaluator notes in contract
- *(F126)* Add contract
- *(F126)* Address evaluator notes in contract
- *(F127)* Add contract
- *(F127)* Address evaluator notes in contract
- *(F128)* Add contract
- *(F128)* Address evaluator notes in contract
- *(F129)* Add contract
- *(F130)* Add contract
- *(F130)* Separate flushable faults from drops in contract
- *(F130)* Add builder notes to contract
- *(F131)* Add contract
- *(F131)* Amend contract to split the target work into debian13 and the others
- *(F132)* Add contract
- *(F132)* Fix contract accounting per review
- *(F132)* Amend contract to run e2e one target and mode per command
- *(F132)* Record none-mode e2e passes on fedora44, ubuntu2404 and ubuntu2604
- *(F132)* Record the final e2e rerun so far
- *(F132)* Record debian13 none in the final rerun
- *(F132)* Record fedora44 and ubuntu2404 in the final rerun
- *(F132)* Tick the checkpoint steps and record the final rerun
- *(spec)* Run each e2e case only where its outcome can differ
- *(F133)* Add contract
- *(F133)* Require a failure on a skip under swtpm
- *(F134)* Add contract
- *(F134)* Amend contract after review
- *(F134)* Align steps with scope after approval
- *(F134)* Amend contract to the kinds and tools a run showed
- *(F134)* Amend contract to withdraw the tpm expectation under lacking
- *(F134)* Block on encrypted-tpm under lacking in the container
- *(F134)* Amend contract to a deviation for encrypted-tpm in containers
- *(F134)* Amend contract to state what covers encrypted-tpm signing
- *(F134)* Record attempt 5 in progress
- *(F135)* Add contract
- *(F135)* Amend contract to extend the encrypted-tpm deviation
- *(F136)* Add contract
- *(F137)* Add contract
- *(F137)* Amend contract to extend the F134 deviation to the pcr cases
- *(F138)* Add contract
- *(F138)* Name the replacement coverage in the F134 deviation
- *(F139)* Add contract
- *(F140)* Add contract
- *(F140)* Amend contract to extend the F134 deviation and reword the negative control
- *(F141)* Add contract
- *(F141)* Amend contract to name the encrypted-tpm cover and extend the F134 deviation
- *(F142)* Add contract
- *(F142)* Record the real runs and tick the last steps
- *(F143)* Add contract
- *(F143)* Fix where the host test runs
- *(F143)* Apply evaluator notes to the contract
- *(F144)* Add contract
- *(F144)* Amend contract to run every case in every mode
- *(F145)* Add contract
- *(F145)* Revise contract
- *(F146)* Add contract
- *(F146)* Revise contract
- *(F146)* Record the baseline
- *(F146)* Record the e2e runs so far
- *(F146)* Record the e2e and package-gate runs and the debian13 budget question
- Answer the blocked question
- *(F146)* Record the final quick run
- *(F146)* Record the load-dependent e2e failures
- *(F146)* Record the inotify cause of the parallel e2e failures
- *(F146)* Record the passing parallel e2e run with the raised inotify limit
- *(F146)* Record that the findings predate the inotify fix
- *(F146)* Record that the upgrade script budget was raised by a person
- *(F146)* Ask a person for the budgets the parallel run exceeded
- *(F146)* Record the budget overages and the request
- *(F146)* Record that the findings predate the raised budgets
- *(F147)* Record the manual acceptance run
- *(F148)* Add progress entry
- *(F148)* Record the manual acceptance run
- *(F149)* Add progress entry
- *(F149)* Record the manual acceptance run

### ⚡ Performance

- *(mutants)* Stop each mutant's tests at the first failure and build without debuginfo
- *(e2e)* Run the target-mode pairs at once
- *(e2e)* Run the no-tpm mode and the old-path upgrade once, time each step
- *(F135)* Run the independent no-plaintext checks at once
- *(F146)* Run the shellcheck pair and the arch mutants at once

### 🧪 Testing

- Drop tests that only pin document wording
- *(F146)* Print the bus journal when a package hook job fails in the lifecycle run
- *(F146)* Answer a lost repeat prompt again in the pty helper and print the transcript on failure
- *(F110)* Keep the creds tests hermetic on a host with a TPM
- *(F149)* Kill the size-limit and ec-oid mutants in the p12 import

### ⚙️ Miscellaneous Tasks

- Add feature list drafted by the initializer
- *(harness)* Run mutants-diff in parallel and void runs that ran out of disk
- *(harness)* Tell builders the session limit and to commit before long runs
- *(harness)* Make contracts split suites that do not fit a session
- *(harness)* Check time budgets after each verify
- *(harness)* Ask contracts and reviews for the time cost of tests
- *(F146)* Raise the e2e debian13 budget to 700 s as a person decided
- *(F146)* Raise the noisy script budgets as a person decided
- *(F146)* Raise the e2e and default script budgets as a person decided

### 💼 Other

- Cap agent-read docs in check-files
- Forbid tests that grep the wording of documents
- *(harness)* Run the release's check-slow in the dev container
- *(harness)* Add a build timeout and MUTANTS_ITERATE to just mutants
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
