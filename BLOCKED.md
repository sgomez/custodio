# F160 blocked: the serial channel is too slow to copy the packages (step 5)

Measured on a real `vm.sh start full` guest (Ubuntu 26.04 image 20261105, `chan.py put`, one run each):
- 300 KB: 20.7 s; 1.5 MB: 101 s. Rate is about 15 KB/s, linear.
- Package N is 4.5 MB (`custodio_0.1.0-1_amd64.deb`), N+1 is 4.5 MB: about 5 minutes each, 10 minutes for both, plus the 1.5 MB `e2e` tree.
  A first `just e2e-vm`-style run died at `copying the package N failed` (`chan.py: timeout after 120s`), as `put` has a 120 s default.
- The guest has a route out (default via 10.0.2.2, `curl http://archive.ubuntu.com` answers 200), so `apt-get` works.

The contract says: copying that takes more than 5 minutes → record it and write BLOCKED.md, because another channel changes F159's launcher.

Question: how should the packages reach the guest?
1. Serve the files from the host over the slirp gateway (host listener on loopback / 10.0.2.2, guest `curl`): the launcher needs no change if user networking is not `restrict=on`, but the driver gains a host listener (to check).
2. Add a second channel to the launcher (9p/virtiofs share, or a second virtio disk with the files): a change to F159's `vm.sh`.
3. Keep the serial channel and accept ~11 min of copy (plus a `put --timeout` per file): the VM time budget would be a person's decision and the CI run gets slower.
4. Shrink the transfer (strip the N+1 package until F163 needs it): the contract forbids silently shrinking the set.

Done and committed: steps 1-4. Also fixed: the driver's test-tool guard wrongly rejected `p11-kit` and `polkitd` (runtime dependencies of the real package, `packaging/nfpm.yaml`); and a race in `scripts/test-e2e-vm-host.sh` (control copies written into the e2e tree while a driver tarred it; about 1 run in 3 failed).
Left: step 5 (rest of the probe: install, has-tpm2, judges, "reaches the TPM" signal) and step 6.
