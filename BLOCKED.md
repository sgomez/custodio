# F104 needs the dev container rebuilt

`harness/Containerfile` now installs `swtpm swtpm-tools tpm2-tools libtss2-dev`. Please rebuild the dev container and restart
the loop. `command -v swtpm tpm2_getcap` and `pkg-config --exists tss2-esys` are empty/failing in the current container, so the
`verify` cannot pass before.

After the rebuild the next session should run `WITH_SWTPM_REQUIRE=1 scripts/test-with-swtpm.sh` directly (`just quick` does not
run script tests), then the `verify`. The real swtpm run is untested so far; see PROGRESS.md.
