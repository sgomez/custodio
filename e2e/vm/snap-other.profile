# The test profile of the snap-refused-other-snap case (F179): a label that looks like another snap's app. It allows what the child needs
# (files, unix sockets) so that AppArmor itself never stops the connect: only the service's label check can refuse it. Loaded by
# e2e/vm/snap-lib.sh at run time, always unloaded; not packaged and not a label source of the service.
profile snap.e2e-other.app {
  capability,
  file,
  network,
  unix,
  signal,
  ptrace,
}
