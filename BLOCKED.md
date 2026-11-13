# Blocked: F175 needs a person to decide how `SO_PEERSEC` is read

NEXT_FINDINGS (finding 1) says `unsafe` belongs only in the PKCS#11 FFI layer, so
`crates/custodio-peer` (a `getsockopt` call and `OwnedFd::from_raw_fd`) must go. I checked what the
lock file offers (rustix 1.1.6, nix 0.31.3, libc 0.2.191):

- `SO_PEERCRED`: safe in rustix (`net::sockopt::socket_peercred`).
- `SO_PEERPIDFD`: safe in nix (`sockopt::PeerPidfd`).
- `SO_PEERSEC`: no safe wrapper in either crate. Neither has a `PeerSec` option, `SO_PASSSEC` or
  `SCM_SECURITY` (grep of both sources). `SCM_SECURITY` would also give the label of each
  message's sender, not the label at connect time.

SPEC.md and CLAUDE.md do not state an `unsafe` rule; the only record is `docs/decisions.md:161`
(Miri runs `ffi::` only). The label is the core of acceptance 2, so it cannot be dropped.

## Options
1. Allow one audited `getsockopt(SO_PEERSEC)` in a small crate (the current design, cut down to that
   one call), and add it to `just mutants`, Miri and ASan. The two other reads move to rustix/nix.
2. Add a dependency that already has a safe `SO_PEERSEC` read (I found none in the lock file; it
   would need a vetting pass).
3. Read the label from `/proc/<pid>/attr/current` through the pidfd. This is safe code but racy
   (the process can change its label or be replaced after connect). `docs/decisions.md:239` already
   rejects it.

## My recommendation
Option 1. Say which one you pick and I will implement it in the next session, including the
contract amendment for the new crate (finding 3), the workspace lints (finding 4), the mutants and
memory-safety gates (finding 2), and the comment fix in `scripts/check-test-label.sh`.
