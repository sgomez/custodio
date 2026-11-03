//! Where the service learns the flatpak application id of a caller, behind a replaceable interface.
//!
//! F67 decided on the cgroup scope of the process the bus pinned with `ProcessFD`: the pid behind the pidfd is
//! looked for in the `cgroup.procs` of every scope of the caller's `app.slice`
//! (`user@<uid>.service/app.slice`, `<uid>` from the bus credentials), and the name of the scope that lists it
//! goes to [`crate::app_id::classify`]. After the scan the pidfd is read again: it must still be the same
//! process. A source never fails and never panics: every failure is [`AppIdOutcome::Undetermined`].
//!
//! What the caller can rely on, with the constants below:
//! - an answer comes within [`LOOKUP_DEADLINE`] (1 s) of the call, whatever the files are;
//! - nothing is followed: every step of the path and every file is opened with `O_NOFOLLOW`, without
//!   blocking, and must be a directory or a regular file; a FIFO, device or symlink is refused;
//! - a `cgroup.procs` is read up to [`MAX_PROCS_BYTES`] and at most [`MAX_CHILDREN`] children of `app.slice`
//!   are looked at; more is `Undetermined`;
//! - a read that does not return (a FUSE file, say) leaves a thread behind, but at most [`MAX_STUCK`] such
//!   threads exist at a time (per reader); at that number a lookup is `Undetermined` at once and starts no
//!   thread. A stuck thread that finishes gives its slot back. A lookup uses two threads (worker and
//!   watchdog), so at most `MAX_STUCK` workers (and their watchdogs) exist at a time.
//!
//! The cgroup2 mount is `/sys/fs/cgroup`. On a host the tree starts there; in a container sharing the host's
//! cgroup namespace (the e2e containers) it starts at `/sys/fs/cgroup/<container id>`. The reader takes the
//! prefix from the service's own `/proc/self/cgroup`: everything in front of `system.slice`.
//!
//! A missing `ProcessFD` never reaches a source: it takes a borrowed pidfd, so the caller (the audit wiring)
//! maps "no `ProcessFD`" to `Undetermined` itself.

mod bounded;
mod guarded;
mod limiter;
mod scan;

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::app_id::{AppIdOutcome, validate};
pub use guarded::{ErasedAppIdSource, GuardedSource};
use limiter::Limiter;

/// The time a whole lookup may take.
pub const LOOKUP_DEADLINE: Duration = Duration::from_secs(1);
/// Largest `cgroup.procs` that is read.
pub const MAX_PROCS_BYTES: usize = 1024 * 1024;
/// Most children of `app.slice` that are looked at.
pub const MAX_CHILDREN: usize = 4096;
/// Most lookups that missed their deadline and are still running.
pub const MAX_STUCK: usize = 8;
/// The cgroup2 mount point.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Reads the app-id of the process a pidfd pins.
pub trait AppIdSource: Send + Sync {
    /// The app-id of the process behind `pidfd`, whose bus credentials say `uid`. Never an error: every failure
    /// is [`AppIdOutcome::Undetermined`].
    fn app_id(&self, pidfd: BorrowedFd<'_>, uid: u32) -> impl Future<Output = AppIdOutcome> + Send;
}

/// A source that answers what it was given, for tests of the code that uses a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeAppIdSource(AppIdOutcome);

impl FakeAppIdSource {
    /// Answers `outcome` every time.
    #[must_use]
    pub fn new(outcome: AppIdOutcome) -> Self {
        Self(outcome)
    }

    /// Answers `Read(id)`; `None` if `id` is not a valid application id.
    #[must_use]
    pub fn reading(id: &str) -> Option<Self> {
        validate(id.as_bytes()).map(|id| Self(AppIdOutcome::Read(id)))
    }
}

impl AppIdSource for FakeAppIdSource {
    fn app_id(
        &self,
        _pidfd: BorrowedFd<'_>,
        _uid: u32,
    ) -> impl Future<Output = AppIdOutcome> + Send {
        std::future::ready(self.0.clone())
    }
}

/// Reads the pid of a pidfd. Tests replace it.
type PidReader = Arc<dyn Fn(BorrowedFd<'_>) -> Option<u32> + Send + Sync>;
/// Runs on the lookup thread before the scan. Tests make it block.
type Hook = Arc<dyn Fn() + Send + Sync>;

/// The source F67 decided on: the scope in the caller's `app.slice`.
pub struct CgroupAppIdSource {
    root: PathBuf,
    limiter: Limiter,
    deadline: Duration,
    pid_reader: PidReader,
    before_scan: Option<Hook>,
}

impl CgroupAppIdSource {
    /// The reader of the service: the cgroup tree under `/sys/fs/cgroup` (below the container's own prefix when
    /// the service runs in one, found from `/proc/self/cgroup` once), the documented deadline and cap.
    #[must_use]
    pub fn new() -> Self {
        let mount = std::path::Path::new(CGROUP_ROOT);
        let own = std::fs::read("/proc/self/cgroup").unwrap_or_default();
        Self::with_root(scan::tree_root(mount, &own), LOOKUP_DEADLINE, MAX_STUCK)
    }

    /// A reader of another cgroup tree, deadline and cap (tests).
    #[must_use]
    pub fn with_root(root: PathBuf, deadline: Duration, cap: usize) -> Self {
        Self {
            root,
            limiter: Limiter::new(deadline, cap),
            deadline,
            pid_reader: Arc::new(scan::read_pid),
            before_scan: None,
        }
    }

    #[cfg(test)]
    fn with_pid_reader(mut self, reader: PidReader) -> Self {
        self.pid_reader = reader;
        self
    }

    #[cfg(test)]
    fn with_before_scan(mut self, hook: Hook) -> Self {
        self.before_scan = Some(hook);
        self
    }
}

impl Default for CgroupAppIdSource {
    fn default() -> Self {
        Self::new()
    }
}

/// The whole blocking lookup, on its own thread.
fn lookup(
    root: &std::path::Path,
    uid: u32,
    pidfd: &OwnedFd,
    until: Instant,
    pid_reader: &PidReader,
) -> AppIdOutcome {
    let Some(pid) = pid_reader(pidfd.as_fd()) else {
        return AppIdOutcome::Undetermined;
    };
    let outcome = scan::scan(root, uid, pid, until);
    // Still the same process? The pidfd names the process, not the number, so a reused pid cannot match.
    if pid_reader(pidfd.as_fd()) == Some(pid) {
        outcome
    } else {
        AppIdOutcome::Undetermined
    }
}

impl AppIdSource for CgroupAppIdSource {
    async fn app_id(&self, pidfd: BorrowedFd<'_>, uid: u32) -> AppIdOutcome {
        let Ok(owned) = pidfd.try_clone_to_owned() else {
            return AppIdOutcome::Undetermined;
        };
        let (root, pid_reader, hook) = (
            self.root.clone(),
            Arc::clone(&self.pid_reader),
            self.before_scan.clone(),
        );
        let until = Instant::now() + self.deadline;
        self.limiter
            .run(move || {
                if let Some(hook) = hook {
                    hook();
                }
                lookup(&root, uid, &owned, until, &pid_reader)
            })
            .await
            .unwrap_or(AppIdOutcome::Undetermined)
    }
}

#[cfg(test)]
mod tests;
