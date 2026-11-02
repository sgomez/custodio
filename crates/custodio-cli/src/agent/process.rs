//! The real spawner: `setpriv --pdeathsig=KILL -- pkttyagent ...`.
//!
//! `pkttyagent` does not watch its parent (`docs/findings.md`, F89), and `custodio-cli` forbids
//! `unsafe`, so `CommandExt::pre_exec` is out. `setpriv` sets the parent-death signal and execs
//! `pkttyagent`, which keeps the pid and its own argv. The signal fires when the parent *thread*
//! exits, so this is called from the main thread. If `setpriv` is missing, no agent is started.

use std::io;
use std::os::fd::AsFd;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, Once, PoisonError};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::pipe::pipe;

use super::{AgentSpawner, Stop};

/// How long the CLI waits for the agent to say that it is registered.
pub const NOTIFY_WAIT: Duration = Duration::from_secs(5);

/// The exit status after SIGINT, SIGTERM or SIGHUP.
pub const SIGNALLED_STATUS: i32 = 130;

/// The running agent, shared with the signal handler thread.
static AGENT: Mutex<Option<Child>> = Mutex::new(None);
static HANDLER: Once = Once::new();

/// Kills and reaps the agent, if there is one.
fn stop_agent() {
    let taken = AGENT.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(mut child) = taken {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Stops the agent, then ends the process with a non-zero status, on SIGINT, SIGTERM or SIGHUP.
fn install_handler() -> bool {
    let mut installed = false;
    HANDLER.call_once(|| {
        installed = ctrlc::set_handler(|| {
            stop_agent();
            std::process::exit(SIGNALLED_STATUS);
        })
        .is_ok();
    });
    installed
}

/// Starts `pkttyagent` found on `PATH`.
pub struct Pkttyagent;

struct Running;

impl Stop for Running {
    fn stop(&mut self) {
        stop_agent();
    }
}

impl AgentSpawner for Pkttyagent {
    fn spawn(&self, args: &[String]) -> io::Result<Box<dyn Stop>> {
        if !install_handler() {
            return Err(io::Error::other("no signal handler"));
        }
        let (notified, notify) = pipe().map_err(io::Error::from)?;
        let child = Command::new("setpriv")
            .arg("--pdeathsig=KILL")
            .arg("--")
            .arg("pkttyagent")
            .args(args)
            .stdin(Stdio::null())
            // The notify descriptor: closed by the agent once registered, or when it ends.
            .stdout(Stdio::from(notify))
            .stderr(Stdio::null())
            .spawn()?;
        *AGENT.lock().unwrap_or_else(PoisonError::into_inner) = Some(child);
        wait_for_close(&notified);
        Ok(Box::new(Running))
    }
}

/// Waits until the write end is closed (the agent registered, or ended), at most [`NOTIFY_WAIT`].
fn wait_for_close(read: &impl AsFd) {
    let deadline = std::time::Instant::now() + NOTIFY_WAIT;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let Ok(secs) = i64::try_from(left.as_secs()) else {
            return;
        };
        let timeout = Timespec {
            tv_sec: secs,
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        let mut fds = [PollFd::new(read, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return,
            Ok(_) => {
                let revents = fds[0].revents();
                if revents.contains(PollFlags::HUP) || revents.contains(PollFlags::ERR) {
                    return;
                }
                // Data on the pipe is not a close; drain it so the wait goes on.
                let mut buf = [0u8; 64];
                if !matches!(rustix::io::read(read, &mut buf), Ok(n) if n > 0) {
                    return;
                }
            }
            Err(Errno::INTR) => {}
            Err(_) => return,
        }
    }
}
