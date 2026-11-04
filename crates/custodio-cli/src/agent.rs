//! A polkit text agent (`pkttyagent`) for the CLI's own process, when the person is on a terminal.
//!
//! polkit has no call that tells whether an agent is registered (`docs/findings/F89.md`), so on a
//! terminal the agent is always started, registered with `--fallback` for this process only:
//! polkitd then prefers any agent of the session (`SPEC_DEVIATIONS.md`, F89). It is started around
//! the one call that makes the service ask polkit, and stopped and reaped when the call returns.

use std::io;

use secrecy::SecretString;

use crate::Importer;
use crate::delete::KeyDeleter;
use crate::failure::ServiceFailure;

pub mod process;

/// The descriptor `pkttyagent` closes when it is registered. The real spawner makes it the
/// agent's standard output, so no `unsafe` descriptor juggling is needed.
pub const NOTIFY_FD: u32 = 1;

/// The CLI's own process, as polkit names a process: its pid and its start time (field 22 of
/// `/proc/<pid>/stat`), so that a reused pid cannot match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub start_time: u64,
}

impl Process {
    /// This process, read from `/proc/self/stat`.
    ///
    /// # Errors
    /// If `/proc/self/stat` cannot be read or parsed.
    pub fn current() -> io::Result<Self> {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let start_time = start_time_of(&stat)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc stat"))?;
        Ok(Self {
            pid: std::process::id(),
            start_time,
        })
    }
}

/// Field 22 of a `/proc/<pid>/stat` line. The command name (field 2) is in parentheses and may
/// hold spaces and parentheses, so fields are counted from the last `)`.
#[must_use]
pub fn start_time_of(stat: &str) -> Option<u64> {
    let after_comm = stat.get(stat.rfind(')')? + 1..)?;
    // `after_comm` starts at field 3, so field 22 is the 20th word.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// The arguments of `pkttyagent`: its notify descriptor, `--fallback`, and exactly one process, the
/// CLI's. Never `--system-bus-name`, another pid, or nothing (which would mean the parent).
#[must_use]
pub fn agent_args(process: Process) -> Vec<String> {
    vec![
        "--fallback".to_owned(),
        format!("--notify-fd={NOTIFY_FD}"),
        format!("--process={},{}", process.pid, process.start_time),
    ]
}

/// A started agent. `stop` ends it and reaps it.
pub trait Stop {
    fn stop(&mut self);
}

/// Starts the agent with `args` (those of [`agent_args`]) and returns once it is registered, has
/// failed, or a bounded wait has passed.
pub trait AgentSpawner {
    /// # Errors
    /// If no agent could be started (a missing `setpriv` or `pkttyagent` is one).
    fn spawn(&self, args: &[String]) -> io::Result<Box<dyn Stop>>;
}

/// Stops the agent when it goes out of scope.
pub struct AgentGuard(Option<Box<dyn Stop>>);

impl AgentGuard {
    #[must_use]
    pub fn running(&self) -> bool {
        self.0.is_some()
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(agent) = self.0.as_mut() {
            agent.stop();
        }
    }
}

/// An importer or deleter that runs the agent around the one call that makes the service ask
/// polkit. Everything before it (the password, the confirmation) has already happened.
pub struct WithAgent<I, S> {
    inner: I,
    spawner: S,
    stdin_is_terminal: bool,
    process: Option<Process>,
}

impl<I, S: AgentSpawner> WithAgent<I, S> {
    #[must_use]
    pub const fn new(
        inner: I,
        spawner: S,
        stdin_is_terminal: bool,
        process: Option<Process>,
    ) -> Self {
        Self {
            inner,
            spawner,
            stdin_is_terminal,
            process,
        }
    }

    /// Only on a terminal; a failure to start leaves the call to go on without an agent.
    fn guard(&self) -> AgentGuard {
        if !self.stdin_is_terminal {
            return AgentGuard(None);
        }
        let Some(process) = self.process else {
            return AgentGuard(None);
        };
        AgentGuard(self.spawner.spawn(&agent_args(process)).ok())
    }
}

impl<I: Importer, S: AgentSpawner> Importer for WithAgent<I, S> {
    fn import_p12(
        &self,
        id: &str,
        p12: &[u8],
        password: &SecretString,
    ) -> Result<String, ServiceFailure> {
        let _agent = self.guard();
        self.inner.import_p12(id, p12, password)
    }
}

impl<I: KeyDeleter, S: AgentSpawner> KeyDeleter for WithAgent<I, S> {
    fn delete_key(&self, id: &str) -> Result<(), ServiceFailure> {
        let _agent = self.guard();
        self.inner.delete_key(id)
    }
}

#[cfg(test)]
mod tests;
