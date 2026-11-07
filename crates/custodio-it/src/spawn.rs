//! Children that inherit no descriptor above stderr.
//!
//! The TSS libraries open their sockets without close-on-exec. A child forked while another test of the
//! same binary holds a TCTI connection keeps the client end open for its whole life, so that test's
//! single-client `swtpm` never sees it close and the next connection waits forever (F117: private
//! `dbus-daemon`s held other tests' TPM connections). Long-lived children of tests start through here.

use std::ffi::OsStr;
use std::process::Command;

const CLOSE_FDS: &str = "for f in /proc/self/fd/*; do n=${f##*/}; [ \"$n\" -gt 2 ] && eval \"exec $n>&-\"; done 2>/dev/null; exec \"$@\"";

/// A [`Command`] that runs `program` once every inherited descriptor above 2 is closed. Arguments,
/// environment and stdio are set on it as on any other.
#[must_use]
pub fn closed_fds(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new("bash");
    command.args(["-c", CLOSE_FDS, "close-fds"]).arg(program);
    command
}
