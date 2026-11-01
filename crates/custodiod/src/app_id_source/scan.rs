//! The blocking part of the lookup: the pid behind the pidfd, then the scope of the caller's `app.slice` that
//! lists it. Everything read here is hostile (a person controls the names and may control the files).

use std::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Instant;

use rustix::fs::{Dir, Mode, OFlags, openat};

use super::bounded::{ReadError, open_regular, read_bounded};
use super::{MAX_CHILDREN, MAX_PROCS_BYTES};
use crate::app_id::{AppIdOutcome, classify};

/// Largest `fdinfo` text that is read.
const MAX_FDINFO_BYTES: usize = 4096;

/// A `u32` written with ASCII digits only: no sign, no space, not empty, not above `u32::MAX`.
fn decimal(text: &[u8]) -> Option<u32> {
    if !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// The pid in the text of a pidfd's `fdinfo`. `None` for a missing line, `0` (another pid namespace), `-1` (the
/// process has ended) and anything that is not a positive number.
pub(super) fn pid_from_fdinfo(info: &[u8]) -> Option<u32> {
    let line = info
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"Pid:"))?;
    let pid = decimal(line.trim_ascii())?;
    (pid != 0).then_some(pid)
}

/// The pid of a process, read from `/proc/self/fdinfo/<fd>` of its pidfd.
pub(super) fn read_pid(pidfd: BorrowedFd<'_>) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let proc = std::fs::File::open("/proc/self/fdinfo").ok()?;
    let file = open_regular(&proc, pidfd.as_raw_fd().to_string()).ok()?;
    pid_from_fdinfo(&read_bounded(file, MAX_FDINFO_BYTES).ok()?)
}

/// Whether the text of a `cgroup.procs` lists `pid`. `None` if it is not a list of decimal pids, one per line.
pub(super) fn lists_pid(procs: &[u8], pid: u32) -> Option<bool> {
    if procs.is_empty() {
        return Some(false);
    }
    let body = procs.strip_suffix(b"\n").unwrap_or(procs);
    let mut found = false;
    for line in body.split(|&b| b == b'\n') {
        found |= decimal(line)? == pid;
    }
    Some(found)
}

fn open_dir(parent: impl AsFd, name: impl rustix::path::Arg) -> Option<OwnedFd> {
    let flags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK);
    openat(parent, name, flags, Mode::empty()).ok()
}

/// `<root>/user.slice/user-<uid>.slice/user@<uid>.service/app.slice`, each step without following a symlink.
/// `None` if any step is not a directory.
fn open_app_slice(root: &std::path::Path, uid: u32) -> Option<OwnedFd> {
    let mut dir: OwnedFd = rustix::fs::open(
        root,
        OFlags::RDONLY
            .union(OFlags::DIRECTORY)
            .union(OFlags::CLOEXEC)
            .union(OFlags::NONBLOCK),
        Mode::empty(),
    )
    .ok()?;
    for part in [
        "user.slice".to_owned(),
        format!("user-{uid}.slice"),
        format!("user@{uid}.service"),
        "app.slice".to_owned(),
    ] {
        dir = open_dir(&dir, &part)?;
    }
    Some(dir)
}

/// Finds the scope of the caller's `app.slice` that lists `pid`, and classifies its name.
/// `None` when the scan finished without finding the pid; `Undetermined` for every failure and limit.
pub(super) fn scan(root: &std::path::Path, uid: u32, pid: u32, until: Instant) -> AppIdOutcome {
    let Some(slice) = open_app_slice(root, uid) else {
        return AppIdOutcome::None;
    };
    let Ok(dir) = Dir::read_from(&slice) else {
        return AppIdOutcome::Undetermined;
    };
    let mut seen = 0usize;
    for entry in dir {
        let Ok(entry) = entry else {
            return AppIdOutcome::Undetermined;
        };
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        seen += 1;
        if seen > MAX_CHILDREN || Instant::now() >= until {
            return AppIdOutcome::Undetermined;
        }
        match lists(&slice, entry.file_name(), pid) {
            Some(true) => return classify(Some(name)),
            Some(false) => {}
            None => return AppIdOutcome::Undetermined,
        }
    }
    AppIdOutcome::None
}

/// Whether the child `name` of `slice` is a cgroup directory whose `cgroup.procs` lists `pid`. A child that is
/// not a directory (a symlink included) is skipped; one that vanished is skipped; `None` for an unreadable list.
fn lists(slice: &OwnedFd, name: &CStr, pid: u32) -> Option<bool> {
    let Some(child) = open_dir(slice, name) else {
        return Some(false);
    };
    match open_regular(&child, "cgroup.procs").and_then(|f| read_bounded(f, MAX_PROCS_BYTES)) {
        Ok(text) => lists_pid(&text, pid),
        Err(ReadError::Missing) => Some(false),
        Err(ReadError::Refused) => None,
    }
}
