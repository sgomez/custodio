//! The snap socket: which instance names are accepted, which directory is trusted, and the path.
//!
//! Inside a snap (`SNAP_INSTANCE_NAME` set) the module talks to `/run/snap.$SNAP_INSTANCE_NAME/custodio.sock` and never
//! to the bus. Anything wrong gives [`Transport::None`], which the module shows as no slots.
//!
//! The instance-name grammar is snapd's (`snap/naming`): `<snap>` or `<snap>_<key>`. A snap name is 2 to 40 of `a-z`,
//! `0-9` and `-`, with at least one letter and no leading, trailing or doubled `-`; the instance key is 1 to 10 of
//! `a-z` and `0-9`. The directory rule is the service's (`custodiod::snap_socket::check_dir`): opened without following
//! a final symbolic link, `fstat`, no group or other write bit, owned by root. The module may not link `custodiod`, so
//! it carries a copy; `custodio-it`'s `snap_transport.rs` pins both to one table.
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The variable snapd sets inside a snap.
pub const SNAP_INSTANCE_VAR: &str = "SNAP_INSTANCE_NAME";

/// The socket the module uses inside a snap, as a template.
pub const SOCKET_PATH_TEMPLATE: &str = "/run/snap.$SNAP_INSTANCE_NAME/custodio.sock";

const BASE_DIR: &str = "/run";
const MAX_SNAP_NAME: usize = 40;
const MIN_SNAP_NAME: usize = 2;
const MAX_KEY: usize = 10;

fn valid_snap_name(name: &str) -> bool {
    (MIN_SNAP_NAME..=MAX_SNAP_NAME).contains(&name.len())
        && name.bytes().any(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// Whether `name` is a snap instance name.
#[must_use]
pub fn valid_instance_name(name: &str) -> bool {
    let (snap, key) = match name.split_once('_') {
        Some((snap, key)) => (snap, Some(key)),
        None => (name, None),
    };
    valid_snap_name(snap)
        && key.is_none_or(|k| {
            (1..=MAX_KEY).contains(&k.len())
                && k.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// What the rule over a directory's `fstat` says (`mode` is `st_mode`): a directory, no group or other write bit, owned
/// by root.
#[must_use]
pub fn directory_ok(is_dir: bool, uid: u32, mode: u32) -> bool {
    is_dir && mode & 0o022 == 0 && uid == 0
}

/// Opens `dir` without following a final symbolic link and applies [`directory_ok`] to what `fstat` says.
#[must_use]
pub fn check_dir(dir: &Path) -> bool {
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(dir)
    else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    directory_ok(meta.is_dir(), meta.uid(), meta.mode())
}

fn base_dir() -> PathBuf {
    #[cfg(feature = "test-socket-dir")]
    if let Some(dir) = super::test_dir::base_dir() {
        return dir;
    }
    PathBuf::from(BASE_DIR)
}

/// The socket path for `instance` under `base`, if the name is valid and the directory passes.
fn path_in(base: &Path, instance: &str) -> Option<PathBuf> {
    if !valid_instance_name(instance) {
        return None;
    }
    let dir = base.join(format!("snap.{instance}"));
    check_dir(&dir).then(|| dir.join("custodio.sock"))
}

/// How the module reaches the service.
#[derive(Debug, PartialEq, Eq)]
pub enum Transport {
    /// The system bus.
    Bus,
    /// The snap's socket.
    Socket(PathBuf),
    /// Inside a snap, but there is no trustworthy socket: no slots.
    None,
}

/// The transport for `instance` (the value of [`SNAP_INSTANCE_VAR`], `None` when unset). The directory is checked now,
/// on every call.
#[must_use]
pub fn select(instance: Option<&OsStr>) -> Transport {
    let Some(instance) = instance else {
        return Transport::Bus;
    };
    instance
        .to_str()
        .and_then(|name| path_in(&base_dir(), name))
        .map_or(Transport::None, Transport::Socket)
}

/// The transport for this process.
#[must_use]
pub fn current() -> Transport {
    select(std::env::var_os(SNAP_INSTANCE_VAR).as_deref())
}

#[cfg(test)]
mod tests;
