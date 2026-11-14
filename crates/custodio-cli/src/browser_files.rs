//! Strict, read-only readers of the untrusted files a browser profile holds: `profiles.ini`, `installs.ini` and
//! `pkcs11.txt`, and the lock state of a profile directory (F172's rules). Everything here takes bytes or a path it is
//! given; nothing reads `$HOME`, nothing creates or writes a file, and malformed input is an error naming the file.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, fcntl_lock};
use rustix::io::Errno;
use rustix::process::{Pid, test_kill_process};

/// The largest input any of these files may have. Real ones are a few kilobytes.
pub const MAX_FILE_LEN: usize = 1024 * 1024;

/// A file that could not be read or is malformed. The text names the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError {
    file: String,
    reason: String,
}

impl FileError {
    fn new(file: &str, reason: impl Into<String>) -> Self {
        Self {
            file: file.to_owned(),
            reason: reason.into(),
        }
    }

    /// The name of the file, as given.
    #[must_use]
    pub fn file(&self) -> &str {
        &self.file
    }
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.reason)
    }
}

impl std::error::Error for FileError {}

/// Read a file whole, refusing one longer than [`MAX_FILE_LEN`]. `Ok(None)` when it does not exist.
///
/// # Errors
/// Any other read failure, or an oversized file.
pub fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, FileError> {
    let name = path.display().to_string();
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(FileError::new(&name, format!("cannot be read: {e}"))),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| FileError::new(&name, format!("cannot be read: {e}")))?;
    if bytes.len() > MAX_FILE_LEN {
        return Err(FileError::new(
            &name,
            format!("is longer than {MAX_FILE_LEN} bytes"),
        ));
    }
    Ok(Some(bytes))
}

fn text<'a>(file: &str, bytes: &'a [u8]) -> Result<&'a str, FileError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(FileError::new(
            file,
            format!("is longer than {MAX_FILE_LEN} bytes"),
        ));
    }
    if bytes.contains(&0) {
        return Err(FileError::new(file, "contains a NUL byte"));
    }
    let s = std::str::from_utf8(bytes).map_err(|_| FileError::new(file, "is not valid UTF-8"))?;
    Ok(s.strip_prefix('\u{feff}').unwrap_or(s))
}

/// One `[ProfileN]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEntry {
    pub name: Option<String>,
    pub path: String,
    pub relative: bool,
}

/// What `profiles.ini` or `installs.ini` names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileIndex {
    pub profiles: Vec<ProfileEntry>,
    /// The `Default=` of each `[InstallHASH]` section, relative to the directory of the file.
    pub install_defaults: Vec<String>,
}

impl ProfileIndex {
    /// Every profile directory the index names, once each, as written (not resolved), the install defaults after the profiles.
    /// Relative paths are taken against `dir`, the directory of the index file.
    #[must_use]
    pub fn directories(&self, dir: &Path) -> Vec<PathBuf> {
        let profiles = self.profiles.iter().map(|p| {
            if p.relative {
                dir.join(&p.path)
            } else {
                PathBuf::from(&p.path)
            }
        });
        let defaults = self.install_defaults.iter().map(|d| dir.join(d));
        let mut seen = HashSet::new();
        profiles
            .chain(defaults)
            .filter(|d| seen.insert(d.clone()))
            .collect()
    }
}

/// Parse `profiles.ini` (`file` names it in errors).
///
/// # Errors
/// An empty, oversized, non-UTF-8 or NUL-holding input, an unclosed section header, a line that is not `key=value`, a
/// key outside a section or repeated in one, a section name repeated, a `[ProfileN]` without a `Path`, an `IsRelative`
/// other than 0 and 1, an empty `Path` or `Default`.
pub fn parse_profiles_ini(file: &str, bytes: &[u8]) -> Result<ProfileIndex, FileError> {
    parse_index(file, bytes)
}

/// Parse `installs.ini`: the same syntax, read for its `[InstallHASH]` sections.
///
/// # Errors
/// As [`parse_profiles_ini`].
pub fn parse_installs_ini(file: &str, bytes: &[u8]) -> Result<ProfileIndex, FileError> {
    parse_index(file, bytes)
}

struct Section {
    name: String,
    keys: Vec<(String, String)>,
}

fn sections(file: &str, bytes: &[u8]) -> Result<Vec<Section>, FileError> {
    let s = text(file, bytes)?;
    let mut out: Vec<Section> = Vec::new();
    for (n, raw) in s.lines().enumerate() {
        let at = |why: &str| FileError::new(file, format!("line {}: {why}", n + 1));
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| at("section header is not closed"))?;
            if name.is_empty() || name.contains(['[', ']']) {
                return Err(at("section name is empty or malformed"));
            }
            if out.iter().any(|s| s.name == name) {
                return Err(at("section is repeated"));
            }
            out.push(Section {
                name: name.to_owned(),
                keys: Vec::new(),
            });
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| at("line is not key=value"))?;
        let section = out.last_mut().ok_or_else(|| at("key outside a section"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(at("empty key"));
        }
        if section.keys.iter().any(|(k, _)| k == key) {
            return Err(at("key is repeated in its section"));
        }
        section.keys.push((key.to_owned(), value.trim().to_owned()));
    }
    if out.is_empty() {
        return Err(FileError::new(file, "has no section"));
    }
    Ok(out)
}

fn is_profile_section(name: &str) -> bool {
    name.strip_prefix("Profile")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_index(file: &str, bytes: &[u8]) -> Result<ProfileIndex, FileError> {
    let mut index = ProfileIndex::default();
    for section in sections(file, bytes)? {
        let get = |k: &str| {
            section
                .keys
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        if is_profile_section(&section.name) {
            let path = get("Path")
                .ok_or_else(|| FileError::new(file, format!("[{}] has no Path", section.name)))?;
            if path.is_empty() {
                return Err(FileError::new(
                    file,
                    format!("[{}] has an empty Path", section.name),
                ));
            }
            let relative = match get("IsRelative") {
                None | Some("0") => false,
                Some("1") => true,
                Some(_) => {
                    return Err(FileError::new(
                        file,
                        format!("[{}] has an IsRelative that is not 0 or 1", section.name),
                    ));
                }
            };
            index.profiles.push(ProfileEntry {
                name: get("Name").map(str::to_owned),
                path: path.to_owned(),
                relative,
            });
        } else if section.name.starts_with("Install")
            && let Some(default) = get("Default")
        {
            if default.is_empty() {
                return Err(FileError::new(
                    file,
                    format!("[{}] has an empty Default", section.name),
                ));
            }
            index.install_defaults.push(default.to_owned());
        }
    }
    Ok(index)
}

/// One module entry of `pkcs11.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleEntry {
    /// `library=`; empty for the internal module.
    pub library: String,
    pub name: String,
    /// Every other line (`parameters=`, `NSS=`, `config=`), in order, as written.
    pub other: Vec<(String, String)>,
}

const MODULE_KEYS: [&str; 5] = ["library", "name", "parameters", "NSS", "config"];

/// Parse `pkcs11.txt`: entries of `key=value` lines separated by blank lines.
///
/// # Errors
/// An oversized, non-UTF-8 or NUL-holding input, a line that is not `key=value`, a key NSS does not define, a key
/// repeated in an entry, an entry without `library` or `name`.
pub fn parse_pkcs11_txt(file: &str, bytes: &[u8]) -> Result<Vec<ModuleEntry>, FileError> {
    let s = text(file, bytes)?;
    let mut entries = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    let mut flush = |current: &mut Vec<(String, String)>, line: usize| -> Result<(), FileError> {
        if current.is_empty() {
            return Ok(());
        }
        let mut library = None;
        let mut name = None;
        let mut other = Vec::new();
        for (k, v) in current.drain(..) {
            match k.as_str() {
                "library" => library = Some(v),
                "name" => name = Some(v),
                _ => other.push((k, v)),
            }
        }
        let (Some(library), Some(name)) = (library, name) else {
            return Err(FileError::new(
                file,
                format!("the entry ending at line {line} has no library or no name"),
            ));
        };
        entries.push(ModuleEntry {
            library,
            name,
            other,
        });
        Ok(())
    };
    for (n, raw) in s.lines().enumerate() {
        let at = |why: &str| FileError::new(file, format!("line {}: {why}", n + 1));
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            flush(&mut current, n)?;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| at("line is not key=value"))?;
        if !MODULE_KEYS.contains(&key) {
            return Err(at("unknown key"));
        }
        if current.iter().any(|(k, _)| k == key) {
            return Err(at("key is repeated in its entry"));
        }
        current.push((key.to_owned(), value.to_owned()));
    }
    flush(&mut current, s.lines().count())?;
    Ok(entries)
}

/// Read and parse the `pkcs11.txt` at `path`; `Ok(None)` when the file does not exist.
///
/// # Errors
/// As [`parse_pkcs11_txt`], and an unreadable or oversized file.
pub fn read_pkcs11_txt(path: &Path) -> Result<Option<Vec<ModuleEntry>>, FileError> {
    match read_bounded(path)? {
        None => Ok(None),
        Some(bytes) => parse_pkcs11_txt(&path.display().to_string(), &bytes).map(Some),
    }
}

/// Entry point of the `profile_index` fuzz target: both index parsers over the same bytes. `true` when they accept it.
/// An error must name the file; a parsed profile must have a non-empty path.
///
/// # Panics
/// When a parser breaks one of those invariants: that is what the fuzz target looks for.
#[must_use]
pub fn fuzz_profile_index(data: &[u8]) -> bool {
    let mut accepted = false;
    for (file, parse) in [
        ("profiles.ini", parse_profiles_ini as fn(&str, &[u8]) -> _),
        ("installs.ini", parse_installs_ini),
    ] {
        match parse(file, data) {
            Ok(index) => {
                accepted = true;
                assert!(index.profiles.iter().all(|p| !p.path.is_empty()));
                assert!(index.install_defaults.iter().all(|d| !d.is_empty()));
            }
            Err(e) => assert!(e.to_string().starts_with(file)),
        }
    }
    accepted
}

/// Entry point of the `nss_modules` fuzz target: the `pkcs11.txt` parser. `true` when it accepts the bytes.
///
/// # Panics
/// When the parser breaks an invariant of its result: that is what the fuzz target looks for.
#[must_use]
pub fn fuzz_nss_modules(data: &[u8]) -> bool {
    match parse_pkcs11_txt("pkcs11.txt", data) {
        Ok(entries) => {
            assert!(
                entries
                    .iter()
                    .all(|e| !e.other.iter().any(|(k, _)| k == "library" || k == "name"))
            );
            true
        }
        Err(e) => {
            assert!(e.to_string().starts_with("pkcs11.txt"));
            false
        }
    }
}

/// Why a profile counts as held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldReason {
    /// `lock` names a live process of this host (or one this user may not signal).
    LiveProcess(i32),
    /// `lock` names another host's address.
    ForeignHost(String),
    /// `lock` is not a symlink to `IP:+PID`.
    UnparseableLock,
    /// Another process holds the `fcntl` lock on `.parentlock`, or it cannot be probed.
    ParentLock,
}

impl fmt::Display for HeldReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveProcess(pid) => write!(f, "in use by process {pid}"),
            Self::ForeignHost(addr) => write!(f, "locked from another host ({addr})"),
            Self::UnparseableLock => f.write_str("its lock cannot be understood"),
            Self::ParentLock => f.write_str("another process holds .parentlock"),
        }
    }
}

/// Whether a browser has the profile open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockState {
    Free,
    Held(HeldReason),
}

/// The state of a process the `lock` symlink names, from the result of `kill(pid, 0)`: only `ESRCH` proves it dead.
#[must_use]
pub fn pid_is_dead(kill: Result<(), Errno>) -> bool {
    kill == Err(Errno::SRCH)
}

/// The address Firefox writes in `lock`: the first IPv4 address of this host's name, 127.0.0.1 if the lookup fails.
#[must_use]
pub fn local_address() -> Ipv4Addr {
    let name = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    (name.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| {
            it.find_map(|a| {
                if let std::net::SocketAddr::V4(v4) = a {
                    Some(*v4.ip())
                } else {
                    None
                }
            })
        })
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

fn legacy_lock(profile: &Path, local: Ipv4Addr) -> Option<HeldReason> {
    let target = match fs::read_link(profile.join("lock")) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => return Some(HeldReason::UnparseableLock),
    };
    let parsed = target
        .to_str()
        .and_then(|t| t.split_once(":+"))
        .and_then(|(addr, pid)| {
            let addr = addr.parse::<Ipv4Addr>().ok()?;
            let pid = pid.parse::<i32>().ok().filter(|p| *p > 0)?;
            Some((addr, pid))
        });
    let Some((addr, pid)) = parsed else {
        return Some(HeldReason::UnparseableLock);
    };
    if addr != local {
        return Some(HeldReason::ForeignHost(addr.to_string()));
    }
    let dead = Pid::from_raw(pid).is_some_and(|p| pid_is_dead(test_kill_process(p)));
    if dead {
        None
    } else {
        Some(HeldReason::LiveProcess(pid))
    }
}

fn parent_lock_held(profile: &Path) -> bool {
    // No O_CREAT: a profile never opened has no `.parentlock` and must not get one.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open(profile.join(".parentlock"))
    {
        Ok(file) => fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive).is_err(),
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

/// The lock state of a profile directory by F172's rule: free unless `lock` is a link to a live local process, to a
/// foreign address or unparseable, or the `fcntl` lock on `.parentlock` cannot be taken. The probe lock is released on
/// return and nothing is created. `local` is the address of this host (see [`local_address`]).
#[must_use]
pub fn lock_state(profile: &Path, local: Ipv4Addr) -> LockState {
    if let Some(reason) = legacy_lock(profile, local) {
        return LockState::Held(reason);
    }
    if parent_lock_held(profile) {
        return LockState::Held(HeldReason::ParentLock);
    }
    LockState::Free
}

/// The real path of each directory, dropping those that do not exist and repeats.
#[must_use]
pub fn real_directories(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    dirs.into_iter()
        .filter_map(|d| fs::canonicalize(d).ok())
        .filter(|d| d.is_dir() && seen.insert(d.clone()))
        .collect()
}
