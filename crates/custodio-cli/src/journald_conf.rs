//! Whether journald's storage is persistent, as `custodio doctor` check 5 reads it (`docs/findings/F190.md`, its
//! `Decision:` line is the specification): the last valid `Storage=` of the main file and its drop-ins, then the
//! state of `/var/log/journal` for `auto`. Files and one `stat` only: never `journalctl`, D-Bus or `/run/log/journal`.
//!
//! [`parse`] and [`evaluate`] are pure (and fuzzed); [`read`] is the thin reader of the files under a root.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// A file is not read past this size.
pub const MAX_FILE_LEN: u64 = 1024 * 1024;

/// The main file, first that exists wins; the others are not merged.
pub const MAIN_FILES: [&str; 4] = [
    "etc/systemd/journald.conf",
    "run/systemd/journald.conf",
    "usr/local/lib/systemd/journald.conf",
    "usr/lib/systemd/journald.conf",
];
/// The drop-in directories, a name in several comes from the first.
pub const DROP_IN_DIRS: [&str; 4] = [
    "etc/systemd/journald.conf.d",
    "run/systemd/journald.conf.d",
    "usr/local/lib/systemd/journald.conf.d",
    "usr/lib/systemd/journald.conf.d",
];
/// The journal directory `auto` needs.
pub const JOURNAL_DIR: &str = "var/log/journal";

/// A value of `Storage=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    Auto,
    Volatile,
    Persistent,
    None,
}

impl Storage {
    fn from_value(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "volatile" => Some(Self::Volatile),
            "persistent" => Some(Self::Persistent),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Where a setting is: a file (as the system sees it, `/etc/...`) and a 1-based line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub file: String,
    pub line: usize,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// One file that journald reads, in the order it applies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub text: String,
}

/// Every file that applies: the main file (if any), then the drop-ins sorted by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Files {
    pub main: Option<File>,
    pub drop_ins: Vec<File>,
}

/// What `stat("/var/log/journal")` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalDir {
    Directory,
    Missing,
    NotDirectory,
    /// Any other error: the reason.
    Error(String),
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Persistent, and why.
    Persistent(String),
    NotPersistent(Cause),
    /// Doctor does not guess: the reason.
    CouldNot(String),
}

/// Why the journal is not persistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// `auto` (set or by default) and `/var/log/journal` does not exist.
    AutoWithoutDirectory(Option<Source>),
    /// `volatile`: the source is the assignment, or the compiled-in default shown by `#Storage=`.
    Volatile {
        source: Source,
        by_default: bool,
    },
    None {
        source: Source,
        by_default: bool,
    },
}

/// One `Storage=` assignment, or what is wrong with a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Assigned(Storage, usize),
    Invalid(usize),
    Continued(usize),
}

/// The `[Journal]` lines of one file that matter: `Storage=` assignments, invalid values, continued lines.
///
/// Only the `[Journal]` section counts; the key is exactly `Storage` and the value, trimmed, exactly one of
/// `auto`, `persistent`, `volatile`, `none`.
#[must_use]
pub fn parse(text: &str) -> Vec<Item> {
    let mut items = Vec::new();
    let mut in_journal = false;
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            in_journal = rest.strip_suffix(']') == Some("Journal");
            continue;
        }
        if !in_journal {
            continue;
        }
        if line.ends_with('\\') {
            items.push(Item::Continued(n));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "Storage" {
            continue;
        }
        items.push(match Storage::from_value(value.trim()) {
            Some(s) => Item::Assigned(s, n),
            None => Item::Invalid(n),
        });
    }
    items
}

/// The compiled-in default the main file shows: its first `#Storage=` line.
fn default_comment(text: &str) -> Option<(Storage, usize)> {
    let (i, value) = text
        .lines()
        .enumerate()
        .find_map(|(i, l)| l.strip_prefix("#Storage=").map(|v| (i, v)))?;
    Some((Storage::from_value(value.trim())?, i + 1))
}

/// The state of the journal for these files and this `stat`.
#[must_use]
pub fn evaluate(files: &Files, dir: &JournalDir) -> Verdict {
    let mut set: Option<(Storage, Source)> = None;
    for file in files.main.iter().chain(&files.drop_ins) {
        for item in parse(&file.text) {
            let at = |line| Source {
                file: file.name.clone(),
                line,
            };
            match item {
                Item::Assigned(s, line) => set = Some((s, at(line))),
                Item::Invalid(line) => {
                    return Verdict::CouldNot(format!(
                        "{} has a Storage= value that is empty or not auto, persistent, volatile or none; journald ignores it and doctor does not guess what was meant",
                        at(line)
                    ));
                }
                Item::Continued(line) => {
                    return Verdict::CouldNot(format!(
                        "{} ends in a backslash in [Journal]: the next line is part of it and doctor does not join lines",
                        at(line)
                    ));
                }
            }
        }
    }
    let (storage, source, by_default) = if let Some((s, source)) = set {
        (s, Some(source), false)
    } else {
        let Some(main) = &files.main else {
            return Verdict::CouldNot("no journald.conf exists and Storage= is not set: the default is auto on systemd 257 and persistent from 259, and a missing file does not say which".to_owned());
        };
        let Some((s, line)) = default_comment(&main.text) else {
            return Verdict::CouldNot(format!(
                "Storage= is not set and {} has no #Storage= line that shows the default",
                main.name
            ));
        };
        (
            s,
            Some(Source {
                file: main.name.clone(),
                line,
            }),
            true,
        )
    };
    let explicit_source = || source.clone().filter(|_| !by_default);
    match storage {
        Storage::Persistent => Verdict::Persistent(if by_default {
            "the default is persistent".to_owned()
        } else {
            "Storage=persistent".to_owned()
        }),
        Storage::Auto => match dir {
            JournalDir::Directory => {
                Verdict::Persistent("Storage=auto and /var/log/journal exists".to_owned())
            }
            JournalDir::Missing => {
                Verdict::NotPersistent(Cause::AutoWithoutDirectory(explicit_source()))
            }
            JournalDir::NotDirectory => {
                Verdict::CouldNot("/var/log/journal is not a directory".to_owned())
            }
            JournalDir::Error(why) => {
                Verdict::CouldNot(format!("cannot stat /var/log/journal: {why}"))
            }
        },
        Storage::Volatile | Storage::None => {
            let source = source.unwrap_or_else(|| Source {
                file: String::new(),
                line: 0,
            });
            Verdict::NotPersistent(if storage == Storage::Volatile {
                Cause::Volatile { source, by_default }
            } else {
                Cause::None { source, by_default }
            })
        }
    }
}

fn read_text(root: &Path, rel: &str) -> Result<Option<File>, String> {
    let path = root.join(rel);
    let shown = format!("/{rel}");
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {shown}: {e}")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    if bytes.len() as u64 > MAX_FILE_LEN {
        return Err(format!("{shown} is longer than {MAX_FILE_LEN} bytes"));
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{shown} is not UTF-8"))?;
    Ok(Some(File { name: shown, text }))
}

/// The files that apply, read under `root`.
///
/// # Errors
/// The reason, for every error but a missing file or directory: an unreadable path, a file over 1 MiB, non-UTF-8.
pub fn read(root: &Path) -> Result<Files, String> {
    let mut files = Files::default();
    for rel in MAIN_FILES {
        if let Some(f) = read_text(root, rel)? {
            files.main = Some(f);
            break;
        }
    }
    // Name -> relative path, the first directory that has the name.
    let mut found: Vec<(Vec<u8>, PathBuf)> = Vec::new();
    for dir in DROP_IN_DIRS {
        let entries = match fs::read_dir(root.join(dir)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cannot read /{dir}: {e}")),
        };
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read /{dir}: {e}"))?;
            let name = entry.file_name();
            let bytes = name.as_encoded_bytes();
            if bytes.ends_with(b".conf") && !found.iter().any(|(n, _)| n == bytes) {
                found.push((bytes.to_vec(), Path::new(dir).join(&name)));
            }
        }
    }
    found.sort();
    for (_, rel) in found {
        let rel = rel.to_string_lossy().into_owned();
        // The file may have gone since the listing: that is a missing file too.
        if let Some(f) = read_text(root, &rel)? {
            files.drop_ins.push(f);
        }
    }
    Ok(files)
}

/// `stat` of the journal directory under `root`.
#[must_use]
pub fn stat_journal_dir(root: &Path) -> JournalDir {
    match fs::metadata(root.join(JOURNAL_DIR)) {
        Ok(m) if m.is_dir() => JournalDir::Directory,
        Ok(_) => JournalDir::NotDirectory,
        Err(e) if e.kind() == io::ErrorKind::NotFound => JournalDir::Missing,
        Err(e) => JournalDir::Error(e.to_string()),
    }
}

/// Entry point of the fuzz target: no input may crash the reader of the configuration.
///
/// # Panics
/// When an invariant breaks: that is what the fuzz target looks for.
#[must_use]
pub fn fuzz_journald_conf(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let items = parse(&text);
    let lines = text.lines().count();
    assert!(items.iter().all(|i| match i {
        Item::Assigned(_, n) | Item::Invalid(n) | Item::Continued(n) => *n >= 1 && *n <= lines,
    }));
    let file = File {
        name: "/etc/systemd/journald.conf".to_owned(),
        text: text.into_owned(),
    };
    let files = Files {
        main: Some(file.clone()),
        drop_ins: vec![file],
    };
    let verdict = evaluate(&files, &JournalDir::Missing);
    // An invalid value never gives an answer.
    if items.iter().any(|i| matches!(i, Item::Invalid(_))) {
        assert!(matches!(verdict, Verdict::CouldNot(_)));
    }
    matches!(verdict, Verdict::Persistent(_))
}
