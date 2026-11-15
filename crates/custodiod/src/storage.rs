//! Is the state directory on an encrypted device? (SPEC Design 7, `docs/findings/F180.md`.)
//!
//! Read-only and tool-free: the mount table, `/sys/dev/block` and the dm uuid. The classifier is pure over a root
//! path, so a fixture tree stands in for `/proc` and `/sys`. Anything not proven to be dm-crypt is
//! [`StateStorage::Unknown`]; no read error, loop or odd shape is ever reported as encrypted.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, CWD, StatxAttributes, StatxFlags, statx};

/// What the service found about the storage of its state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateStorage {
    /// Every path to the physical devices goes through dm-crypt.
    Encrypted,
    /// A chain read completely, ending at physical devices, with no dm-crypt in it.
    NotEncrypted,
    /// Anything else.
    Unknown,
}

impl StateStorage {
    /// The value on the bus and in the journal.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::NotEncrypted => "not-encrypted",
            Self::Unknown => "unknown",
        }
    }

    /// The three values.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Encrypted, Self::NotEncrypted, Self::Unknown]
    }
}

/// Filesystems that live on one block device whose number the mount table gives.
const BLOCK_FILESYSTEMS: [&str; 8] = [
    "ext2", "ext3", "ext4", "xfs", "f2fs", "jfs", "vfat", "exfat",
];
/// Deepest chain followed.
const MAX_DEPTH: usize = 16;
/// The dm uuid prefix of dm-crypt (cryptsetup).
/// dm uuid prefixes of the types in which cryptsetup 2.7.5 (`lib/libdevmapper.c` `dm_prepare_uuid`) creates a dm-crypt
/// target. Every cryptsetup device starts with `CRYPT-<type>-`, also `INTEGRITY`, `VERITY`, `SUBDEV` and `TEMP`, which
/// encrypt nothing, so the bare `CRYPT-` prefix is not proof.
const CRYPT_PREFIXES: [&str; 3] = ["CRYPT-LUKS1-", "CRYPT-LUKS2-", "CRYPT-PLAIN-"];
/// The dm uuid prefix of LVM.
const LVM_PREFIX: &str = "LVM-";
const DEFAULT_STATE_DIR: &str = "/var/lib/custodio";

/// The production entry point: classifies the real `/` for the directory systemd names in `STATE_DIRECTORY`
/// (the default when unset is the unit's own, `/var/lib/custodio`). Only `main` calls it.
#[must_use]
pub fn classify_state_dir(state_directory: Option<OsString>) -> StateStorage {
    let dir = state_directory.unwrap_or_else(|| OsString::from(DEFAULT_STATE_DIR));
    // `STATE_DIRECTORY` may hold several directories separated by ':'; the unit has one.
    classify(Path::new("/"), Path::new(&dir))
}

/// Classifies `state_dir` over `root` (`root/proc/self/mountinfo`, `root/sys/dev/block`). The directory itself is
/// resolved on the running system.
#[must_use]
pub fn classify(root: &Path, state_dir: &Path) -> StateStorage {
    classify_with(root, state_dir, &has_fscrypt)
}

/// [`classify`] with the fscrypt check given (a fixture directory cannot carry the attribute).
#[must_use]
pub fn classify_with(
    root: &Path,
    state_dir: &Path,
    fscrypt: &dyn Fn(&Path) -> io::Result<bool>,
) -> StateStorage {
    let Ok(dir) = fs::canonicalize(state_dir) else {
        return StateStorage::Unknown;
    };
    let Some(device) = mounted_device(root, &dir) else {
        return StateStorage::Unknown;
    };
    let node = root.join("sys/dev/block").join(device);
    let Ok(node) = fs::canonicalize(node) else {
        return StateStorage::Unknown;
    };
    let verdict = walk(&node, &mut Vec::new());
    if verdict == StateStorage::NotEncrypted && !matches!(fscrypt(&dir), Ok(false)) {
        // The filesystem may encrypt this directory itself, or the check failed: not proven either way.
        return StateStorage::Unknown;
    }
    verdict
}

/// Whether the filesystem marks `dir` as fscrypt-encrypted. A filesystem that cannot (mask lacks the bit) is `false`.
///
/// # Errors
/// The `statx` error.
pub fn has_fscrypt(dir: &Path) -> io::Result<bool> {
    let stat = statx(CWD, dir, AtFlags::empty(), StatxFlags::empty())?;
    Ok(fscrypt_flag(stat.stx_attributes_mask, stat.stx_attributes))
}

/// The fscrypt bit of a `statx` answer: set, and the filesystem able to say.
#[must_use]
pub fn fscrypt_flag(mask: StatxAttributes, attributes: StatxAttributes) -> bool {
    mask.contains(StatxAttributes::ENCRYPTED) && attributes.contains(StatxAttributes::ENCRYPTED)
}

/// `major:minor` of the filesystem that holds `dir`, when its type is on the block list.
fn mounted_device(root: &Path, dir: &Path) -> Option<String> {
    let table = fs::read_to_string(root.join("proc/self/mountinfo")).ok()?;
    let mut best: Option<(usize, Mount)> = None;
    for mount in table.lines().filter_map(Mount::parse) {
        if !dir.starts_with(&mount.point) {
            continue;
        }
        let depth = mount.point.components().count();
        // The later entry of the same point is the one on top.
        if best.as_ref().is_none_or(|(d, _)| depth >= *d) {
            best = Some((depth, mount));
        }
    }
    let (_, mount) = best?;
    let usable = BLOCK_FILESYSTEMS.contains(&mount.fstype) && !mount.device.starts_with("0:");
    usable.then(|| mount.device.to_owned())
}

struct Mount<'a> {
    device: &'a str,
    point: PathBuf,
    fstype: &'a str,
}

impl<'a> Mount<'a> {
    /// `id parent maj:min root point options [optional...] - fstype source super-options`.
    fn parse(line: &'a str) -> Option<Self> {
        let fields: Vec<&str> = line.split(' ').collect();
        let dash = fields.iter().position(|f| *f == "-")?;
        Some(Self {
            device: fields.get(2)?,
            point: PathBuf::from(unescape(fields.get(4)?)),
            fstype: fields.get(dash + 1)?,
        })
    }
}

/// The kernel writes space, tab, newline and backslash as `\040`, `\011`, `\012`, `\134`.
fn unescape(field: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let mut out = Vec::with_capacity(field.len());
    let mut rest = field.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        let octal = tail
            .get(..3)
            .filter(|d| b == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)))
            .and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok());
        if let Some(byte) = octal {
            out.push(byte);
            rest = tail.get(3..).unwrap_or_default();
        } else {
            out.push(b);
            rest = tail;
        }
    }
    OsString::from_vec(out)
}

/// The verdict for the device whose sysfs directory is `node`; `path` holds the directories being followed.
fn walk(node: &Path, path: &mut Vec<PathBuf>) -> StateStorage {
    if path.len() >= MAX_DEPTH || path.iter().any(|p| p == node) {
        return StateStorage::Unknown;
    }
    path.push(node.to_owned());
    let verdict = walk_node(node, path);
    path.pop();
    verdict
}

fn walk_node(node: &Path, path: &mut Vec<PathBuf>) -> StateStorage {
    if node.join("dm").is_dir() {
        let Ok(uuid) = fs::read_to_string(node.join("dm/uuid")) else {
            return StateStorage::Unknown;
        };
        let uuid = uuid.trim_end();
        if CRYPT_PREFIXES.iter().any(|p| uuid.starts_with(p)) {
            return StateStorage::Encrypted;
        }
        if uuid.starts_with(LVM_PREFIX) {
            return members(node, path, false);
        }
        return StateStorage::Unknown;
    }
    if node.join("md").is_dir() {
        // Only a set whose every member is encrypted is proven; plain RAID is not classified.
        return members(node, path, true);
    }
    if node.join("partition").is_file() {
        let Some(disk) = node.parent() else {
            return StateStorage::Unknown;
        };
        return if disk.join("dev").is_file() && !disk.join("partition").exists() {
            walk(disk, path)
        } else {
            StateStorage::Unknown
        };
    }
    // A physical disk: a hardware `device` link, nothing stacked on it (loop, zram and nbd have no such link).
    let stacked = fs::read_dir(node.join("slaves")).is_ok_and(|mut d| d.next().is_some());
    if node.join("device").exists() && node.join("dev").is_file() && !stacked {
        StateStorage::NotEncrypted
    } else {
        StateStorage::Unknown
    }
}

/// The verdict over `node/slaves`: all members the same, else unknown. `only_encrypted` turns *not encrypted* into
/// *unknown* (md).
fn members(node: &Path, path: &mut Vec<PathBuf>, only_encrypted: bool) -> StateStorage {
    let Ok(dir) = fs::read_dir(node.join("slaves")) else {
        return StateStorage::Unknown;
    };
    let mut seen: Option<StateStorage> = None;
    for entry in dir {
        let Ok(entry) = entry else {
            return StateStorage::Unknown;
        };
        let Ok(member) = fs::canonicalize(entry.path()) else {
            return StateStorage::Unknown;
        };
        let verdict = walk(&member, path);
        match seen {
            None => seen = Some(verdict),
            Some(first) if first == verdict => {}
            Some(_) => return StateStorage::Unknown,
        }
    }
    match seen {
        Some(StateStorage::NotEncrypted) if only_encrypted => StateStorage::Unknown,
        Some(v) => v,
        None => StateStorage::Unknown,
    }
}
