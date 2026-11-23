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

/// Why the answer is [`StateStorage::Unknown`]: one value per group of causes (`docs/findings/F189.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    /// No mount covers the state directory, or the mount table cannot be read.
    NoMount,
    /// The covering mount is not a filesystem on one block device (tmpfs, overlay, network, anonymous device).
    NotBlockFilesystem,
    /// The sysfs chain is missing or incomplete: a node, `dm/uuid` or `slaves/` cannot be read, the shape of a
    /// partition is wrong, or the chain loops or is too deep.
    SysfsIncomplete,
    /// A layer the service does not classify: RAID that is not all encrypted, a dm target other than LVM and
    /// dm-crypt, a disk without a hardware link or with devices stacked on it.
    LayerNotClassified,
    /// The members of an LVM or RAID layer do not all give the same answer.
    MembersDisagree,
    /// The filesystem may encrypt the directory itself, or the check failed.
    FscryptNotExcluded,
    /// The state directory itself cannot be resolved.
    StateDirUnresolved,
}

impl UnknownReason {
    /// Every value, in the order of `docs/api.md`.
    pub const ALL: [Self; 7] = [
        Self::NoMount,
        Self::NotBlockFilesystem,
        Self::SysfsIncomplete,
        Self::LayerNotClassified,
        Self::MembersDisagree,
        Self::FscryptNotExcluded,
        Self::StateDirUnresolved,
    ];

    /// The value on the bus.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoMount => "no-mount",
            Self::NotBlockFilesystem => "not-block-filesystem",
            Self::SysfsIncomplete => "sysfs-incomplete",
            Self::LayerNotClassified => "layer-not-classified",
            Self::MembersDisagree => "members-disagree",
            Self::FscryptNotExcluded => "fscrypt-not-excluded",
            Self::StateDirUnresolved => "state-dir-unresolved",
        }
    }
}

/// The verdict and, for `unknown` only, its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnosis {
    storage: StateStorage,
    reason: Option<UnknownReason>,
}

impl Default for Diagnosis {
    /// What a service that was not told anything answers: `unknown`, with no mount found.
    fn default() -> Self {
        Self::unknown(UnknownReason::NoMount)
    }
}

impl Diagnosis {
    /// An `unknown` with its reason.
    #[must_use]
    pub const fn unknown(reason: UnknownReason) -> Self {
        Self {
            storage: StateStorage::Unknown,
            reason: Some(reason),
        }
    }

    /// A proven answer: no reason.
    #[must_use]
    pub const fn proven(found: Found) -> Self {
        Self {
            storage: match found {
                Found::Encrypted => StateStorage::Encrypted,
                Found::NotEncrypted => StateStorage::NotEncrypted,
            },
            reason: None,
        }
    }

    /// The wire value of the reason: empty when there is none.
    #[must_use]
    pub const fn reason_name(self) -> &'static str {
        match self.reason {
            Some(reason) => reason.name(),
            None => "",
        }
    }

    #[must_use]
    pub const fn storage(self) -> StateStorage {
        self.storage
    }

    /// `Some` exactly when [`Self::storage`] is `unknown`.
    #[must_use]
    pub const fn reason(self) -> Option<UnknownReason> {
        self.reason
    }
}

/// A proven chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    Encrypted,
    NotEncrypted,
}

type Walked = Result<Found, UnknownReason>;

/// The production entry point: classifies the real `/` for the directory systemd names in `STATE_DIRECTORY`
/// (the default when unset is the unit's own, `/var/lib/custodio`).
#[must_use]
pub fn classify_state_dir(state_directory: Option<OsString>) -> StateStorage {
    diagnose_state_dir(state_directory).storage
}

/// [`classify_state_dir`] with the reason of an `unknown`. Only `main` calls it.
#[must_use]
pub fn diagnose_state_dir(state_directory: Option<OsString>) -> Diagnosis {
    let dir = state_directory.unwrap_or_else(|| OsString::from(DEFAULT_STATE_DIR));
    // `STATE_DIRECTORY` may hold several directories separated by ':'; the unit has one.
    diagnose_with(Path::new("/"), Path::new(&dir), &has_fscrypt)
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
    diagnose_with(root, state_dir, fscrypt).storage
}

/// [`classify_with`] with the reason of an `unknown`.
#[must_use]
pub fn diagnose_with(
    root: &Path,
    state_dir: &Path,
    fscrypt: &dyn Fn(&Path) -> io::Result<bool>,
) -> Diagnosis {
    match chain(root, state_dir, fscrypt) {
        Ok(found) => Diagnosis::proven(found),
        Err(reason) => Diagnosis::unknown(reason),
    }
}

fn chain(root: &Path, state_dir: &Path, fscrypt: &dyn Fn(&Path) -> io::Result<bool>) -> Walked {
    let dir = fs::canonicalize(state_dir).map_err(|_| UnknownReason::StateDirUnresolved)?;
    let device = mounted_device(root, &dir)?;
    let node = root.join("sys/dev/block").join(device);
    let node = fs::canonicalize(node).map_err(|_| UnknownReason::SysfsIncomplete)?;
    let found = walk(&node, &mut Vec::new())?;
    if found == Found::NotEncrypted && !matches!(fscrypt(&dir), Ok(false)) {
        // The filesystem may encrypt this directory itself, or the check failed: not proven either way.
        return Err(UnknownReason::FscryptNotExcluded);
    }
    Ok(found)
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
fn mounted_device(root: &Path, dir: &Path) -> Result<String, UnknownReason> {
    let table =
        fs::read_to_string(root.join("proc/self/mountinfo")).map_err(|_| UnknownReason::NoMount)?;
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
    let (_, mount) = best.ok_or(UnknownReason::NoMount)?;
    let usable = BLOCK_FILESYSTEMS.contains(&mount.fstype) && !mount.device.starts_with("0:");
    if usable {
        Ok(mount.device.to_owned())
    } else {
        Err(UnknownReason::NotBlockFilesystem)
    }
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
fn walk(node: &Path, path: &mut Vec<PathBuf>) -> Walked {
    if path.len() >= MAX_DEPTH || path.iter().any(|p| p == node) {
        return Err(UnknownReason::SysfsIncomplete);
    }
    path.push(node.to_owned());
    let verdict = walk_node(node, path);
    path.pop();
    verdict
}

fn walk_node(node: &Path, path: &mut Vec<PathBuf>) -> Walked {
    if node.join("dm").is_dir() {
        let uuid =
            fs::read_to_string(node.join("dm/uuid")).map_err(|_| UnknownReason::SysfsIncomplete)?;
        let uuid = uuid.trim_end();
        if uuid.is_empty() {
            return Err(UnknownReason::SysfsIncomplete);
        }
        if CRYPT_PREFIXES.iter().any(|p| uuid.starts_with(p)) {
            return Ok(Found::Encrypted);
        }
        if uuid.starts_with(LVM_PREFIX) {
            return members(node, path, false);
        }
        return Err(UnknownReason::LayerNotClassified);
    }
    if node.join("md").is_dir() {
        // Only a set whose every member is encrypted is proven; plain RAID is not classified.
        return members(node, path, true);
    }
    if node.join("partition").is_file() {
        let disk = node.parent().ok_or(UnknownReason::SysfsIncomplete)?;
        return if disk.join("dev").is_file() && !disk.join("partition").exists() {
            walk(disk, path)
        } else {
            Err(UnknownReason::SysfsIncomplete)
        };
    }
    // The kernel names a device-mapper node `dm-<minor>`; without its `dm/` directory it is still being set up
    // (`slaves/` is filled before `dm/` appears), not a layer of another kind.
    if node
        .file_name()
        .is_some_and(|n| n.as_encoded_bytes().starts_with(b"dm-"))
    {
        return Err(UnknownReason::SysfsIncomplete);
    }
    // A physical disk: a hardware `device` link, nothing stacked on it (loop, zram and nbd have no such link).
    let stacked = fs::read_dir(node.join("slaves")).is_ok_and(|mut d| d.next().is_some());
    if node.join("device").exists() && node.join("dev").is_file() && !stacked {
        Ok(Found::NotEncrypted)
    } else {
        Err(UnknownReason::LayerNotClassified)
    }
}

/// The verdict over `node/slaves`: all members the same, else unknown. `only_encrypted` turns *not encrypted* into
/// *unknown* (md).
fn members(node: &Path, path: &mut Vec<PathBuf>, only_encrypted: bool) -> Walked {
    let dir = fs::read_dir(node.join("slaves")).map_err(|_| UnknownReason::SysfsIncomplete)?;
    let mut seen: Option<Found> = None;
    for entry in dir {
        let entry = entry.map_err(|_| UnknownReason::SysfsIncomplete)?;
        let member = fs::canonicalize(entry.path()).map_err(|_| UnknownReason::SysfsIncomplete)?;
        let found = walk(&member, path)?;
        match seen {
            None => seen = Some(found),
            Some(first) if first == found => {}
            Some(_) => return Err(UnknownReason::MembersDisagree),
        }
    }
    match seen {
        Some(Found::NotEncrypted) if only_encrypted => Err(UnknownReason::LayerNotClassified),
        Some(v) => Ok(v),
        None => Err(UnknownReason::SysfsIncomplete),
    }
}
