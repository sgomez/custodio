//! Key store: one plain file per key, kept in a private directory per owner uid:
//! `<root>/<uid>/<id>`.
//!
//! Every directory is `0700` and every file `0600`. A key is written to a temporary file in the
//! same directory, synced, then linked into place, so a reader never sees a partial key and an
//! existing key is never overwritten.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::OFlags;
use secrecy::{ExposeSecret, SecretSlice};
use zeroize::Zeroizing;

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const PERM_MASK: u32 = 0o777;
const MAX_ID_LEN: usize = 64;
/// The rule for a key id: 1 to `MAX_ID_LEN` bytes of `[A-Za-z0-9_-]`. The audit `KeyId` uses it too.
pub(crate) fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

const MAX_KEY_LEN: u64 = 64 * 1024;
const TMP_PREFIX: &str = ".tmp-";

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors from the key store. Messages never contain key material.
#[derive(Debug)]
pub enum StoreError {
    /// The key id is empty, too long or has characters outside `[A-Za-z0-9_-]`.
    InvalidId,
    /// A key with this id already exists.
    AlreadyExists,
    /// No key with this id.
    NotFound,
    /// The state directory or a key file has a mode other than the required one.
    BadPermissions(PathBuf),
    /// The state path or a key file is not a plain directory/file (symlinks are rejected).
    BadFileType(PathBuf),
    /// The state path or a key file is not owned by the service uid.
    BadOwner(PathBuf),
    /// The key file is larger than any key we store.
    TooLarge,
    /// The key was stored, but syncing the directory failed, so durability is unconfirmed.
    /// Retrying `put` yields `AlreadyExists`; use `get` to check the key.
    SyncFailed(io::Error),
    /// Underlying I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId => f.write_str("invalid key id"),
            Self::AlreadyExists => f.write_str("key already exists"),
            Self::NotFound => f.write_str("key not found"),
            Self::BadPermissions(p) => write!(f, "unsafe permissions on {}", p.display()),
            Self::BadFileType(p) => write!(f, "unexpected file type at {}", p.display()),
            Self::BadOwner(p) => write!(f, "unexpected owner of {}", p.display()),
            Self::SyncFailed(e) => write!(f, "key stored but directory sync failed: {e}"),
            Self::TooLarge => f.write_str("key file too large"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Key store rooted at a state directory.
#[derive(Debug)]
pub struct KeyStore {
    dir: PathBuf,
    uid: u32,
    /// Test seam: the uid expected for key files only, so the file check can fail while the
    /// directory checks pass.
    #[cfg(test)]
    file_uid: Option<u32>,
}

impl KeyStore {
    /// Open the store at `dir`, creating it with mode `0700` if missing.
    ///
    /// An existing directory with any other mode, or an owner other than the effective uid, is
    /// rejected rather than silently fixed. Leftover `.tmp-*` files from a crashed `put` are
    /// removed from the root and from every well-formed owner area, so only one process may use a
    /// state directory at a time. Any other entry in the root is left alone and never read.
    ///
    /// # Errors
    /// Fails if the directory cannot be created or has unsafe permissions or owner.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_as(dir.into(), rustix::process::geteuid().as_raw())
    }

    /// Like `open`, with the expected owner uid given explicitly so tests can exercise the check.
    fn open_as(dir: PathBuf, uid: u32) -> Result<Self, StoreError> {
        match DirBuilder::new().mode(DIR_MODE).create(&dir) {
            // The umask can only remove bits; make the mode exact regardless.
            Ok(()) => fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?,
            Err(e) => {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            }
        }
        check_dir(&dir, uid)?;
        let store = Self {
            dir,
            uid,
            #[cfg(test)]
            file_uid: None,
        };
        store.remove_stale_temp_files()?;
        Ok(store)
    }

    fn remove_stale_temp_files(&self) -> Result<(), StoreError> {
        remove_temp_files(&self.dir)?;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let is_area = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok().map(|u| (u, n.to_owned())))
                .is_some_and(|(u, n)| u.to_string() == n);
            // Only a well-formed area is touched; anything else is left for `get`/`put` to refuse.
            if is_area && check_dir(&entry.path(), self.uid).is_ok() {
                remove_temp_files(&entry.path())?;
            }
        }
        Ok(())
    }

    /// Directory this store lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The area of `owner`: `<root>/<uid in decimal>`. The name is derived from the `u32` alone,
    /// so no id can reach another owner's area.
    fn area_path(&self, owner: u32) -> PathBuf {
        self.dir.join(owner.to_string())
    }

    /// The checked area of `owner`, or `None` if it does not exist. Creates nothing.
    fn existing_area(&self, owner: u32) -> Result<Option<PathBuf>, StoreError> {
        let area = self.area_path(owner);
        match check_dir(&area, self.uid) {
            Ok(()) => Ok(Some(area)),
            Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The checked area of `owner`, created with mode `0700` if missing.
    fn ensure_area(&self, owner: u32) -> Result<PathBuf, StoreError> {
        let area = self.area_path(owner);
        // Any failure to create (already there, missing root, no permission) is judged by
        // `check_dir` below, which looks at what is actually on disk.
        if DirBuilder::new().mode(DIR_MODE).create(&area).is_ok() {
            // The umask can only remove bits; make the mode exact regardless.
            fs::set_permissions(&area, fs::Permissions::from_mode(DIR_MODE))?;
            File::open(&self.dir)
                .and_then(|d| d.sync_all())
                .map_err(StoreError::SyncFailed)?;
        }
        check_dir(&area, self.uid)?;
        Ok(area)
    }

    /// Store `key` for `owner` under `id`, atomically and without overwriting.
    ///
    /// # Errors
    /// `AlreadyExists` if the owner already has this id, `InvalidId` for a bad id, `Io` otherwise.
    pub fn put(&self, owner: u32, id: &str, key: &SecretSlice<u8>) -> Result<(), StoreError> {
        if !valid_key_id(id) {
            return Err(StoreError::InvalidId);
        }
        let area = self.ensure_area(owner)?;
        let dest = area.join(id);
        let tmp = area.join(format!(
            "{TMP_PREFIX}{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = write_synced(&tmp, key.expose_secret())
            // `hard_link` fails if `dest` exists, so this is atomic and never overwrites.
            .and_then(|()| fs::hard_link(&tmp, &dest));
        let _ = fs::remove_file(&tmp);
        result.map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                StoreError::AlreadyExists
            } else {
                StoreError::Io(e)
            }
        })?;
        File::open(&area)
            .and_then(|d| d.sync_all())
            .map_err(StoreError::SyncFailed)
    }

    /// Read the key `owner` stored under `id`.
    ///
    /// # Errors
    /// `NotFound`; `BadPermissions`, `BadOwner` or `BadFileType` if the area or the file is not
    /// as required (a plain `0700` directory / `0600` file owned by the service uid, symlinks not
    /// followed); `Io` otherwise.
    pub fn get(&self, owner: u32, id: &str) -> Result<SecretSlice<u8>, StoreError> {
        if !valid_key_id(id) {
            return Err(StoreError::InvalidId);
        }
        let path = self
            .existing_area(owner)?
            .ok_or(StoreError::NotFound)?
            .join(id);
        let file = match OpenOptions::new()
            .read(true)
            // NONBLOCK so a FIFO cannot hang the open; NOCTTY so a tty cannot become ours.
            .custom_flags(
                OFlags::NOFOLLOW
                    .union(OFlags::NONBLOCK)
                    .union(OFlags::NOCTTY)
                    .bits()
                    .cast_signed(),
            )
            .open(&path)
        {
            Ok(f) => f,
            // With O_NOFOLLOW a symlink fails with ELOOP.
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
                return Err(StoreError::BadFileType(path));
            }
            Err(e) => {
                return Err(if e.kind() == io::ErrorKind::NotFound {
                    StoreError::NotFound
                } else {
                    e.into()
                });
            }
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(StoreError::BadFileType(path));
        }
        #[cfg(test)]
        let expected = self.file_uid.unwrap_or(self.uid);
        #[cfg(not(test))]
        let expected = self.uid;
        if meta.uid() != expected {
            return Err(StoreError::BadOwner(path));
        }
        if meta.mode() & PERM_MASK != FILE_MODE {
            return Err(StoreError::BadPermissions(path));
        }
        if meta.len() > MAX_KEY_LEN {
            return Err(StoreError::TooLarge);
        }
        // Allocate the exact size up front so the buffer never moves and leaves key bytes behind.
        let len = usize::try_from(meta.len()).map_err(|_| StoreError::TooLarge)?;
        let mut buf = Zeroizing::new(vec![0_u8; len]);
        file.take(meta.len()).read_exact(&mut buf)?;
        Ok(SecretSlice::from(buf.to_vec()))
    }

    /// Remove the key `owner` stored under `id`. A missing key or area is not an error and creates
    /// nothing. Used to undo an import whose journal entry could not be written.
    ///
    /// # Errors
    /// `InvalidId`; `BadFileType` or `BadOwner` for a file that is not a plain file of the service
    /// uid (a symlink is never followed or removed); `Io` otherwise.
    pub fn remove(&self, owner: u32, id: &str) -> Result<(), StoreError> {
        if !valid_key_id(id) {
            return Err(StoreError::InvalidId);
        }
        let Some(area) = self.existing_area(owner)? else {
            return Ok(());
        };
        // `get` refuses what is not a plain file of the service uid, without following symlinks, so
        // `remove_file` below only ever sees a file this store wrote.
        match self.get(owner, id) {
            Ok(_) => {}
            Err(StoreError::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        }
        fs::remove_file(area.join(id))?;
        File::open(&area)
            .and_then(|d| d.sync_all())
            .map_err(StoreError::SyncFailed)
    }

    /// Ids of all keys of `owner`, sorted. An owner without an area has none; nothing is created.
    ///
    /// # Errors
    /// `Io` if the area cannot be read; the area errors of `get`.
    pub fn list(&self, owner: u32) -> Result<Vec<String>, StoreError> {
        let Some(area) = self.existing_area(owner)? else {
            return Ok(Vec::new());
        };
        let mut ids = Vec::new();
        for entry in fs::read_dir(&area)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str()
                && !name.starts_with(TMP_PREFIX)
                && valid_key_id(name)
            {
                ids.push(name.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }
}

/// Check that `path` is a real directory (not a symlink) with mode `0700` owned by `uid`.
/// A missing path is `Io` with kind `NotFound`.
fn check_dir(path: &Path, uid: u32) -> Result<(), StoreError> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(StoreError::BadFileType(path.to_owned()));
    }
    if meta.mode() & PERM_MASK != DIR_MODE {
        return Err(StoreError::BadPermissions(path.to_owned()));
    }
    if meta.uid() != uid {
        return Err(StoreError::BadOwner(path.to_owned()));
    }
    Ok(())
}

fn remove_temp_files(dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(TMP_PREFIX)
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn write_synced(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)?;
    // The umask can only remove bits; make the mode exact regardless.
    f.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests;
