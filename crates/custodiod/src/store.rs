//! Key store: one plain file per key in a private state directory.
//!
//! The directory is `0700` and every file `0600`. A key is written to a temporary file in the
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
}

impl KeyStore {
    /// Open the store at `dir`, creating it with mode `0700` if missing.
    ///
    /// An existing directory with any other mode, or an owner other than the effective uid, is
    /// rejected rather than silently fixed. Leftover `.tmp-*` files from a crashed `put` are
    /// removed, so only one process may use a state directory at a time.
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
        let meta = fs::symlink_metadata(&dir)?;
        if !meta.is_dir() {
            return Err(StoreError::BadFileType(dir));
        }
        if meta.mode() & PERM_MASK != DIR_MODE {
            return Err(StoreError::BadPermissions(dir));
        }
        if meta.uid() != uid {
            return Err(StoreError::BadOwner(dir));
        }
        let store = Self { dir, uid };
        store.remove_stale_temp_files()?;
        Ok(store)
    }

    fn remove_stale_temp_files(&self) -> Result<(), StoreError> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(TMP_PREFIX)
                && entry.file_type()?.is_file()
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// Directory this store lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, id: &str) -> Result<PathBuf, StoreError> {
        let valid = !id.is_empty()
            && id.len() <= MAX_ID_LEN
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if valid {
            Ok(self.dir.join(id))
        } else {
            Err(StoreError::InvalidId)
        }
    }

    /// Store `key` under `id`, atomically and without overwriting.
    ///
    /// # Errors
    /// `AlreadyExists` if the id is taken, `InvalidId` for a bad id, `Io` otherwise.
    pub fn put(&self, id: &str, key: &SecretSlice<u8>) -> Result<(), StoreError> {
        let dest = self.path_for(id)?;
        let tmp = self.dir.join(format!(
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
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(StoreError::SyncFailed)
    }

    /// Read the key stored under `id`.
    ///
    /// # Errors
    /// `NotFound`; `BadPermissions`, `BadOwner` or `BadFileType` if the file is not a regular
    /// `0600` file owned by the service uid (symlinks are not followed); `Io` otherwise.
    pub fn get(&self, id: &str) -> Result<SecretSlice<u8>, StoreError> {
        let path = self.path_for(id)?;
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
        if meta.uid() != self.uid {
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

    /// Ids of all stored keys, sorted.
    ///
    /// # Errors
    /// `Io` if the directory cannot be read.
    pub fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str()
                && !name.starts_with(TMP_PREFIX)
                && self.path_for(name).is_ok()
            {
                ids.push(name.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }
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
