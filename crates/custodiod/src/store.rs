//! Key store: one record file per key, kept in a private directory per owner uid:
//! `<root>/<uid>/<id>`. The file is a [`Record`]: owner, id, [`Kind`], certificate and the protected
//! key. The write API takes only a [`Record`], which holds a [`Protected`] key and nothing else, so
//! no plaintext key reaches a file, a temporary one included.
//!
//! Every directory is `0700` and every file `0600`. A record is written to a temporary file in the
//! same directory, synced, then linked into place, so a reader never sees a partial record and an
//! existing record is never overwritten. A file of the earlier format (no magic) is recognised and
//! never read.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, OFlags};

mod error;
mod files;
mod kind;
mod legacy;
mod record;

pub use error::StoreError;
use files::{TMP_PREFIX, remove_temp_files, removed_by_us, sync_dir, tmp_path, write_synced};
pub use kind::Kind;
pub use legacy::LegacyEntry;
pub use record::{Field, MAX_RECORD, Protected, Record, RecordError};

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

    /// Store `record` for its owner under its id, atomically and without overwriting. The record is
    /// checked again first, so nothing is created for one that is not well formed.
    ///
    /// # Errors
    /// `AlreadyExists` if the owner already has this id, `Record` for a record that fails its checks,
    /// `Io` otherwise.
    pub fn put(&self, record: &Record) -> Result<(), StoreError> {
        self.put_with_hook(record, |_| Ok(()))
    }

    /// [`Self::put`] with `between` run on the temporary file after it is written and before it is
    /// linked into place; if it fails, nothing is linked. Lets a test look at the file in between.
    ///
    /// # Errors
    /// The errors of [`Self::put`]; the failure of `between`, as `Io`.
    #[doc(hidden)]
    pub fn put_with_hook(
        &self,
        record: &Record,
        between: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let data = record.encode().map_err(|e| match e {
            RecordError::BadId => StoreError::InvalidId,
            e => StoreError::Record(e),
        })?;
        let area = self.ensure_area(record.owner())?;
        let dest = area.join(record.id());
        let tmp = tmp_path(&area);
        let result = write_synced(&tmp, &data)
            .and_then(|()| between(&tmp))
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
        sync_dir(&area)
    }

    /// Opens the file of `owner`'s `id` and applies the file rules, without reading it: a plain file
    /// of the service uid with mode `0600`, symlinks not followed, a FIFO never blocking.
    fn open_checked(&self, owner: u32, id: &str) -> Result<(PathBuf, File), StoreError> {
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
        Ok((path, file))
    }

    /// Whether `owner` has a file under `id` that passes the file rules. The content is not read, so
    /// this is true of a record that no longer parses and of a file of the earlier format.
    ///
    /// # Errors
    /// The area and file errors of `get`, except `NotFound`, which is `Ok(false)`.
    pub fn contains(&self, owner: u32, id: &str) -> Result<bool, StoreError> {
        match self.open_checked(owner, id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Read the record `owner` stored under `id`.
    ///
    /// # Errors
    /// `NotFound`; `BadPermissions`, `BadOwner` or `BadFileType` if the area or the file is not
    /// as required (a plain `0700` directory / `0600` file owned by the service uid, symlinks not
    /// followed); `Legacy` for a file of the earlier format, which is not read past its first
    /// bytes; `TooLarge`, `Record` or `Mismatch` for a file that is not a well-formed record of
    /// this owner and id; `Io` otherwise.
    pub fn get(&self, owner: u32, id: &str) -> Result<Record, StoreError> {
        let (path, file) = self.open_checked(owner, id)?;
        let mut magic = Vec::with_capacity(record::MAGIC.len());
        (&file)
            .take(record::MAGIC.len() as u64)
            .read_to_end(&mut magic)?;
        if magic.as_slice() != record::MAGIC.as_slice() {
            return Err(StoreError::Legacy);
        }
        // Only a file with the magic is read on. One byte more than the bound tells a file that is
        // too large from one that is not.
        let mut bytes = Vec::new();
        (&file).rewind()?;
        (&file)
            .take(MAX_RECORD as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD {
            return Err(StoreError::TooLarge);
        }
        let record = Record::decode(&bytes).map_err(StoreError::Record)?;
        if record.owner() != owner || record.id() != id {
            return Err(StoreError::Mismatch(path));
        }
        Ok(record)
    }

    /// Takes the exclusive lock of the area of `owner` (`flock` on the directory), held until the
    /// returned handle is dropped. Remove and replace take it, so a replace cannot recreate a record
    /// that a remove has just deleted.
    fn lock_area(area: &Path) -> Result<File, StoreError> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(
                OFlags::DIRECTORY
                    .union(OFlags::NOFOLLOW)
                    .union(OFlags::CLOEXEC)
                    .bits()
                    .cast_signed(),
            )
            .open(area)?;
        rustix::fs::flock(&dir, FlockOperation::LockExclusive).map_err(io::Error::from)?;
        Ok(dir)
    }

    /// Remove the key `owner` stored under `id`. A missing key or area is not an error and creates
    /// nothing. Used to undo an import whose journal entry could not be written.
    ///
    /// # Errors
    /// `InvalidId`; `BadFileType` or `BadOwner` for a file that is not a plain file of the service
    /// uid (a symlink is never followed or removed); `Io` otherwise.
    pub fn remove(&self, owner: u32, id: &str) -> Result<(), StoreError> {
        self.remove_existing(owner, id).map(|_| ())
    }

    /// Like [`Self::remove`], but tells whether this call removed the file: `Ok(false)` when there
    /// was none, so of two callers removing the same file only one gets `Ok(true)`. The file rules
    /// apply but the content is not parsed, so a record that no longer parses can still be removed.
    ///
    /// # Errors
    /// The same as [`Self::remove`].
    pub fn remove_existing(&self, owner: u32, id: &str) -> Result<bool, StoreError> {
        if !valid_key_id(id) {
            return Err(StoreError::InvalidId);
        }
        let Some(area) = self.existing_area(owner)? else {
            return Ok(false);
        };
        let _lock = Self::lock_area(&area)?;
        // `open_checked` refuses what is not a plain file of the service uid, without following
        // symlinks, so `remove_file` below only ever sees a file this store wrote.
        match self.open_checked(owner, id) {
            Ok(_) => {}
            Err(StoreError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        }
        if !removed_by_us(fs::remove_file(area.join(id)))? {
            return Ok(false);
        }
        sync_dir(&area)?;
        Ok(true)
    }

    /// Replace the certificate of the existing record `owner` stored under `id`, atomically: the
    /// whole new record (kind and protected key unchanged) is written to a temporary file in the
    /// same directory and synced, then renamed over the target, then the directory is synced. A
    /// reader sees the old or the new record, never neither. It never creates a record and holds
    /// the area lock, so a concurrent remove cannot be undone by it. Gives back the old certificate.
    ///
    /// # Errors
    /// `NotFound` if there is no such record; the errors of `get` for a target that is not a plain
    /// `0600` record of the service uid; `Record` for a certificate that is empty or over its bound;
    /// `SyncFailed` if the new record is in place but the directory could not be synced; `Io`
    /// otherwise. A failure leaves the old record and no temporary file.
    pub fn replace_certificate(
        &self,
        owner: u32,
        id: &str,
        certificate: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        self.replace_with(owner, id, certificate, || Ok(()))
    }

    /// [`Self::replace_certificate`] with `before_rename` run after the temporary file is written and
    /// before the rename; if it fails, nothing is renamed. Lets a test look at the moment between.
    fn replace_with(
        &self,
        owner: u32,
        id: &str,
        certificate: &[u8],
        before_rename: impl FnOnce() -> io::Result<()>,
    ) -> Result<Vec<u8>, StoreError> {
        if !valid_key_id(id) {
            return Err(StoreError::InvalidId);
        }
        let area = self.existing_area(owner)?.ok_or(StoreError::NotFound)?;
        let _lock = Self::lock_area(&area)?;
        // `get` refuses what is not a plain file of the service uid, so `rename` below only ever
        // replaces a file this store wrote.
        let old = self.get(owner, id)?;
        let data = old
            .with_certificate(certificate)
            .and_then(|new| new.encode())
            .map_err(StoreError::Record)?;
        let tmp = tmp_path(&area);
        let result = write_synced(&tmp, &data)
            .and_then(|()| before_rename())
            .and_then(|()| fs::rename(&tmp, area.join(id)));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        sync_dir(&area)?;
        Ok(old.certificate().to_vec())
    }

    /// The names in the area of `owner` that can be ids, sorted: not temporary files, not other entries.
    fn names(area: &Path) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(area)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str()
                && !name.starts_with(TMP_PREFIX)
                && valid_key_id(name)
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Whether the file `name` of `owner` starts with the magic. Reads no more than the magic.
    fn is_record(&self, owner: u32, name: &str) -> Result<bool, StoreError> {
        let (_, file) = self.open_checked(owner, name)?;
        let mut head = Vec::with_capacity(record::MAGIC.len());
        (&file)
            .take(record::MAGIC.len() as u64)
            .read_to_end(&mut head)?;
        Ok(head.as_slice() == record::MAGIC.as_slice())
    }

    /// The ids in the area of `owner`, sorted: every file that can be a key, whatever its format. An
    /// owner without an area has none; nothing is created. No file is opened, so a file that breaks
    /// the rules shows up here and is refused by `get`; a file of the earlier format also shows up
    /// here, `get` answers `Legacy` for it, and [`Self::legacy`] lists those.
    ///
    /// # Errors
    /// `Io` if the area cannot be read; the area errors of `get`.
    pub fn list(&self, owner: u32) -> Result<Vec<String>, StoreError> {
        let Some(area) = self.existing_area(owner)? else {
            return Ok(Vec::new());
        };
        Self::names(&area)
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

#[cfg(test)]
mod tests;
