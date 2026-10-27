//! Key store: one plain file per key in a private state directory.
//!
//! The directory is `0700` and every file `0600`. A key is written to a temporary file in the
//! same directory, synced, then linked into place, so a reader never sees a partial key and an
//! existing key is never overwritten.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// The state path or a key file is not owned by the current user, or is not a plain file/dir.
    BadFileType(PathBuf),
    /// The key file is larger than any key we store.
    TooLarge,
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
}

impl KeyStore {
    /// Open the store at `dir`, creating it with mode `0700` if missing.
    ///
    /// An existing directory with any other mode is rejected rather than silently fixed.
    ///
    /// # Errors
    /// Fails if the directory cannot be created or has unsafe permissions.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        match DirBuilder::new().mode(DIR_MODE).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let meta = fs::symlink_metadata(&dir)?;
        if !meta.is_dir() {
            return Err(StoreError::BadFileType(dir));
        }
        if meta.mode() & PERM_MASK != DIR_MODE {
            return Err(StoreError::BadPermissions(dir));
        }
        Ok(Self { dir })
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
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Read the key stored under `id`.
    ///
    /// # Errors
    /// `NotFound`, `BadPermissions` if the file is not `0600`, `Io` otherwise.
    pub fn get(&self, id: &str) -> Result<SecretSlice<u8>, StoreError> {
        let path = self.path_for(id)?;
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(StoreError::BadFileType(path));
        }
        if meta.mode() & PERM_MASK != FILE_MODE {
            return Err(StoreError::BadPermissions(path));
        }
        if meta.len() > MAX_KEY_LEN {
            return Err(StoreError::TooLarge);
        }
        let mut buf = Zeroizing::new(Vec::new());
        file.take(MAX_KEY_LEN).read_to_end(&mut buf)?;
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
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(FILE_MODE))?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    fn secret(bytes: &[u8]) -> SecretSlice<u8> {
        SecretSlice::from(bytes.to_vec())
    }

    fn mode(p: &Path) -> io::Result<u32> {
        Ok(fs::metadata(p)?.mode() & PERM_MASK)
    }

    #[test]
    fn creates_directory_0700() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("state");
        let store = KeyStore::open(&dir)?;
        assert_eq!(mode(store.dir())?, 0o700);
        Ok(())
    }

    #[test]
    fn rejects_existing_directory_with_loose_mode() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("state");
        DirBuilder::new().mode(0o755).create(&dir)?;
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        assert!(matches!(
            KeyStore::open(&dir),
            Err(StoreError::BadPermissions(_))
        ));
        Ok(())
    }

    #[test]
    fn files_are_0600_and_roundtrip() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = KeyStore::open(tmp.path().join("s"))?;
        store.put("k1", &secret(b"hunter2"))?;
        assert_eq!(mode(&store.dir().join("k1"))?, 0o600);
        assert_eq!(store.get("k1")?.expose_secret(), b"hunter2");
        Ok(())
    }

    #[test]
    fn mode_is_exact_under_permissive_umask() -> TestResult {
        // The explicit set_permissions makes the mode independent of the umask.
        let tmp = tempfile::tempdir()?;
        let p = tmp.path().join("f");
        write_synced(&p, b"x")?;
        assert_eq!(mode(&p)?, 0o600);
        Ok(())
    }

    #[test]
    fn put_does_not_overwrite_and_leaves_no_temp_files() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = KeyStore::open(tmp.path().join("s"))?;
        store.put("k", &secret(b"one"))?;
        assert!(matches!(
            store.put("k", &secret(b"two")),
            Err(StoreError::AlreadyExists)
        ));
        assert_eq!(store.get("k")?.expose_secret(), b"one");
        let names: Vec<_> = fs::read_dir(store.dir())?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        assert_eq!(names.len(), 1);
        Ok(())
    }

    #[test]
    fn rejects_bad_ids() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = KeyStore::open(tmp.path().join("s"))?;
        for id in ["", "..", "a/b", ".hidden", "a b", &"x".repeat(65)] {
            assert!(matches!(
                store.put(id, &secret(b"x")),
                Err(StoreError::InvalidId)
            ));
            assert!(matches!(store.get(id), Err(StoreError::InvalidId)));
        }
        Ok(())
    }

    #[test]
    fn get_rejects_loose_file_mode_and_missing() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = KeyStore::open(tmp.path().join("s"))?;
        assert!(matches!(store.get("nope"), Err(StoreError::NotFound)));
        store.put("k", &secret(b"x"))?;
        let p = store.dir().join("k");
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        assert!(matches!(store.get("k"), Err(StoreError::BadPermissions(_))));
        Ok(())
    }

    #[test]
    fn list_is_sorted_and_skips_temp_files() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = KeyStore::open(tmp.path().join("s"))?;
        store.put("b", &secret(b"1"))?;
        store.put("a", &secret(b"2"))?;
        fs::write(store.dir().join(".tmp-1-1"), b"partial")?;
        assert_eq!(store.list()?, ["a", "b"]);
        Ok(())
    }

    #[test]
    fn debug_never_prints_key_material() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = KeyStore::open(tmp.path().join("s"))?;
        let key = secret(b"SUPERSECRET");
        store.put("k", &key)?;
        let got = store.get("k")?;
        for out in [format!("{key:?}"), format!("{got:?}"), format!("{store:?}")] {
            assert!(!out.contains("SUPERSECRET"));
            assert!(!out.contains("83, 85, 80")); // the bytes as a decimal list
        }
        let errs = [
            StoreError::InvalidId,
            StoreError::BadPermissions(PathBuf::from("/x")),
        ];
        for e in errs {
            assert!(!format!("{e:?} {e}").contains("SUPERSECRET"));
        }
        Ok(())
    }
}
