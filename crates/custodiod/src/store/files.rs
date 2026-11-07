//! The file helpers of the key store: temporary files, synced writes, directory syncs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{FILE_MODE, StoreError};

pub(super) const TMP_PREFIX: &str = ".tmp-";

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn tmp_path(area: &Path) -> PathBuf {
    area.join(format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(super) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(StoreError::SyncFailed)
}

/// Whether a `remove_file` removed the file: a file already gone (another remover was faster, in
/// the time since `get`) is `false`, any other failure an error.
pub(super) fn removed_by_us(result: io::Result<()>) -> Result<bool, StoreError> {
    match result {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub(super) fn remove_temp_files(dir: &Path) -> Result<(), StoreError> {
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

pub(super) fn write_synced(path: &Path, data: &[u8]) -> io::Result<()> {
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
