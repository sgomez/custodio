//! Recognising the earlier format, for the purge. There is no reader: only names are looked at.
//!
//! The earlier format kept a key as `<id>` (PKCS#8 DER) and its certificate as `<id>-cert`. One key
//! is one entry, with the file names that make it up. An orphan `<id>-cert` without a key file is
//! listed once, as `<id>`. The names alone cannot always tell `a` + `a-cert` from two keys, but the
//! earlier import wrote a certificate for every key and refused an id that collided with one, so a
//! state it made reads one way; a hand-made one is read by the fixed rule in [`group`].

use std::collections::BTreeSet;
use std::fs;

use super::files::{removed_by_us, sync_dir};
use super::{KeyStore, StoreError, valid_key_id};

const CERT_SUFFIX: &str = "-cert";

/// A key of the earlier format: its owner, its id and the files to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyEntry {
    pub owner: u32,
    pub id: String,
    pub files: Vec<String>,
}

/// The stem of a certificate name, if it has one (`a-cert` → `a`).
fn stem(name: &str) -> Option<&str> {
    name.strip_suffix(CERT_SUFFIX).filter(|s| !s.is_empty())
}

/// Groups the names of the legacy files of `owner`: a name is a certificate when its stem is a
/// file that is not itself a certificate; a certificate whose stem is missing, and which has no
/// certificate of its own, is an orphan and stands for its stem; everything else is a key.
pub(super) fn group(owner: u32, names: &[String]) -> Vec<LegacyEntry> {
    let all: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    // Shorter names first, so a stem is decided before the name built on it.
    let mut by_len: Vec<&str> = all.iter().copied().collect();
    by_len.sort_by_key(|n| n.len());
    let mut certs = BTreeSet::new();
    for name in by_len {
        if let Some(s) = stem(name)
            && all.contains(s)
            && !certs.contains(s)
        {
            certs.insert(name);
        }
    }
    let mut entries: Vec<LegacyEntry> = Vec::new();
    for name in &all {
        if certs.contains(name) {
            continue;
        }
        let own_cert = format!("{name}{CERT_SUFFIX}");
        if let Some(s) = stem(name)
            && !all.contains(own_cert.as_str())
        {
            entries.push(LegacyEntry {
                owner,
                id: s.to_owned(),
                files: vec![(*name).to_owned()],
            });
            continue;
        }
        let mut files = vec![(*name).to_owned()];
        if certs.contains(own_cert.as_str()) {
            files.push(own_cert);
        }
        entries.push(LegacyEntry {
            owner,
            id: (*name).to_owned(),
            files,
        });
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries
}

impl KeyStore {
    /// The keys of `owner` that are still in the earlier format, one entry per key with the files
    /// that make it up. Nothing is read but the first bytes of each file.
    ///
    /// # Errors
    /// As [`Self::list`].
    pub fn legacy(&self, owner: u32) -> Result<Vec<LegacyEntry>, StoreError> {
        let Some(area) = self.existing_area(owner)? else {
            return Ok(Vec::new());
        };
        let mut old = Vec::new();
        for name in Self::names(&area)? {
            if !self.is_record(owner, &name)? {
                old.push(name);
            }
        }
        Ok(group(owner, &old))
    }

    /// [`Self::legacy`] for every owner area of the store, by owner then id.
    ///
    /// # Errors
    /// As [`Self::list`], for any area.
    pub fn legacy_all(&self) -> Result<Vec<LegacyEntry>, StoreError> {
        let mut owners = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            if let Some(uid) = name
                .to_str()
                .and_then(|n| n.parse::<u32>().ok().filter(|u| u.to_string() == n))
            {
                owners.push(uid);
            }
        }
        owners.sort_unstable();
        let mut all = Vec::new();
        for owner in owners {
            all.extend(self.legacy(owner)?);
        }
        Ok(all)
    }

    /// Removes the files of one key of the earlier format (see [`Self::legacy`]), under the lock of the
    /// owner's area, then syncs the directory. Each file passes the file rules first (a plain file of the
    /// service uid, mode `0600`, symlinks neither followed nor removed) and its content is not parsed. A
    /// file that is a record of the current format, or is already gone, is left alone. The first file
    /// that breaks a rule stops the removal; nothing is repaired. Gives back how many files it removed.
    ///
    /// # Errors
    /// `InvalidId`; the area errors of `get`; `BadFileType`, `BadOwner` or `BadPermissions` for a file
    /// that breaks the rules; `Io` or `SyncFailed` otherwise.
    pub fn remove_legacy(&self, entry: &LegacyEntry) -> Result<usize, StoreError> {
        if !entry.files.iter().all(|f| valid_key_id(f)) {
            return Err(StoreError::InvalidId);
        }
        let Some(area) = self.existing_area(entry.owner)? else {
            return Ok(0);
        };
        let _lock = Self::lock_area(&area)?;
        let mut removed = 0;
        for name in &entry.files {
            match self.is_record(entry.owner, name) {
                Ok(false) => {}
                Ok(true) | Err(StoreError::NotFound) => continue,
                Err(e) => return Err(e),
            }
            if removed_by_us(fs::remove_file(area.join(name)))? {
                removed += 1;
            }
        }
        sync_dir(&area)?;
        Ok(removed)
    }
}
