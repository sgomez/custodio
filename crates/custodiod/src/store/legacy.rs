//! Recognising the earlier format, for the purge. There is no reader: only names are looked at.
//!
//! The earlier format kept a key as `<id>` (PKCS#8 DER) and its certificate as `<id>-cert`. One key
//! is one entry, with the file names that make it up. An orphan `<id>-cert` without a key file is
//! listed once, as `<id>`. The names alone cannot always tell `a` + `a-cert` from two keys, but the
//! earlier import wrote a certificate for every key and refused an id that collided with one, so a
//! state it made reads one way; a hand-made one is read by the fixed rule in [`group`].

use std::collections::BTreeSet;

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
