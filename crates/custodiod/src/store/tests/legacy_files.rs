//! Recognising the earlier format: reported, listed, never read.

use super::*;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|n| (*n).to_owned()).collect()
}

fn entry(id: &str, files: &[&str]) -> LegacyEntry {
    LegacyEntry {
        owner: OWNER,
        id: id.to_owned(),
        files: names(files),
    }
}

#[test]
fn a_key_and_its_certificate_are_one_entry() {
    let got = legacy::group(OWNER, &names(&["a", "a-cert", "b", "b-cert"]));
    assert_eq!(
        got,
        [entry("a", &["a", "a-cert"]), entry("b", &["b", "b-cert"])]
    );
}

#[test]
fn an_orphan_certificate_is_listed_once_as_its_key() {
    assert_eq!(
        legacy::group(OWNER, &names(&["a-cert"])),
        [entry("a", &["a-cert"])]
    );
    assert_eq!(
        legacy::group(OWNER, &names(&["a-cert", "b", "b-cert"])),
        [entry("a", &["a-cert"]), entry("b", &["b", "b-cert"])]
    );
}

#[test]
fn a_key_without_a_certificate_and_odd_names() {
    assert_eq!(legacy::group(OWNER, &names(&["k"])), [entry("k", &["k"])]);
    // `-cert` alone has no stem: it is a key.
    assert_eq!(
        legacy::group(OWNER, &names(&["-cert"])),
        [entry("-cert", &["-cert"])]
    );
    // A key whose own name ends in `-cert`, with its certificate.
    assert_eq!(
        legacy::group(OWNER, &names(&["a-cert", "a-cert-cert"])),
        [entry("a-cert", &["a-cert", "a-cert-cert"])]
    );
    assert_eq!(legacy::group(OWNER, &[]), []);
}

fn legacy_file(store: &KeyStore, owner: u32, name: &str) -> io::Result<()> {
    let dir = store.dir().join(owner.to_string());
    if !dir.exists() {
        DirBuilder::new().mode(0o700).create(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    // DER first byte, as the earlier format wrote it.
    write_synced(
        &dir.join(name),
        &[
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, b'L', b'E', b'G', b'A', b'C', b'Y',
        ],
    )
}

#[test]
fn legacy_files_are_reported_listed_and_not_read() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    for name in ["old", "old-cert", "orphan-cert"] {
        legacy_file(&store, OWNER, name)?;
    }
    legacy_file(&store, 2000, "other")?;
    store.put(&rec(OWNER, "new", b"cert"))?;
    assert!(matches!(store.get(OWNER, "old"), Err(StoreError::Legacy)));
    assert!(matches!(
        store.get(OWNER, "orphan-cert"),
        Err(StoreError::Legacy)
    ));
    assert!(store.get(OWNER, "new").is_ok());
    // The names list everything; the legacy listing is one entry per key, without the new record.
    assert_eq!(
        store.list(OWNER)?,
        ["new", "old", "old-cert", "orphan-cert"]
    );
    assert_eq!(
        store.legacy(OWNER)?,
        [
            entry("old", &["old", "old-cert"]),
            entry("orphan", &["orphan-cert"])
        ]
    );
    assert_eq!(store.legacy(7)?, []);
    let all = store.legacy_all()?;
    assert_eq!(all.len(), 3);
    assert_eq!(
        all.last().map(|e| (e.owner, e.id.as_str())),
        Some((2000, "other"))
    );
    // Nothing of the content comes back in an error, its Display or its Debug.
    let err = store.get(OWNER, "old").err().ok_or("a refusal")?;
    let shown = format!("{err:?} {err}");
    assert!(
        !shown.contains("LEGACY") && !shown.contains("135"),
        "{shown}"
    );
    // A file of the earlier format is neither changed nor removed by reading it.
    assert_eq!(fs::read(area(&store).join("old"))?.len(), 12);
    Ok(())
}

#[test]
fn a_legacy_file_under_a_bad_mode_is_a_file_rule_error() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    legacy_file(&store, OWNER, "old")?;
    fs::set_permissions(area(&store).join("old"), fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        store.get(OWNER, "old"),
        Err(StoreError::BadPermissions(_))
    ));
    assert!(matches!(
        store.legacy(OWNER),
        Err(StoreError::BadPermissions(_))
    ));
    // A symlink with a legacy name is a file type error, not `Legacy`.
    std::os::unix::fs::symlink("/etc/hostname", area(&store).join("link"))?;
    assert!(matches!(
        store.get(OWNER, "link"),
        Err(StoreError::BadFileType(_))
    ));
    Ok(())
}

#[test]
fn a_legacy_file_may_still_be_removed_by_hand() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    legacy_file(&store, OWNER, "old")?;
    assert!(store.contains(OWNER, "old")?);
    assert!(store.remove_existing(OWNER, "old")?);
    assert_eq!(store.legacy(OWNER)?, []);
    Ok(())
}
