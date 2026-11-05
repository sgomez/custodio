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

#[test]
fn remove_legacy_removes_the_files_of_the_entry_only() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    for name in ["old", "old-cert", "keep", "orphan-cert"] {
        legacy_file(&store, OWNER, name)?;
    }
    legacy_file(&store, 2000, "old")?;
    store.put(&rec(OWNER, "orphan", b"cert"))?;
    store.put(&rec(OWNER, "new", b"cert"))?;
    assert_eq!(store.remove_legacy(&entry("old", &["old", "old-cert"]))?, 2);
    // The orphan certificate goes, the new-format key it is named after stays.
    assert_eq!(store.remove_legacy(&entry("orphan", &["orphan-cert"]))?, 1);
    assert_eq!(store.list(OWNER)?, ["keep", "new", "orphan"]);
    assert!(store.get(OWNER, "orphan").is_ok() && store.get(OWNER, "new").is_ok());
    // Another owner's key of the same name is not touched.
    assert_eq!(
        store.legacy(2000)?,
        [LegacyEntry {
            owner: 2000,
            ..entry("old", &["old"])
        }]
    );
    // Idempotent: a second call finds nothing and removes nothing.
    assert_eq!(store.remove_legacy(&entry("old", &["old", "old-cert"]))?, 0);
    Ok(())
}

#[test]
fn remove_legacy_never_removes_a_current_record() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "a", b"cert"))?;
    assert_eq!(store.remove_legacy(&entry("a", &["a"]))?, 0);
    assert!(store.get(OWNER, "a").is_ok());
    // An owner without an area has nothing, and none is made.
    assert_eq!(
        store.remove_legacy(&LegacyEntry {
            owner: 9,
            ..entry("a", &["a"])
        })?,
        0
    );
    assert!(!store.dir().join("9").exists());
    Ok(())
}

#[test]
fn remove_legacy_refuses_a_symlink_and_a_bad_file_and_stops() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let outside = tmp.path().join("target");
    fs::write(&outside, b"target")?;
    legacy_file(&store, OWNER, "first")?;
    std::os::unix::fs::symlink(&outside, area(&store).join("link"))?;
    legacy_file(&store, OWNER, "last")?;
    let err = store.remove_legacy(&entry("x", &["first", "link", "last"]));
    assert!(matches!(err, Err(StoreError::BadFileType(_))), "{err:?}");
    // `first` went before the symlink was met; the symlink, its target and `last` are untouched.
    assert_eq!(store.list(OWNER)?, ["last", "link"]);
    assert_eq!(fs::read(&outside)?, b"target");
    assert!(fs::symlink_metadata(area(&store).join("link"))?.is_symlink());
    // A file with a loose mode is refused, not repaired.
    fs::set_permissions(area(&store).join("last"), fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        store.remove_legacy(&entry("last", &["last"])),
        Err(StoreError::BadPermissions(_))
    ));
    assert_eq!(mode(&area(&store).join("last"))?, 0o644);
    // An invalid name is refused before anything is looked at.
    assert!(matches!(
        store.remove_legacy(&entry("x", &["../x"])),
        Err(StoreError::InvalidId)
    ));
    Ok(())
}

#[test]
fn remove_legacy_refuses_a_foreign_owner_and_a_symlinked_area() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = KeyStore::open(tmp.path().join("s"))?;
    legacy_file(&store, OWNER, "old")?;
    store.file_uid = Some(OWNER + 1);
    assert!(matches!(
        store.remove_legacy(&entry("old", &["old"])),
        Err(StoreError::BadOwner(_))
    ));
    store.file_uid = None;
    assert_eq!(store.list(OWNER)?, ["old"]);
    // An area that is a symlink is not followed.
    let real = tmp.path().join("real");
    DirBuilder::new().mode(0o700).create(&real)?;
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700))?;
    fs::write(real.join("old"), b"x")?;
    std::os::unix::fs::symlink(&real, store.dir().join("3000"))?;
    let other = LegacyEntry {
        owner: 3000,
        ..entry("old", &["old"])
    };
    assert!(matches!(
        store.remove_legacy(&other),
        Err(StoreError::BadFileType(_))
    ));
    assert!(real.join("old").exists());
    Ok(())
}
