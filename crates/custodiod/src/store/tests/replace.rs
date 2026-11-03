//! `replace_existing`: the content changes atomically and only of a plain file that is there.

use super::*;

/// Names in the area of `OWNER`, sorted, hidden files included.
fn all_names(store: &KeyStore) -> Result<Vec<String>, io::Error> {
    let mut names = Vec::new();
    for e in fs::read_dir(area(store))? {
        names.push(e?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn store_with(files: &[(&str, &[u8])]) -> Result<(tempfile::TempDir, KeyStore), Box<dyn Error>> {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    for (id, bytes) in files {
        store.put(OWNER, id, &secret(bytes))?;
    }
    Ok((tmp, store))
}

#[test]
fn replace_changes_the_content_and_keeps_mode_0600() -> TestResult {
    let (_tmp, store) = store_with(&[("a", b"old"), ("b", b"other")])?;
    store.put(2000, "a", &secret(b"theirs"))?;
    store.replace_existing(OWNER, "a", b"new content")?;
    assert_eq!(store.get(OWNER, "a")?.expose_secret(), b"new content");
    assert_eq!(mode(&area(&store).join("a"))?, 0o600);
    assert_eq!(mode(&area(&store))?, 0o700);
    // Other ids and other owners are untouched; no temporary file is left.
    assert_eq!(store.get(OWNER, "b")?.expose_secret(), b"other");
    assert_eq!(store.get(2000, "a")?.expose_secret(), b"theirs");
    assert_eq!(all_names(&store)?, ["a", "b"]);
    Ok(())
}

#[test]
fn replace_with_shorter_and_empty_content_leaves_no_old_tail() -> TestResult {
    let (_tmp, store) = store_with(&[("a", b"a long old content")])?;
    store.replace_existing(OWNER, "a", b"x")?;
    assert_eq!(store.get(OWNER, "a")?.expose_secret(), b"x");
    store.replace_existing(OWNER, "a", b"")?;
    assert_eq!(store.get(OWNER, "a")?.expose_secret(), b"");
    Ok(())
}

#[test]
fn replace_never_creates() -> TestResult {
    let (_tmp, store) = store_with(&[("b", b"other")])?;
    assert!(matches!(
        store.replace_existing(OWNER, "a", b"x"),
        Err(StoreError::NotFound)
    ));
    // An owner without an area gets none.
    assert!(matches!(
        store.replace_existing(3000, "a", b"x"),
        Err(StoreError::NotFound)
    ));
    assert!(!store.dir().join("3000").exists());
    assert_eq!(all_names(&store)?, ["b"]);
    assert!(matches!(
        store.replace_existing(OWNER, "bad id", b"x"),
        Err(StoreError::InvalidId)
    ));
    Ok(())
}

#[test]
fn replace_refuses_a_symlink_a_directory_and_a_foreign_owner() -> TestResult {
    let (tmp, mut store) = store_with(&[("a", b"old"), ("c", b"old-c")])?;
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"outside")?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
    fs::remove_file(area(&store).join("a"))?;
    std::os::unix::fs::symlink(&outside, area(&store).join("a"))?;
    fs::create_dir(area(&store).join("dir"))?;
    assert!(matches!(
        store.replace_existing(OWNER, "a", b"new"),
        Err(StoreError::BadFileType(_))
    ));
    assert!(matches!(
        store.replace_existing(OWNER, "dir", b"new"),
        Err(StoreError::BadFileType(_))
    ));
    // Untouched: the link still points to the file, which has its bytes; no temporary file.
    assert_eq!(fs::read(&outside)?, b"outside");
    assert!(fs::symlink_metadata(area(&store).join("a"))?.is_symlink());
    assert!(area(&store).join("dir").is_dir());
    assert_eq!(all_names(&store)?, ["a", "c", "dir"]);
    store.file_uid = Some(store.uid.wrapping_add(1));
    assert!(matches!(
        store.replace_existing(OWNER, "c", b"new"),
        Err(StoreError::BadOwner(_))
    ));
    assert_eq!(fs::read(area(&store).join("c"))?, b"old-c");
    Ok(())
}

#[test]
fn a_failure_before_the_rename_keeps_the_old_content_and_removes_the_temp_file() -> TestResult {
    let (_tmp, store) = store_with(&[("a", b"old")])?;
    let dest = area(&store).join("a");
    let mut during = Vec::new();
    let got = store.replace_with(OWNER, "a", b"new", || {
        during = all_names(&store)?;
        assert_eq!(fs::read(&dest)?, b"old");
        Err(io::Error::other("injected"))
    });
    assert!(matches!(got, Err(StoreError::Io(_))));
    // At the injected moment the temporary file existed next to the old content.
    assert_eq!(during.len(), 2);
    assert!(during.iter().any(|n| n.starts_with(TMP_PREFIX)));
    assert_eq!(fs::read(&dest)?, b"old");
    assert_eq!(all_names(&store)?, ["a"]);
    Ok(())
}

#[test]
fn an_unwritable_area_is_refused_and_nothing_changes() -> TestResult {
    let (_tmp, store) = store_with(&[("a", b"old")])?;
    if rustix::process::geteuid().is_root() {
        return Ok(());
    }
    fs::set_permissions(area(&store), fs::Permissions::from_mode(0o500))?;
    let got = store.replace_existing(OWNER, "a", b"new");
    // The area is no longer `0700`, which `get` refuses before anything is written.
    assert!(got.is_err());
    fs::set_permissions(area(&store), fs::Permissions::from_mode(0o700))?;
    assert_eq!(fs::read(area(&store).join("a"))?, b"old");
    assert_eq!(all_names(&store)?, ["a"]);
    Ok(())
}

/// What a reader may rely on: the entry is there and holds the old or the new content.
fn reader_sees(path: &Path, old: &[u8], new: &[u8]) -> bool {
    fs::read(path).is_ok_and(|b| b == old || b == new)
}

/// A deliberately broken replace: remove, then write. `between` runs in the gap.
fn non_atomic_replace(path: &Path, data: &[u8], between: impl FnOnce()) -> io::Result<()> {
    fs::remove_file(path)?;
    between();
    fs::write(path, data)
}

#[test]
fn replace_is_atomic() -> TestResult {
    let (_tmp, store) = store_with(&[("a", b"old")])?;
    let dest = area(&store).join("a");
    // At the moment between the temporary file and the rename the target holds the old content.
    let mut seen_before_rename = false;
    store.replace_with(OWNER, "a", b"new", || {
        seen_before_rename = reader_sees(&dest, b"old", b"new") && fs::read(&dest)? == b"old";
        Ok(())
    })?;
    assert!(seen_before_rename);
    assert_eq!(fs::read(&dest)?, b"new");
    // And after the rename the entry holds the new content, with no moment of absence in between:
    // the failure injected at the only gap leaves the entry present.
    let got = store.replace_with(OWNER, "a", b"newer", || {
        assert!(reader_sees(&dest, b"new", b"newer"));
        Err(io::Error::other("injected"))
    });
    assert!(got.is_err());
    assert!(reader_sees(&dest, b"new", b"newer"));
    Ok(())
}

#[test]
fn the_reader_check_fails_against_a_non_atomic_write() -> TestResult {
    let (_tmp, store) = store_with(&[("a", b"old")])?;
    let dest = area(&store).join("a");
    let mut seen = None;
    non_atomic_replace(&dest, b"new", || {
        seen = Some(reader_sees(&dest, b"old", b"new"));
    })?;
    // In the gap of the broken write the entry is missing, and the check says so.
    assert_eq!(seen, Some(false));
    assert!(reader_sees(&dest, b"old", b"new"));
    // The check also rejects a partial value.
    assert!(!reader_sees(&dest, b"old", b"newer"));
    Ok(())
}
