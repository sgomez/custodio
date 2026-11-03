//! The per-owner layout: separation, modes, refusals and concurrent inserts.

use super::*;

fn names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut v = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    v.sort();
    Ok(v)
}

fn fresh() -> Result<(tempfile::TempDir, KeyStore), Box<dyn Error>> {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    Ok((tmp, store))
}

#[test]
fn owner_is_recorded_in_the_path_and_found_again() -> TestResult {
    let (tmp, store) = fresh()?;
    store.put(7, "k", &secret(b"seven"))?;
    assert_eq!(fs::read(store.dir().join("7").join("k"))?, b"seven");
    assert_eq!(store.get(7, "k")?.expose_secret(), b"seven");
    assert!(matches!(store.get(8, "k"), Err(StoreError::NotFound)));
    drop(store);
    let reopened = KeyStore::open(tmp.path().join("s"))?;
    assert_eq!(reopened.get(7, "k")?.expose_secret(), b"seven");
    assert!(matches!(reopened.get(8, "k"), Err(StoreError::NotFound)));
    Ok(())
}

#[test]
fn owners_are_kept_apart_and_reads_create_nothing() -> TestResult {
    let (_tmp, store) = fresh()?;
    store.put(1, "a-only", &secret(b"a"))?;
    store.put(2, "b-only", &secret(b"b"))?;
    assert_eq!(store.list(1)?, ["a-only"]);
    assert_eq!(store.list(2)?, ["b-only"]);
    assert!(matches!(store.get(2, "a-only"), Err(StoreError::NotFound)));
    // An owner without an area: reads see nothing and create nothing.
    assert!(matches!(store.get(3, "a-only"), Err(StoreError::NotFound)));
    assert_eq!(store.list(3)?, Vec::<String>::new());
    assert_eq!(names(store.dir())?, ["1", "2"]);
    // A key planted by hand in B's area under A's id is not A's.
    fs::write(store.dir().join("2").join("planted"), b"x")?;
    fs::set_permissions(
        store.dir().join("2").join("planted"),
        fs::Permissions::from_mode(0o600),
    )?;
    assert!(matches!(store.get(1, "planted"), Err(StoreError::NotFound)));
    assert_eq!(store.list(1)?, ["a-only"]);
    Ok(())
}

#[test]
fn two_owners_may_store_the_same_id() -> TestResult {
    let (_tmp, store) = fresh()?;
    store.put(1, "my-key", &secret(b"one"))?;
    store.put(2, "my-key", &secret(b"two"))?;
    assert_eq!(store.get(1, "my-key")?.expose_secret(), b"one");
    assert_eq!(store.get(2, "my-key")?.expose_secret(), b"two");
    assert!(matches!(
        store.put(1, "my-key", &secret(b"again")),
        Err(StoreError::AlreadyExists)
    ));
    assert_eq!(store.get(1, "my-key")?.expose_secret(), b"one");
    Ok(())
}

#[test]
fn numeric_ids_stay_valid_and_pairs_never_collide() -> TestResult {
    let (_tmp, store) = fresh()?;
    for id in ["0", "1000", "1000-key"] {
        assert!(valid_key_id(id));
    }
    for id in ["", ".", "..", "a/b", &"x".repeat(65)] {
        assert!(matches!(
            store.put(1, id, &secret(b"x")),
            Err(StoreError::InvalidId)
        ));
    }
    store.put(1, "00-x", &secret(b"owner1"))?;
    store.put(10, "0-x", &secret(b"owner10"))?;
    assert_eq!(store.list(1)?, ["00-x"]);
    assert_eq!(store.list(10)?, ["0-x"]);
    assert!(matches!(store.get(1, "0-x"), Err(StoreError::NotFound)));
    assert!(matches!(store.get(10, "00-x"), Err(StoreError::NotFound)));
    // An id equal to another owner's uid is just an id.
    store.put(1, "10", &secret(b"id ten"))?;
    assert_eq!(store.list(1)?, ["00-x", "10"]);
    assert_eq!(store.list(10)?, ["0-x"]);
    assert_eq!(store.get(1, "10")?.expose_secret(), b"id ten");
    Ok(())
}

#[test]
fn umask_child_areas() -> TestResult {
    if std::env::var_os(CHILD_ENV).is_none() {
        return Ok(());
    }
    let tmp = tempfile::tempdir()?;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o277));
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(5, "k", &secret(b"x"))?;
    assert_eq!(mode(&store.dir().join("5"))?, 0o700);
    assert_eq!(mode(&store.dir().join("5").join("k"))?, 0o600);
    println!("umask areas ran");
    Ok(())
}

#[test]
fn area_and_key_modes_are_exact_under_restrictive_umask() -> TestResult {
    let out = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "store::tests::owners::umask_child_areas",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()?;
    assert!(out.status.success(), "child failed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("umask areas ran"));
    Ok(())
}

#[test]
fn loose_area_is_refused_and_left_alone() -> TestResult {
    let (_tmp, store) = fresh()?;
    store.put(4, "k", &secret(b"x"))?;
    let area = store.dir().join("4");
    fs::set_permissions(&area, fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        store.get(4, "k"),
        Err(StoreError::BadPermissions(_))
    ));
    assert!(matches!(store.list(4), Err(StoreError::BadPermissions(_))));
    assert!(matches!(
        store.put(4, "k2", &secret(b"y")),
        Err(StoreError::BadPermissions(_))
    ));
    assert_eq!(mode(&area)?, 0o755);
    assert_eq!(names(&area)?, ["k"]);
    // Other owners are unaffected.
    store.put(5, "k", &secret(b"z"))?;
    // Reopening neither repairs it nor fails.
    let dir = store.dir().to_owned();
    drop(store);
    KeyStore::open(&dir)?;
    assert_eq!(mode(&area)?, 0o755);
    Ok(())
}

#[test]
fn foreign_owned_area_and_key_are_refused() -> TestResult {
    let (_tmp, mut store) = fresh()?;
    store.put(4, "k", &secret(b"x"))?;
    let real = store.uid;
    store.uid = real.wrapping_add(1);
    assert!(matches!(store.get(4, "k"), Err(StoreError::BadOwner(_))));
    assert!(matches!(store.list(4), Err(StoreError::BadOwner(_))));
    assert!(matches!(
        store.put(4, "k2", &secret(b"y")),
        Err(StoreError::BadOwner(_))
    ));
    assert_eq!(names(&store.dir().join("4"))?, ["k"]);
    // The file check alone: the area belongs to us, the file does not.
    store.uid = real;
    assert!(store.get(4, "k").is_ok());
    store.file_uid = Some(real.wrapping_add(1));
    assert!(matches!(store.get(4, "k"), Err(StoreError::BadOwner(_))));
    assert_eq!(names(&store.dir().join("4"))?, ["k"]);
    Ok(())
}

#[test]
fn symlinked_area_is_refused_and_target_untouched() -> TestResult {
    let (tmp, store) = fresh()?;
    let target = tmp.path().join("target");
    DirBuilder::new().mode(0o700).create(&target)?;
    fs::write(target.join("k"), b"secret")?;
    fs::set_permissions(target.join("k"), fs::Permissions::from_mode(0o600))?;
    std::os::unix::fs::symlink(&target, store.dir().join("9"))?;
    assert!(matches!(store.get(9, "k"), Err(StoreError::BadFileType(_))));
    assert!(matches!(store.list(9), Err(StoreError::BadFileType(_))));
    assert!(matches!(
        store.put(9, "new", &secret(b"y")),
        Err(StoreError::BadFileType(_))
    ));
    assert_eq!(names(&target)?, ["k"]);
    assert!(store.dir().join("9").is_symlink());
    Ok(())
}

#[test]
fn non_directory_in_place_of_area_is_refused_and_kept() -> TestResult {
    let (_tmp, store) = fresh()?;
    let p = store.dir().join("1000");
    fs::write(&p, b"flat")?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        store.get(1000, "k"),
        Err(StoreError::BadFileType(_))
    ));
    assert!(matches!(store.list(1000), Err(StoreError::BadFileType(_))));
    assert!(matches!(
        store.put(1000, "k", &secret(b"y")),
        Err(StoreError::BadFileType(_))
    ));
    assert_eq!(fs::read(&p)?, b"flat");
    assert_eq!(mode(&p)?, 0o600);
    Ok(())
}

#[test]
fn symlinked_root_is_refused() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let real = tmp.path().join("real");
    KeyStore::open(&real)?;
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link)?;
    assert!(matches!(
        KeyStore::open(&link),
        Err(StoreError::BadFileType(_))
    ));
    assert_eq!(names(&real)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn old_layout_flat_files_are_ignored_and_untouched() -> TestResult {
    let (tmp, store) = fresh()?;
    let root = store.dir().to_owned();
    for name in ["flatkey", "0", "5"] {
        fs::write(root.join(name), b"flat")?;
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600))?;
    }
    for owner in [77, 1000] {
        assert!(matches!(
            store.get(owner, "flatkey"),
            Err(StoreError::NotFound)
        ));
    }
    assert_eq!(store.list(1000)?, Vec::<String>::new());
    // Owners 0 and 5: the area path is a flat file; refused, not read as a key.
    assert!(matches!(
        store.get(0, "flatkey"),
        Err(StoreError::BadFileType(_))
    ));
    assert!(matches!(store.get(5, "x"), Err(StoreError::BadFileType(_))));
    drop(store);
    let store = KeyStore::open(&root)?;
    for name in ["flatkey", "0", "5"] {
        assert_eq!(fs::read(root.join(name))?, b"flat");
        assert_eq!(mode(&root.join(name))?, 0o600);
    }
    store.put(1000, "flatkey", &secret(b"new"))?;
    assert_eq!(fs::read(root.join("flatkey"))?, b"flat");
    drop(tmp);
    Ok(())
}

#[test]
fn fifo_as_area_does_not_hang() -> TestResult {
    let (_tmp, store) = fresh()?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        store.dir().join("6"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )?;
    assert!(matches!(store.get(6, "k"), Err(StoreError::BadFileType(_))));
    Ok(())
}

#[test]
fn open_removes_stale_temp_files_in_root_and_areas_only() -> TestResult {
    let (_tmp, store) = fresh()?;
    store.put(3, "k", &secret(b"x"))?;
    store.put(4, "k", &secret(b"x"))?;
    let root = store.dir().to_owned();
    fs::write(root.join(".tmp-1-1"), b"p")?;
    fs::write(root.join("3").join(".tmp-2-2"), b"p")?;
    // A badly-moded area is not touched.
    fs::write(root.join("4").join(".tmp-3-3"), b"p")?;
    fs::set_permissions(root.join("4"), fs::Permissions::from_mode(0o755))?;
    drop(store);
    KeyStore::open(&root)?;
    assert!(!root.join(".tmp-1-1").exists());
    assert_eq!(names(&root.join("3"))?, ["k"]);
    assert!(root.join("4").join(".tmp-3-3").exists());
    Ok(())
}

#[test]
fn list_skips_temp_files_and_other_entries() -> TestResult {
    let (_tmp, store) = fresh()?;
    store.put(3, "b", &secret(b"1"))?;
    fs::write(store.dir().join("3").join(".tmp-9-9"), b"p")?;
    fs::write(store.dir().join("3").join("bad name"), b"p")?;
    assert_eq!(store.list(3)?, ["b"]);
    Ok(())
}

#[test]
fn put_leaves_no_temp_file_on_conflict() -> TestResult {
    let (_tmp, store) = fresh()?;
    store.put(3, "k", &secret(b"one"))?;
    assert!(matches!(
        store.put(3, "k", &secret(b"two")),
        Err(StoreError::AlreadyExists)
    ));
    assert_eq!(names(&store.dir().join("3"))?, ["k"]);
    assert_eq!(store.get(3, "k")?.expose_secret(), b"one");
    Ok(())
}

/// Covers filesystem atomicity only: `put` takes no in-process lock, so the threads race on disk.
#[test]
fn concurrent_inserts_of_one_owner_and_id_leave_one_key() -> TestResult {
    const THREADS: usize = 16;
    for _ in 0..5 {
        let (_tmp, store) = fresh()?;
        let store = std::sync::Arc::new(store);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|n| {
                let (store, barrier) = (store.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let body = format!("writer-{n}");
                    (
                        body.clone(),
                        store.put(42, "same", &secret(body.as_bytes())),
                    )
                })
            })
            .collect();
        let mut winners = Vec::new();
        for h in handles {
            let (body, r) = h.join().map_err(|_| "thread panicked")?;
            match r {
                Ok(()) => winners.push(body),
                Err(StoreError::AlreadyExists) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let [winner] = winners.as_slice() else {
            return Err("not exactly one winner".into());
        };
        assert_eq!(store.list(42)?, ["same"]);
        assert_eq!(store.get(42, "same")?.expose_secret(), winner.as_bytes());
        assert_eq!(names(&store.dir().join("42"))?, ["same"]);
    }
    Ok(())
}

#[test]
fn concurrent_inserts_of_different_owners_all_succeed() -> TestResult {
    let (_tmp, store) = fresh()?;
    let store = std::sync::Arc::new(store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8_u32)
        .map(|owner| {
            let (store, barrier) = (store.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                store.put(owner, "my-key", &secret(&owner.to_le_bytes()))
            })
        })
        .collect();
    for h in handles {
        h.join().map_err(|_| "thread panicked")??;
    }
    for owner in 0..8_u32 {
        assert_eq!(
            store.get(owner, "my-key")?.expose_secret(),
            owner.to_le_bytes()
        );
    }
    Ok(())
}

#[test]
fn a_root_that_stopped_being_a_directory_is_an_io_error_not_an_empty_store() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("s");
    let store = KeyStore::open(&root)?;
    fs::remove_dir(&root)?;
    fs::write(&root, b"file")?;
    assert!(matches!(store.get(1, "k"), Err(StoreError::Io(_))));
    assert!(matches!(store.list(1), Err(StoreError::Io(_))));
    assert!(matches!(
        store.put(1, "k", &secret(b"x")),
        Err(StoreError::Io(_))
    ));
    Ok(())
}
