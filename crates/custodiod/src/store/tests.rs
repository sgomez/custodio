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
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
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

const CHILD_ENV: &str = "CUSTODIO_UMASK_CHILD";

#[test]
fn mode_is_exact_under_restrictive_umask() -> TestResult {
    // umask is process-wide, so run the check in a child test process.
    let exe = std::env::current_exe()?;
    let out = std::process::Command::new(exe)
        .args(["--exact", "store::tests::umask_child", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()?;
    assert!(out.status.success(), "child failed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("umask child ran"));
    Ok(())
}

#[test]
fn umask_child() -> TestResult {
    if std::env::var_os(CHILD_ENV).is_none() {
        return Ok(());
    }
    // 0o277 would turn the requested 0600 into 0400 without the explicit chmod.
    let tmp = tempfile::tempdir()?;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o277));
    let p = tmp.path().join("f");
    write_synced(&p, b"x")?;
    assert_eq!(mode(&p)?, 0o600);
    // A directory created by `open` must also come out exactly 0700.
    let store = KeyStore::open(tmp.path().join("s"))?;
    assert_eq!(mode(store.dir())?, 0o700);
    store.put("k", &secret(b"x"))?;
    println!("umask child ran");
    Ok(())
}

#[test]
fn rejects_symlinked_key() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"x")?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
    std::os::unix::fs::symlink(&outside, store.dir().join("k"))?;
    assert!(matches!(store.get("k"), Err(StoreError::BadFileType(_))));
    Ok(())
}

#[test]
fn rejects_foreign_owner() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = KeyStore::open(tmp.path().join("s"))?;
    store.put("k", &secret(b"x"))?;
    store.uid = store.uid.wrapping_add(1);
    assert!(matches!(store.get("k"), Err(StoreError::BadOwner(_))));
    Ok(())
}

#[test]
fn open_rejects_foreign_owner() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("s");
    let uid = rustix::process::geteuid().as_raw();
    KeyStore::open_as(dir.clone(), uid)?;
    assert!(matches!(
        KeyStore::open_as(dir, uid.wrapping_add(1)),
        Err(StoreError::BadOwner(_))
    ));
    Ok(())
}

#[test]
fn open_rejects_symlink_and_regular_file() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let real = tmp.path().join("real");
    KeyStore::open(&real)?;
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link)?;
    assert!(matches!(
        KeyStore::open(&link),
        Err(StoreError::BadFileType(_))
    ));
    let file = tmp.path().join("file");
    fs::write(&file, b"x")?;
    assert!(matches!(
        KeyStore::open(&file),
        Err(StoreError::BadFileType(_))
    ));
    Ok(())
}

#[test]
fn get_rejects_fifo_without_blocking() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        store.dir().join("k"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )?;
    assert!(matches!(store.get("k"), Err(StoreError::BadFileType(_))));
    Ok(())
}

#[test]
fn open_removes_stale_temp_files() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("s");
    let store = KeyStore::open(&dir)?;
    fs::write(dir.join(".tmp-1-1"), b"partial")?;
    drop(store);
    let store = KeyStore::open(&dir)?;
    assert_eq!(fs::read_dir(store.dir())?.count(), 0);
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
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644))?;
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
    // The exact redacted form fails if `secrecy` is swapped for a type that prints contents.
    assert_eq!(format!("{key:?}"), "SecretBox<[u8]>([REDACTED])");
    assert_eq!(format!("{got:?}"), "SecretBox<[u8]>([REDACTED])");
    let errs = [
        StoreError::InvalidId,
        StoreError::BadPermissions(PathBuf::from("/x")),
        StoreError::BadOwner(PathBuf::from("/x")),
        StoreError::Io(io::Error::other("boom")),
        StoreError::SyncFailed(io::Error::other("boom")),
    ];
    for e in errs {
        assert!(!format!("{e:?} {e}").contains("SUPERSECRET"));
    }
    Ok(())
}

#[test]
fn key_size_limit_is_exact() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let max = usize::try_from(MAX_KEY_LEN)?;
    assert_eq!(MAX_KEY_LEN, 65536);
    store.put("small", &secret(&vec![7; 2000]))?;
    assert_eq!(store.get("small")?.expose_secret().len(), 2000);
    store.put("max", &secret(&vec![7; max]))?;
    assert_eq!(store.get("max")?.expose_secret().len(), max);
    store.put("over", &secret(&vec![7; max + 1]))?;
    assert!(matches!(store.get("over"), Err(StoreError::TooLarge)));
    Ok(())
}

#[test]
fn open_keeps_keys_and_non_file_temp_entries() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("s");
    let store = KeyStore::open(&dir)?;
    store.put("k", &secret(b"keep"))?;
    fs::create_dir(dir.join(".tmp-dir"))?;
    fs::write(dir.join(".tmp-file"), b"x")?;
    let store = KeyStore::open(&dir)?;
    assert_eq!(store.get("k")?.expose_secret(), b"keep");
    assert!(dir.join(".tmp-dir").is_dir());
    assert!(!dir.join(".tmp-file").exists());
    Ok(())
}

#[test]
fn open_reports_missing_parent_as_io() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let r = KeyStore::open(tmp.path().join("no/such/s"));
    assert!(matches!(r, Err(StoreError::Io(_))));
    Ok(())
}

#[test]
fn get_reports_unreadable_file_as_io_not_missing() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put("k", &secret(b"x"))?;
    fs::set_permissions(store.dir().join("k"), fs::Permissions::from_mode(0o0))?;
    // As root the open would succeed and report the mode instead; both are not `NotFound`.
    assert!(!matches!(store.get("k"), Err(StoreError::NotFound)));
    Ok(())
}

#[test]
fn errors_display_their_cause() {
    let p = || PathBuf::from("/x/y");
    let io = || io::Error::other("boom");
    for (e, want) in [
        (StoreError::InvalidId, "invalid key id"),
        (StoreError::AlreadyExists, "key already exists"),
        (StoreError::NotFound, "key not found"),
        (
            StoreError::BadPermissions(p()),
            "unsafe permissions on /x/y",
        ),
        (StoreError::BadFileType(p()), "unexpected file type at /x/y"),
        (StoreError::BadOwner(p()), "unexpected owner of /x/y"),
        (StoreError::TooLarge, "key file too large"),
        (
            StoreError::SyncFailed(io()),
            "key stored but directory sync failed: boom",
        ),
        (StoreError::Io(io()), "i/o error: boom"),
    ] {
        assert_eq!(e.to_string(), want);
    }
}
