use super::*;
use crate::creds::memory::MemoryCreds;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

const OWNER: u32 = 1000;

/// The protected key of every test record: an encrypted credential made by the in-memory service.
#[allow(clippy::expect_used)] // test helper; a panic is the intended failure
fn protected() -> Protected {
    let plain = secrecy::SecretSlice::from(b"KEY-PLAINTEXT-MARKER".to_vec());
    let sealed = crate::creds::seal(&MemoryCreds::host(), "test", &plain);
    Protected::from_sealed(&sealed.expect("seal with the in-memory service"))
}

/// A record that skipped its checks (a bad id), to show that `put` makes them again.
fn rec_unchecked(owner: u32, id: &str, certificate: &[u8]) -> Record {
    Record::new_unchecked(owner, id, Kind::EncryptedHost, certificate, protected())
}

/// The certificate in the record file at `path`, read and decoded without the store.
fn file_cert(path: &Path) -> io::Result<Vec<u8>> {
    let record = Record::decode(&fs::read(path)?).map_err(io::Error::other)?;
    Ok(record.certificate().to_vec())
}

/// A record of `owner`'s key `id` whose certificate is `certificate`.
#[allow(clippy::expect_used)] // test helper; a panic is the intended failure
fn rec(owner: u32, id: &str, certificate: &[u8]) -> Record {
    Record::new(owner, id, Kind::EncryptedHost, certificate, protected()).expect("a valid record")
}

fn area(store: &KeyStore) -> PathBuf {
    store.dir().join(OWNER.to_string())
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
    store.put(&rec(OWNER, "k1", b"hunter2"))?;
    assert_eq!(mode(&store.dir().join("1000").join("k1"))?, 0o600);
    assert_eq!(store.get(OWNER, "k1")?.certificate(), b"hunter2");
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
    store.put(&rec(OWNER, "k", b"x"))?;
    println!("umask child ran");
    Ok(())
}

#[test]
fn rejects_symlinked_key() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "other", b"o"))?;
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"x")?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
    std::os::unix::fs::symlink(&outside, area(&store).join("k"))?;
    assert!(matches!(
        store.get(OWNER, "k"),
        Err(StoreError::BadFileType(_))
    ));
    Ok(())
}

#[test]
fn rejects_foreign_owner() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k", b"x"))?;
    store.file_uid = Some(store.uid.wrapping_add(1));
    assert!(matches!(
        store.get(OWNER, "k"),
        Err(StoreError::BadOwner(_))
    ));
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
    store.put(&rec(OWNER, "other", b"o"))?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        area(&store).join("k"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )?;
    assert!(matches!(
        store.get(OWNER, "k"),
        Err(StoreError::BadFileType(_))
    ));
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
    store.put(&rec(OWNER, "k", b"one"))?;
    assert!(matches!(
        store.put(&rec(OWNER, "k", b"two")),
        Err(StoreError::AlreadyExists)
    ));
    assert_eq!(store.get(OWNER, "k")?.certificate(), b"one");
    let names: Vec<_> = fs::read_dir(area(&store))?
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
            store.put(&rec_unchecked(OWNER, id, b"x")),
            Err(StoreError::InvalidId)
        ));
        assert!(matches!(store.get(OWNER, id), Err(StoreError::InvalidId)));
    }
    Ok(())
}

#[test]
fn get_rejects_loose_file_mode_and_missing() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    assert!(matches!(
        store.get(OWNER, "nope"),
        Err(StoreError::NotFound)
    ));
    store.put(&rec(OWNER, "k", b"x"))?;
    let p = area(&store).join("k");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        store.get(OWNER, "k"),
        Err(StoreError::BadPermissions(_))
    ));
    Ok(())
}

#[test]
fn list_is_sorted_and_skips_temp_files() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "b", b"1"))?;
    store.put(&rec(OWNER, "a", b"2"))?;
    fs::write(area(&store).join(".tmp-1-1"), b"partial")?;
    assert_eq!(store.list(OWNER)?, ["a", "b"]);
    Ok(())
}

#[test]
fn debug_never_prints_key_material() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let record = rec(OWNER, "k", b"CERTIFICATE");
    store.put(&record)?;
    let got = store.get(OWNER, "k")?;
    assert_eq!(got, record);
    for out in [
        format!("{record:?}"),
        format!("{got:?}"),
        format!("{store:?}"),
    ] {
        assert!(!out.contains("KEY-PLAINTEXT-MARKER"));
        // Nor the credential bytes, as a decimal list or in hex.
        let credential = got.protected().credential().ok_or("a credential")?;
        let hex = credential
            .iter()
            .fold(String::new(), |acc, b| acc + &format!("{b:02x}"));
        assert!(!out.contains(hex.get(..32).ok_or("a long credential")?));
        assert!(!out.contains("17, 17, 17, 17"));
    }
    let errs = [
        StoreError::InvalidId,
        StoreError::Legacy,
        StoreError::Record(RecordError::Truncated),
        StoreError::Mismatch(PathBuf::from("/x")),
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
fn record_size_limits_are_exact() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    assert_eq!(record::MAX_CERTIFICATE, 16 * 1024);
    store.put(&rec(OWNER, "small", &vec![7; 2000]))?;
    assert_eq!(store.get(OWNER, "small")?.certificate().len(), 2000);
    store.put(&rec(OWNER, "max", &vec![7; record::MAX_CERTIFICATE]))?;
    assert_eq!(
        store.get(OWNER, "max")?.certificate().len(),
        record::MAX_CERTIFICATE
    );
    // One byte more is refused before anything is written.
    let over = Record::new_unchecked(
        OWNER,
        "over",
        Kind::EncryptedHost,
        &vec![7; record::MAX_CERTIFICATE + 1],
        protected(),
    );
    assert!(matches!(
        store.put(&over),
        Err(StoreError::Record(RecordError::Oversized(
            Field::Certificate
        )))
    ));
    assert!(!store.contains(OWNER, "over")?);
    // A file larger than any record is `TooLarge` once it starts like one.
    let path = area(&store).join("huge");
    let mut bytes = record::MAGIC.to_vec();
    bytes.resize(MAX_RECORD + 1, 0);
    write_synced(&path, &bytes)?;
    assert!(matches!(
        store.get(OWNER, "huge"),
        Err(StoreError::TooLarge)
    ));
    bytes.pop();
    fs::remove_file(&path)?;
    write_synced(&path, &bytes)?;
    assert!(matches!(
        store.get(OWNER, "huge"),
        Err(StoreError::Record(_))
    ));
    Ok(())
}

#[test]
fn open_keeps_keys_and_non_file_temp_entries() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("s");
    let store = KeyStore::open(&dir)?;
    store.put(&rec(OWNER, "k", b"keep"))?;
    fs::create_dir(dir.join(".tmp-dir"))?;
    fs::write(dir.join(".tmp-file"), b"x")?;
    let store = KeyStore::open(&dir)?;
    assert_eq!(store.get(OWNER, "k")?.certificate(), b"keep");
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
    store.put(&rec(OWNER, "k", b"x"))?;
    fs::set_permissions(area(&store).join("k"), fs::Permissions::from_mode(0o0))?;
    // As root the open would succeed and report the mode instead; both are not `NotFound`.
    assert!(!matches!(store.get(OWNER, "k"), Err(StoreError::NotFound)));
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

mod framing;
mod legacy_files;
mod owners;
mod records;
mod replace;
mod rules;

#[test]
fn remove_deletes_only_that_id() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k1", b"a"))?;
    store.put(&rec(OWNER, "k2", b"b"))?;
    store.put(&rec(OWNER + 1, "k1", b"c"))?;
    store.remove(OWNER, "k1")?;
    assert_eq!(store.list(OWNER)?, vec!["k2".to_owned()]);
    assert_eq!(store.list(OWNER + 1)?, vec!["k1".to_owned()]);
    assert!(matches!(store.get(OWNER, "k1"), Err(StoreError::NotFound)));
    // The id can be stored again.
    store.put(&rec(OWNER, "k1", b"d"))?;
    Ok(())
}

#[test]
fn remove_of_a_missing_key_or_area_is_not_an_error() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.remove(OWNER, "nothing")?;
    assert!(!area(&store).exists(), "remove must not create the area");
    store.put(&rec(OWNER, "k1", b"a"))?;
    store.remove(OWNER, "nothing")?;
    assert_eq!(store.list(OWNER)?, vec!["k1".to_owned()]);
    Ok(())
}

#[test]
fn remove_rejects_a_bad_id() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k1", b"a"))?;
    for id in ["", "../k1", "a/b", ".tmp-1"] {
        assert!(matches!(
            store.remove(OWNER, id),
            Err(StoreError::InvalidId)
        ));
    }
    Ok(())
}

#[test]
fn remove_refuses_a_symlink_and_a_foreign_owner() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = KeyStore::open(tmp.path().join("s"))?;
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"x")?;
    store.put(&rec(OWNER, "real", b"a"))?;
    std::os::unix::fs::symlink(&outside, area(&store).join("link"))?;
    assert!(matches!(
        store.remove(OWNER, "link"),
        Err(StoreError::BadFileType(_))
    ));
    assert!(area(&store).join("link").symlink_metadata().is_ok());
    assert!(outside.exists());
    store.file_uid = Some(store.uid.wrapping_add(1));
    assert!(matches!(
        store.remove(OWNER, "real"),
        Err(StoreError::BadOwner(_))
    ));
    assert!(area(&store).join("real").exists());
    Ok(())
}

#[test]
fn remove_refuses_a_directory() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k1", b"a"))?;
    fs::create_dir(area(&store).join("dir"))?;
    assert!(matches!(
        store.remove(OWNER, "dir"),
        Err(StoreError::BadFileType(_))
    ));
    Ok(())
}

#[test]
fn remove_existing_tells_removed_from_missing() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    // No area: nothing removed, nothing created.
    assert!(!store.remove_existing(OWNER, "k1")?);
    assert!(!area(&store).exists());
    store.put(&rec(OWNER, "k1", b"a"))?;
    store.put(&rec(OWNER, "k1-cert", b"c"))?;
    store.put(&rec(OWNER + 1, "k1", b"b"))?;
    assert!(!store.remove_existing(OWNER, "other")?);
    assert!(store.remove_existing(OWNER, "k1")?);
    assert!(!store.remove_existing(OWNER, "k1")?);
    // The certificate entry is removed by its own name; other owners and ids are untouched.
    assert_eq!(store.list(OWNER)?, vec!["k1-cert".to_owned()]);
    assert!(store.remove_existing(OWNER, "k1-cert")?);
    assert_eq!(store.list(OWNER)?, Vec::<String>::new());
    assert_eq!(store.list(OWNER + 1)?, vec!["k1".to_owned()]);
    assert!(matches!(
        store.remove_existing(OWNER, "../k1"),
        Err(StoreError::InvalidId)
    ));
    Ok(())
}

#[test]
fn remove_existing_refuses_what_remove_refuses() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "real", b"a"))?;
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"x")?;
    std::os::unix::fs::symlink(&outside, area(&store).join("link"))?;
    fs::create_dir(area(&store).join("dir"))?;
    for id in ["link", "dir"] {
        assert!(matches!(
            store.remove_existing(OWNER, id),
            Err(StoreError::BadFileType(_))
        ));
    }
    assert!(outside.exists() && area(&store).join("dir").is_dir());
    assert!(area(&store).join("real").exists());
    Ok(())
}

#[test]
fn a_file_gone_before_its_removal_is_not_ours() {
    assert!(matches!(removed_by_us(Ok(())), Ok(true)));
    let gone = io::Error::from(io::ErrorKind::NotFound);
    assert!(matches!(removed_by_us(Err(gone)), Ok(false)));
    let denied = io::Error::from(io::ErrorKind::PermissionDenied);
    assert!(matches!(removed_by_us(Err(denied)), Err(StoreError::Io(_))));
}
