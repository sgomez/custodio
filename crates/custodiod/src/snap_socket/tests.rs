use super::*;
use std::error::Error;
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn Error>>;

fn none<T>() -> Vec<T> {
    Vec::new()
}

#[test]
fn the_firefox_name_maps_to_the_firefox_directory() {
    assert_eq!(descriptor_name("firefox"), "snap-firefox");
    assert_eq!(snap_for_descriptor("snap-firefox"), Some("firefox"));
    assert_eq!(socket_dir("firefox"), PathBuf::from("/run/snap.firefox"));
}

#[test]
fn names_that_are_not_a_known_snap_select_nothing() {
    for name in [
        "",
        "snap-",
        "snap-..",
        "snap-../x",
        "snap-fire/fox",
        "snap-Firefox",
        "snap-FIREFOX",
        "snap--firefox",
        "snap-firefox-",
        "snap-fire--fox",
        "snap-chromium",
        "snap-firefox2",
        "firefox",
        "snap.firefox",
        "unknown",
        "dbus",
        "connection",
        "snap-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert_eq!(snap_for_descriptor(name), None, "{name:?}");
    }
}

#[test]
fn snap_name_rules() {
    assert!(valid_snap_name("a"));
    assert!(valid_snap_name("a1-b2"));
    assert!(valid_snap_name(&"a".repeat(40)));
    assert!(!valid_snap_name(&"a".repeat(41)));
    assert!(!valid_snap_name("123"));
    assert!(!valid_snap_name("1-2"));
    assert!(!valid_snap_name("A"));
    assert!(!valid_snap_name("a_b"));
    assert!(!valid_snap_name("-a"));
    assert!(!valid_snap_name("a-"));
    assert!(!valid_snap_name("a--b"));
    assert!(!valid_snap_name(""));
}

#[test]
fn only_a_descriptor_named_for_firefox_is_selected() {
    let passed = vec![
        (None, 0),
        (Some("unknown".to_owned()), 1),
        (Some("snap-firefox".to_owned()), 2),
        (Some("snap-chromium".to_owned()), 3),
        (Some("snap-firefox".to_owned()), 4),
    ];
    assert_eq!(select(passed), vec![("firefox", 2)]);
    assert_eq!(select(vec![(None, 0), (Some("x".to_owned()), 1)]), none());
    assert_eq!(select::<u8>(Vec::new()), none());
}

#[test]
fn unselected_descriptors_are_closed() {
    struct Closes(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Closes {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let passed = vec![
        (None, Closes(count.clone())),
        (Some("snap-firefox".to_owned()), Closes(count.clone())),
        (Some("snap-firefox".to_owned()), Closes(count.clone())),
        (Some("other".to_owned()), Closes(count.clone())),
    ];
    let kept = select(passed);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(kept.len(), 1);
}

#[test]
fn the_environment_counts_only_for_this_process() {
    let names = Some("snap-firefox:dbus");
    assert_eq!(
        listen_names(Some("7"), Some("2"), names, 7),
        vec![Some("snap-firefox".to_owned()), Some("dbus".to_owned())]
    );
    assert_eq!(listen_names(Some("8"), Some("2"), names, 7), none());
    assert_eq!(listen_names(Some("7"), Some("3"), names, 7), none());
    assert_eq!(listen_names(Some("7"), Some("1"), names, 7), none());
    assert_eq!(listen_names(Some("x"), Some("2"), names, 7), none());
    assert_eq!(listen_names(Some("7"), Some("x"), names, 7), none());
    assert_eq!(listen_names(None, Some("2"), names, 7), none());
    assert_eq!(listen_names(Some("7"), None, names, 7), none());
    assert_eq!(listen_names(Some("7"), Some("5000"), None, 7), none());
    assert_eq!(listen_names(Some("7"), Some("4096"), None, 7).len(), 4096);
    assert_eq!(
        listen_names(Some("7"), Some("2"), None, 7),
        vec![None, None]
    );
    assert_eq!(listen_names(Some("7"), Some("1"), Some(""), 7), vec![None]);
    assert_eq!(listen_names(Some("7"), Some("0"), None, 7), none());
}

#[test]
fn a_root_directory_without_group_or_other_write_passes() {
    assert_eq!(check_dir(Path::new("/usr")), Ok(()));
}

#[test]
fn the_refusals_are_told_apart() -> TestResult {
    assert_eq!(check_dir(Path::new("/tmp")), Err(Refusal::GroupWritable));
    assert_eq!(
        check_dir(Path::new("/nonexistent/x")),
        Err(Refusal::Missing)
    );
    assert_eq!(
        check_dir(Path::new("/etc/passwd")),
        Err(Refusal::NotDirectory)
    );
    let tmp = tempfile::tempdir()?;
    // Owned by the test user, which is not root (or is root in a container: then the mode decides).
    let own = tmp.path().join("own");
    std::fs::create_dir(&own)?;
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755))?;
    if rustix::process::getuid().is_root() {
        assert_eq!(check_dir(&own), Ok(()));
    } else {
        assert_eq!(check_dir(&own), Err(Refusal::NotRootOwned));
    }
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink("/usr", &link)?;
    assert_eq!(check_dir(&link), Err(Refusal::Symlink));
    Ok(())
}

#[test]
fn a_refusal_is_journaled_with_the_socket_and_the_reason() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let listener = UnixListener::bind(tmp.path().join("s"))?;
    let mut journal = Vec::new();
    let outcome = serve(
        "snap-firefox",
        listener,
        Path::new("/nonexistent/x"),
        &mut journal,
    );
    assert!(matches!(outcome, Outcome::Refused(_, Refusal::Missing)));
    assert_eq!(
        String::from_utf8(journal)?,
        "custodiod: socket snap-firefox is not served: the directory does not exist (/nonexistent/x)\n"
    );
    Ok(())
}

#[test]
fn the_refusal_texts_are_distinct() {
    let all = [
        Refusal::Missing,
        Refusal::Symlink,
        Refusal::NotDirectory,
        Refusal::NotRootOwned,
        Refusal::GroupWritable,
        Refusal::OtherWritable,
        Refusal::Unreadable,
    ];
    let texts: std::collections::HashSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), all.len());
}

#[test]
fn the_rule_over_metadata() {
    let dir = FileType::Directory;
    assert_eq!(judge(dir, 0, 0o40755), Ok(()));
    assert_eq!(judge(dir, 0, 0o40700), Ok(()));
    assert_eq!(judge(dir, 0, 0o40775), Err(Refusal::GroupWritable));
    assert_eq!(judge(dir, 0, 0o40757), Err(Refusal::OtherWritable));
    assert_eq!(judge(dir, 0, 0o41777), Err(Refusal::GroupWritable));
    assert_eq!(judge(dir, 1000, 0o40755), Err(Refusal::NotRootOwned));
    assert_eq!(judge(dir, 1000, 0o40775), Err(Refusal::GroupWritable));
    assert_eq!(
        judge(FileType::RegularFile, 0, 0o100_644),
        Err(Refusal::NotDirectory)
    );
    assert_eq!(
        judge(FileType::Symlink, 0, 0o120_777),
        Err(Refusal::NotDirectory)
    );
}
