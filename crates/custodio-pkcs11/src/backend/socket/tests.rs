use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;

#[test]
fn instance_names() {
    let long_ok = "a".repeat(40);
    let good = [
        "firefox",
        "ab",
        "a1",
        "my-snap",
        "firefox_a",
        "firefox_work1",
        "a-b_0123456789",
        &long_ok,
    ];
    for n in good {
        assert!(valid_instance_name(n), "{n}");
    }
    let long = "a".repeat(41);
    let bad = [
        "",
        "a",
        "..",
        "../x",
        "a/b",
        "a\0b",
        "Firefox",
        "-ab",
        "ab-",
        "a--b",
        "12",
        "99-9",
        "_a",
        "firefox_",
        "firefox_A",
        "firefox_a-b",
        "firefox_01234567890",
        "firefox__a",
        "firefox_a_b",
        "a b",
        "fire.fox",
        "firefox\n",
        "ünï",
        &long,
    ];
    for n in bad {
        assert!(!valid_instance_name(n), "{n:?}");
    }
}

/// The rule's table; `custodio-it`'s `snap_transport.rs` runs the same rows against the service's check.
#[test]
fn directory_rule() {
    // (is dir, uid, mode, ok)
    let rows = [
        (true, 0, 0o40_755, true),
        (true, 0, 0o40_700, true),
        (true, 0, 0o40_775, false),
        (true, 0, 0o40_757, false),
        (true, 0, 0o40_777, false),
        (true, 1000, 0o40_755, false),
        (true, 1000, 0o40_777, false),
        (false, 0, 0o100_644, false),
    ];
    for (dir, uid, mode, ok) in rows {
        assert_eq!(directory_ok(dir, uid, mode), ok, "{dir} {uid} {mode:o}");
    }
}

#[test]
fn a_symlink_is_not_followed_and_a_missing_directory_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("snap.firefox");
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    // Owned by the test user: refused unless the tests run as root.
    assert_eq!(check_dir(&dir), std::fs::metadata(&dir)?.uid() == 0);
    let link = tmp.path().join("snap.link");
    symlink("/", &link)?;
    assert!(!check_dir(&link));
    assert!(!check_dir(&tmp.path().join("missing")));
    assert!(path_in(tmp.path(), "../x").is_none());
    Ok(())
}

#[test]
fn unset_is_the_bus_and_a_bad_value_is_none() {
    assert_eq!(select(None), Transport::Bus);
    assert_eq!(select(Some(OsStr::new(""))), Transport::None);
    assert_eq!(select(Some(OsStr::new("Bad/Name"))), Transport::None);
    assert_eq!(select(Some(OsStr::new("nosuchsnap"))), Transport::None);
}

/// The code spans of the "Socket transport" section of `docs/api.md`.
fn spans(doc: &str) -> Vec<String> {
    let section = doc
        .split("\n## ")
        .find(|s| s.starts_with("Socket transport"))
        .unwrap_or_default();
    section
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn documents(doc: &str) -> bool {
    let spans = spans(doc);
    spans.iter().any(|s| s == SOCKET_PATH_TEMPLATE) && spans.iter().any(|s| s == SNAP_INSTANCE_VAR)
}

#[test]
fn api_md_names_the_socket_path_and_variable() -> Result<(), Box<dyn std::error::Error>> {
    let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api.md"))?;
    assert!(documents(&doc));
    assert!(!documents(
        &doc.replace("custodio.sock`", "custodio.socket`")
    ));
    assert!(!documents(&doc.replace("SNAP_INSTANCE_NAME", "SNAP_NAME")));
    Ok(())
}
