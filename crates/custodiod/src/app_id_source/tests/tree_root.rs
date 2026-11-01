use super::*;
use scan::tree_root;

#[test]
fn tree_root_strips_the_prefix_before_system_slice() {
    let mount = Path::new("/sys/fs/cgroup");
    let cases: [(&[u8], &str); 6] = [
        (b"0::/system.slice/custodio.service\n", "/sys/fs/cgroup"),
        (
            b"0::/abc123/system.slice/custodio.service\n",
            "/sys/fs/cgroup/abc123",
        ),
        (
            b"12:cpu:/x\n0::/a/b/system.slice/custodio.service\n",
            "/sys/fs/cgroup/a/b",
        ),
        (
            b"0::/abc/../system.slice/custodio.service\n",
            "/sys/fs/cgroup",
        ),
        (b"0::/abc/other.slice/custodio.service\n", "/sys/fs/cgroup"),
        (b"", "/sys/fs/cgroup"),
    ];
    for (text, want) in cases {
        assert_eq!(tree_root(mount, text), Path::new(want), "{text:?}");
    }
    for text in [
        &b"0::/a//system.slice/x\n"[..],
        b"0::/a\0b/system.slice/x\n",
        b"0::abc/system.slice/x\n",
    ] {
        assert_eq!(tree_root(mount, text), mount, "{text:?}");
    }
}

#[test]
fn nested_container_tree_is_read_below_its_prefix() -> TestResult {
    let outer = tempfile::tempdir()?;
    let nested = Tree {
        dir: tempfile::tempdir_in(outer.path())?,
    };
    fs::create_dir_all(nested.slice(UID))?;
    nested.scope(FLATPAK, "4242\n")?;
    let id = nested
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name")?
        .to_owned();
    let own = format!("0::/{id}/system.slice/custodio.service\n");
    let root = tree_root(outer.path(), own.as_bytes());
    assert_eq!(root, nested.root());
    let source = CgroupAppIdSource::with_root(root, Duration::from_secs(5), 4)
        .with_pid_reader(Arc::new(|_| Some(PID)));
    assert_eq!(lookup_of(&source, UID)?, read("org.example.App")?);
    // Without the prefix the same tree shows no scope.
    let flat = tree_root(outer.path(), b"0::/system.slice/custodio.service\n");
    let source = CgroupAppIdSource::with_root(flat, Duration::from_secs(5), 4)
        .with_pid_reader(Arc::new(|_| Some(PID)));
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::None);
    Ok(())
}
