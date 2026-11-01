use super::*;
use std::fs;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;
use zbus::block_on;

mod bounded;
mod limiter;
mod reader_bounds;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const UID: u32 = 1001;
const PID: u32 = 4242;
const FLATPAK: &str = "app-flatpak-org.example.App-5151.scope";

/// A fixture cgroup tree: `<root>/user.slice/user-<uid>.slice/user@<uid>.service/app.slice`.
struct Tree {
    dir: TempDir,
}

impl Tree {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let tree = Self {
            dir: tempfile::tempdir()?,
        };
        fs::create_dir_all(tree.slice(UID))?;
        Ok(tree)
    }

    fn slice(&self, uid: u32) -> std::path::PathBuf {
        self.dir.path().join(format!(
            "user.slice/user-{uid}.slice/user@{uid}.service/app.slice"
        ))
    }

    fn scope_in(&self, uid: u32, name: &str, procs: &[u8]) -> std::io::Result<()> {
        let dir = self.slice(uid).join(name);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("cgroup.procs"), procs)
    }

    fn scope(&self, name: &str, procs: &str) -> std::io::Result<()> {
        self.scope_in(UID, name, procs.as_bytes())
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }
}

fn devnull() -> std::io::Result<fs::File> {
    fs::File::open("/dev/null")
}

fn reader(tree: &Tree) -> CgroupAppIdSource {
    CgroupAppIdSource::with_root(tree.root().to_path_buf(), Duration::from_secs(5), 4)
        .with_pid_reader(Arc::new(|_| Some(PID)))
}

/// `block_on` that gives up after 20 s, so a source that never wakes its task fails a test instead of hanging.
fn block_on_limited<T>(fut: impl Future<Output = T>) -> Option<T> {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        let left = until.checked_duration_since(Instant::now())?;
        std::thread::park_timeout(left);
    }
}

fn lookup_of(source: &impl AppIdSource, uid: u32) -> std::io::Result<AppIdOutcome> {
    let fd = devnull()?;
    block_on_limited(source.app_id(fd.as_fd(), uid))
        .ok_or_else(|| std::io::Error::other("lookup hung"))
}

fn read(id: &str) -> Result<AppIdOutcome, &'static str> {
    Ok(AppIdOutcome::Read(
        validate(id.as_bytes()).ok_or("invalid id")?,
    ))
}

#[test]
fn reads_flatpak_scope_of_pinned_pid() -> TestResult {
    let tree = Tree::new()?;
    tree.scope("app-flatpak-org.other.One-7.scope", "100\n200\n")?;
    tree.scope(FLATPAK, "1\n4242\n9\n")?;
    tree.scope("app-gnome-gedit-99b.scope", "300\n")?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, read("org.example.App")?);
    Ok(())
}

#[test]
fn escaped_app_id_is_read() -> TestResult {
    let tree = Tree::new()?;
    tree.scope(
        "app-flatpak-org.example.My_App\\x2dName-5151.scope",
        "4242\n",
    )?;
    assert_eq!(
        lookup_of(&reader(&tree), UID)?,
        read("org.example.My_App-Name")?
    );
    Ok(())
}

#[test]
fn fake_source_returns_the_three_outcomes() -> TestResult {
    let fd = devnull()?;
    let read_it = FakeAppIdSource::reading("org.example.App").ok_or("invalid id")?;
    assert_eq!(
        block_on(read_it.app_id(fd.as_fd(), 1)),
        read("org.example.App")?
    );
    let none = FakeAppIdSource::new(AppIdOutcome::None);
    assert_eq!(block_on(none.app_id(fd.as_fd(), 1)), AppIdOutcome::None);
    let unknown = FakeAppIdSource::new(AppIdOutcome::Undetermined);
    assert_eq!(
        block_on(unknown.app_id(fd.as_fd(), 1)),
        AppIdOutcome::Undetermined
    );
    assert!(FakeAppIdSource::reading("not an id").is_none());
    Ok(())
}

#[test]
fn lookup_through_the_trait_object() -> TestResult {
    // The same generic call works for the fake and the real reader.
    fn ask(source: &impl AppIdSource) -> std::io::Result<AppIdOutcome> {
        lookup_of(source, UID)
    }
    let tree = Tree::new()?;
    tree.scope(FLATPAK, "4242\n")?;
    assert_eq!(
        ask(&FakeAppIdSource::new(AppIdOutcome::None))?,
        AppIdOutcome::None
    );
    assert_eq!(ask(&reader(&tree))?, read("org.example.App")?);
    Ok(())
}

#[test]
fn non_flatpak_scope_is_none() -> TestResult {
    let tree = Tree::new()?;
    tree.scope("app-gnome-gedit-99b.scope", "4242\n")?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, AppIdOutcome::None);
    Ok(())
}

#[test]
fn pid_in_no_scope_is_none() -> TestResult {
    let tree = Tree::new()?;
    tree.scope(FLATPAK, "1\n2\n")?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, AppIdOutcome::None);
    Ok(())
}

#[test]
fn no_app_slice_directory_is_none() -> TestResult {
    let dir = tempfile::tempdir()?;
    let source = CgroupAppIdSource::with_root(dir.path().to_path_buf(), Duration::from_secs(5), 4)
        .with_pid_reader(Arc::new(|_| Some(PID)));
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::None);
    Ok(())
}

#[test]
fn invalid_scope_name_is_undetermined() -> TestResult {
    let tree = Tree::new()?;
    tree.scope("app-flatpak-..bad-1.scope", "4242\n")?;
    let got = lookup_of(&reader(&tree), UID)?;
    assert_eq!(got, AppIdOutcome::Undetermined);
    assert!(!format!("{got:?}").contains("bad"));
    Ok(())
}

#[test]
fn only_the_callers_uid_slice_is_read() -> TestResult {
    let tree = Tree::new()?;
    tree.scope_in(1002, FLATPAK, b"4242\n")?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, AppIdOutcome::None);
    assert_eq!(lookup_of(&reader(&tree), 1002)?, read("org.example.App")?);
    Ok(())
}

#[test]
fn symlinked_scope_dir_is_skipped() -> TestResult {
    let tree = Tree::new()?;
    let target = tree.root().join("elsewhere");
    fs::create_dir(&target)?;
    fs::write(target.join("cgroup.procs"), "4242\n")?;
    std::os::unix::fs::symlink(&target, tree.slice(UID).join(FLATPAK))?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, AppIdOutcome::None);
    Ok(())
}

#[test]
fn symlinked_app_slice_is_not_entered() -> TestResult {
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    fs::create_dir_all(real.join("app.slice").join(FLATPAK))?;
    fs::write(
        real.join("app.slice").join(FLATPAK).join("cgroup.procs"),
        "4242\n",
    )?;
    let service = dir.path().join(format!("user.slice/user-{UID}.slice"));
    fs::create_dir_all(&service)?;
    std::os::unix::fs::symlink(&real, service.join(format!("user@{UID}.service")))?;
    let source = CgroupAppIdSource::with_root(dir.path().to_path_buf(), Duration::from_secs(5), 4)
        .with_pid_reader(Arc::new(|_| Some(PID)));
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::None);
    Ok(())
}

#[test]
fn symlinked_cgroup_procs_is_undetermined() -> TestResult {
    let tree = Tree::new()?;
    let dir = tree.slice(UID).join(FLATPAK);
    fs::create_dir(&dir)?;
    let real = tree.root().join("procs");
    fs::write(&real, "4242\n")?;
    std::os::unix::fs::symlink(&real, dir.join("cgroup.procs"))?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, AppIdOutcome::Undetermined);
    Ok(())
}

#[test]
fn scope_that_vanished_is_skipped() -> TestResult {
    let tree = Tree::new()?;
    fs::create_dir(tree.slice(UID).join("app-flatpak-org.a.B-1.scope"))?;
    tree.scope(FLATPAK, "4242\n")?;
    assert_eq!(lookup_of(&reader(&tree), UID)?, read("org.example.App")?);
    Ok(())
}

#[test]
fn non_decimal_pid_list_is_undetermined() -> TestResult {
    for bad in [
        &b"12x\n"[..],
        b"-1\n",
        b"+5\n",
        b"99999999999\n",
        b"4242\n\0\n",
        b"1\n\n2\n",
        b"4294967296\n",
    ] {
        let tree = Tree::new()?;
        tree.scope_in(UID, FLATPAK, bad)?;
        assert_eq!(
            lookup_of(&reader(&tree), UID)?,
            AppIdOutcome::Undetermined,
            "{bad:?}"
        );
    }
    Ok(())
}

#[test]
fn pid_lists_parse_literally() {
    assert_eq!(scan::lists_pid(b"", 5), Some(false));
    assert_eq!(scan::lists_pid(b"\n", 5), None);
    assert_eq!(scan::lists_pid(b"5", 5), Some(true));
    assert_eq!(scan::lists_pid(b"5\n", 5), Some(true));
    assert_eq!(scan::lists_pid(b"4\n6\n", 5), Some(false));
    assert_eq!(scan::lists_pid(b"4294967295\n", 4_294_967_295), Some(true));
}

#[test]
fn fdinfo_pid_zero_or_minus_one_is_undetermined() {
    for text in [
        "Pid:\t0\n",
        "Pid:\t-1\n",
        "Pid:\tx\n",
        "Pid:\t\n",
        "Pid:\t4294967296\n",
        "Pid:\t+7\n",
    ] {
        assert_eq!(scan::pid_from_fdinfo(text.as_bytes()), None, "{text:?}");
    }
    assert_eq!(
        scan::pid_from_fdinfo(b"pos:\t0\nPid:\t921\nNSpid:\t921\n"),
        Some(921)
    );
}

#[test]
fn fdinfo_missing_pid_is_undetermined() -> TestResult {
    assert_eq!(scan::pid_from_fdinfo(b"pos:\t0\nNSpid:\t921\n"), None);
    assert_eq!(scan::pid_from_fdinfo(b""), None);
    let tree = Tree::new()?;
    tree.scope(FLATPAK, "4242\n")?;
    let source = reader(&tree).with_pid_reader(Arc::new(|_| None));
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::Undetermined);
    Ok(())
}

#[test]
fn real_pidfd_gives_its_pid() -> TestResult {
    let me = rustix::process::getpid();
    let pidfd = rustix::process::pidfd_open(me, rustix::process::PidfdFlags::empty())?;
    assert_eq!(
        scan::read_pid(pidfd.as_fd()),
        Some(me.as_raw_nonzero().get().cast_unsigned())
    );
    Ok(())
}

#[test]
fn pid_changed_after_scan_is_undetermined() -> TestResult {
    let tree = Tree::new()?;
    tree.scope(FLATPAK, "5\n")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let changing = reader(&tree).with_pid_reader(Arc::new(move |_| {
        Some(if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            5
        } else {
            6
        })
    }));
    assert_eq!(lookup_of(&changing, UID)?, AppIdOutcome::Undetermined);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let gone = Arc::new(AtomicUsize::new(0));
    let after = Arc::clone(&gone);
    let exited = reader(&tree).with_pid_reader(Arc::new(move |_| {
        (after.fetch_add(1, Ordering::SeqCst) == 0).then_some(5)
    }));
    assert_eq!(lookup_of(&exited, UID)?, AppIdOutcome::Undetermined);
    let same = reader(&tree).with_pid_reader(Arc::new(|_| Some(5)));
    assert_eq!(lookup_of(&same, UID)?, read("org.example.App")?);
    Ok(())
}

#[test]
fn panicking_reader_is_undetermined() -> TestResult {
    let tree = Tree::new()?;
    let source =
        reader(&tree).with_pid_reader(Arc::new(|_| std::panic::resume_unwind(Box::new("boom"))));
    assert_eq!(lookup_of(&source, UID)?, AppIdOutcome::Undetermined);
    Ok(())
}

#[test]
fn production_constants_are_documented_values() {
    assert_eq!(LOOKUP_DEADLINE, Duration::from_secs(1));
    assert_eq!(MAX_PROCS_BYTES, 1024 * 1024);
    assert_eq!(MAX_CHILDREN, 4096);
    assert_eq!(MAX_STUCK, 8);
    let source = CgroupAppIdSource::new();
    assert_eq!(source.root, Path::new("/sys/fs/cgroup"));
    assert_eq!(source.deadline, LOOKUP_DEADLINE);
    assert_eq!(source.limiter.cap(), MAX_STUCK);
}
