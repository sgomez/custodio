//! The strict readers of `profiles.ini`, `installs.ini`, `pkcs11.txt` and the lock rule (F181, F172's Decisions).

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use custodio_cli::browser_files::{
    HeldReason, LockState, MAX_FILE_LEN, ModuleEntry, fuzz_nss_modules, fuzz_profile_index,
    lock_state, parse_installs_ini, parse_pkcs11_txt, parse_profiles_ini, pid_is_dead,
    read_pkcs11_txt,
};
use rustix::io::Errno;

/// F172's fixture, with the profile directories under `/tmp/w`.
const PROFILES_INI: &str = "[General]\nStartWithLastProfile=1\nVersion=2\n\n[Profile1]\nName=other\nIsRelative=0\n\
Path=/tmp/w/pi-abs\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=abc.default-release\nDefault=1\n\n\
[Install4F96D1932A9F858E]\nDefault=abc.default-release\nLocked=1\n";

#[test]
fn profiles_ini_lists_relative_absolute_and_install_default() {
    let index = parse_profiles_ini("profiles.ini", PROFILES_INI.as_bytes()).unwrap();
    // The install default names the same directory as [Profile0]: it is listed once.
    let dirs = index.directories(Path::new("/tmp/w/pi"));
    assert_eq!(
        dirs,
        [
            PathBuf::from("/tmp/w/pi-abs"),
            PathBuf::from("/tmp/w/pi/abc.default-release")
        ]
    );
    assert_eq!(index.profiles[1].name.as_deref(), Some("default-release"));
    assert_eq!(index.install_defaults, ["abc.default-release"]);
    // The same text read as installs.ini gives the same answer.
    assert_eq!(
        parse_installs_ini("installs.ini", PROFILES_INI.as_bytes()).unwrap(),
        index
    );
}

#[test]
fn installs_ini_alone_names_install_defaults() {
    let index = parse_installs_ini(
        "installs.ini",
        b"[4F96D1932A9F858E]\nDefault=x.default\nLocked=1\n",
    )
    .unwrap();
    assert_eq!(index.profiles.len(), 0);
    // A section that is not an Install one carries no default: only `[Install...]` does.
    assert_eq!(index.install_defaults.len(), 0);
    let index = parse_installs_ini("installs.ini", b"[InstallABC]\nDefault=x.default\n").unwrap();
    assert_eq!(index.install_defaults, ["x.default"]);
}

#[test]
fn comments_crlf_bom_and_unknown_sections_are_accepted() {
    let text = "\u{feff}; comment\r\n# other\r\n[BackgroundTasksProfiles]\r\nx=1\r\n[Profile0]\r\nPath=p\r\nIsRelative=1\r\n";
    let index = parse_profiles_ini("profiles.ini", text.as_bytes()).unwrap();
    assert_eq!(index.profiles.len(), 1);
    assert!(index.profiles[0].relative);
    assert_eq!(index.profiles[0].path, "p");
}

#[test]
fn malformed_index_is_an_error_naming_the_file() {
    let oversize = vec![b'a'; MAX_FILE_LEN + 1];
    let cases: &[(&str, &[u8])] = &[
        ("entry without Path", b"[Profile0]\nName=x\nIsRelative=1\n"),
        ("empty Path", b"[Profile0]\nPath=\n"),
        ("unclosed header", b"[Profile0\nPath=x\n"),
        ("empty section name", b"[]\nPath=x\n"),
        ("NUL byte", b"[Profile0]\nPath=x\0y\n"),
        ("non-UTF-8", b"[Profile0]\nPath=\xff\xfe\n"),
        ("duplicate key", b"[Profile0]\nPath=x\nPath=y\n"),
        (
            "duplicate section",
            b"[Profile0]\nPath=x\n[Profile0]\nPath=y\n",
        ),
        ("key before section", b"Path=x\n[Profile0]\nPath=x\n"),
        ("line without equals", b"[Profile0]\nPath\n"),
        (
            "IsRelative not 0 or 1",
            b"[Profile0]\nPath=x\nIsRelative=yes\n",
        ),
        ("empty Default", b"[Install1]\nDefault=\n"),
        ("oversize", &oversize),
        ("empty", b""),
        ("only comments", b"; nothing\n"),
    ];
    for (what, bytes) in cases {
        for (file, parse) in [
            (
                "my/profiles.ini",
                parse_profiles_ini as fn(&str, &[u8]) -> _,
            ),
            ("my/installs.ini", parse_installs_ini),
        ] {
            let err = parse(file, bytes).expect_err(what);
            assert!(err.to_string().contains(file), "{what}: {err}");
            assert_eq!(err.file(), file);
        }
    }
    // Negative control: the sizes just inside the bound parse.
    let mut ok = b"[Profile0]\nPath=".to_vec();
    ok.resize(MAX_FILE_LEN - 1, b'a');
    ok.push(b'\n');
    assert!(parse_profiles_ini("profiles.ini", &ok).is_ok());
}

const PKCS11_TXT: &str = "library=\nname=NSS Internal PKCS #11 Module\nparameters=configdir='sql:/p' certPrefix='' \
keyPrefix='' secmod='secmod.db' flags= updatedir='' updateCertPrefix='' updateKeyPrefix='' updateid='' updateTokenDescription=''\n\
NSS=Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={slotFlags=[ECC,RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,\
MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512] askpw=any timeout=30})\n\nlibrary=/usr/lib/libcustodio_pkcs11.so\n\
name=custodio\n\nlibrary=p11-kit-proxy.so\nname=p11\nNSS=trustOrder=1\n\n";

#[test]
fn pkcs11_txt_reads_library_and_name_and_keeps_other_lines() {
    let entries = parse_pkcs11_txt("pkcs11.txt", PKCS11_TXT.as_bytes()).unwrap();
    let names: Vec<_> = entries
        .iter()
        .map(|e| (e.library.as_str(), e.name.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("", "NSS Internal PKCS #11 Module"),
            ("/usr/lib/libcustodio_pkcs11.so", "custodio"),
            ("p11-kit-proxy.so", "p11")
        ]
    );
    let internal: &ModuleEntry = &entries[0];
    assert_eq!(internal.other.len(), 2);
    assert_eq!(internal.other[0].0, "parameters");
    assert!(
        internal.other[0]
            .1
            .starts_with("configdir='sql:/p' certPrefix=''")
    );
    assert_eq!(internal.other[1].0, "NSS");
    assert!(
        internal.other[1]
            .1
            .contains("slotParams=(1={slotFlags=[ECC,RSA")
    );
    assert_eq!(
        entries[2].other,
        [("NSS".to_owned(), "trustOrder=1".to_owned())]
    );
    assert_eq!(entries[1].other.len(), 0);
    // No trailing blank line, CRLF and a comment are fine too.
    let entries = parse_pkcs11_txt("pkcs11.txt", b"# c\r\nlibrary=a\r\nname=b").unwrap();
    assert_eq!(
        (entries[0].library.as_str(), entries[0].name.as_str()),
        ("a", "b")
    );
    // Empty is a file with no module, not an error.
    assert_eq!(parse_pkcs11_txt("pkcs11.txt", b"").unwrap().len(), 0);
}

#[test]
fn pkcs11_txt_malformed_is_an_error() {
    let oversize = vec![b'\n'; MAX_FILE_LEN + 1];
    let cases: &[(&str, &[u8])] = &[
        ("no name", b"library=a\n"),
        ("no library", b"name=a\n"),
        ("unknown key", b"library=a\nname=b\nbogus=1\n"),
        ("no equals", b"library=a\nname=b\nwhat\n"),
        ("duplicate key", b"library=a\nname=b\nname=c\n"),
        ("NUL", b"library=a\nname=b\0\n"),
        ("non-UTF-8", b"library=a\nname=\xff\n"),
        ("second entry bad", b"library=a\nname=b\n\nlibrary=c\n"),
        ("oversize", &oversize),
    ];
    for (what, bytes) in cases {
        let err = parse_pkcs11_txt("home/pkcs11.txt", bytes).expect_err(what);
        assert!(err.to_string().contains("home/pkcs11.txt"), "{what}: {err}");
    }
}

#[test]
fn reading_pkcs11_txt_from_disk_tells_absent_from_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pkcs11.txt");
    assert_eq!(read_pkcs11_txt(&path).unwrap(), None);
    fs::write(&path, PKCS11_TXT).unwrap();
    assert_eq!(read_pkcs11_txt(&path).unwrap().unwrap().len(), 3);
    fs::write(&path, "junk\n").unwrap();
    let err = read_pkcs11_txt(&path).unwrap_err();
    assert!(err.to_string().contains(&path.display().to_string()));
    // A directory in its place is an error too, not "absent".
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(read_pkcs11_txt(&path).is_err());
    // An oversized file is refused without being parsed.
    fs::remove_dir(&path).unwrap();
    fs::write(&path, vec![b'\n'; MAX_FILE_LEN + 1]).unwrap();
    assert!(
        read_pkcs11_txt(&path)
            .unwrap_err()
            .to_string()
            .contains("longer")
    );
}

#[test]
fn fuzz_entry_points_reach_the_parsers() {
    assert!(fuzz_profile_index(PROFILES_INI.as_bytes()));
    assert!(!fuzz_profile_index(b"[Profile0\n"));
    assert!(!fuzz_profile_index(b"\xff\0"));
    assert!(fuzz_nss_modules(PKCS11_TXT.as_bytes()));
    assert!(!fuzz_nss_modules(b"bogus=1\n"));
    assert!(!fuzz_nss_modules(b"\0"));
}

// ---- lock state ---------------------------------------------------------------------------------------------------

/// A fixed fixture address for "this host": the code's own lookup never produces the expected value.
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 1, 2, 3);

fn profile() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// A child that holds the `fcntl` write lock of `path` until its stdin closes (the test binary run again).
struct Holder(
    Child,
    #[allow(dead_code, reason = "keeps the pipe open so the child can print")]
    BufReader<std::process::ChildStdout>,
);

impl Holder {
    fn start(path: &Path) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lock_holder_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CUSTODIO_HOLD_LOCK", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("held") {
            line.clear();
            assert_ne!(
                out.read_line(&mut line).unwrap(),
                0,
                "the holder ended before it held the lock"
            );
        }
        Self(child, out)
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}

/// Not a test of its own: the child of [`Holder`]. Without the variable it does nothing.
#[test]
fn lock_holder_helper() {
    use std::io::{Read, Write};
    let Some(path) = std::env::var_os("CUSTODIO_HOLD_LOCK") else {
        return;
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    println!("held");
    std::io::stdout().flush().unwrap();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

fn live_pid() -> (Child, i32) {
    let child = Command::new("sleep").arg("1000").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    (child, pid)
}

fn dead_pid() -> i32 {
    let mut child = Command::new("true").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    child.wait().unwrap();
    pid
}

#[test]
fn lock_state_follows_the_rule() {
    // absent: free (the naive rule agrees)
    let p = profile();
    assert_eq!(lock_state(p.path(), LOCAL), LockState::Free);

    // stale: a local address and a dead pid (the naive "lock exists" rule says held)
    let p = profile();
    symlink(format!("{LOCAL}:+{}", dead_pid()), p.path().join("lock")).unwrap();
    assert_eq!(lock_state(p.path(), LOCAL), LockState::Free);

    // live local pid
    let (mut child, pid) = live_pid();
    let p = profile();
    symlink(format!("{LOCAL}:+{pid}"), p.path().join("lock")).unwrap();
    assert_eq!(
        lock_state(p.path(), LOCAL),
        LockState::Held(HeldReason::LiveProcess(pid))
    );
    // the same link with a dead pid is the control: only the pid differs
    child.kill().unwrap();
    child.wait().unwrap();

    // foreign host with a live pid, and with a dead one (an address that is not ours proves nothing about the pid)
    let (mut child, pid) = live_pid();
    for pid in [pid, dead_pid()] {
        let p = profile();
        symlink(format!("10.99.99.99:+{pid}"), p.path().join("lock")).unwrap();
        assert_eq!(
            lock_state(p.path(), LOCAL),
            LockState::Held(HeldReason::ForeignHost("10.99.99.99".into()))
        );
    }
    child.kill().unwrap();
    child.wait().unwrap();

    // `.parentlock` fcntl-held by another process (the naive rule says free)
    let p = profile();
    let parent = p.path().join(".parentlock");
    fs::write(&parent, "").unwrap();
    {
        let _holder = Holder::start(&parent);
        assert_eq!(
            lock_state(p.path(), LOCAL),
            LockState::Held(HeldReason::ParentLock)
        );
    }
    // `.parentlock` present and nobody holds it: free, and still free after the holder ended
    assert_eq!(lock_state(p.path(), LOCAL), LockState::Free);
    // and the probe released its own lock: a second probe works
    assert_eq!(lock_state(p.path(), LOCAL), LockState::Free);

    // `.parentlock` not readable by us as a file at all: held, not guessed free
    let p = profile();
    fs::create_dir(p.path().join(".parentlock")).unwrap();
    assert_eq!(
        lock_state(p.path(), LOCAL),
        LockState::Held(HeldReason::ParentLock)
    );
}

#[test]
fn an_unparseable_lock_is_held() {
    for target in [
        "garbage",
        "10.1.2.3:+",
        "10.1.2.3:+0",
        "10.1.2.3:+-4",
        "10.1.2.3:+x",
        ":+5",
        "10.1.2:+5",
        "10.1.2.3+5",
    ] {
        let p = profile();
        symlink(target, p.path().join("lock")).unwrap();
        assert_eq!(
            lock_state(p.path(), LOCAL),
            LockState::Held(HeldReason::UnparseableLock),
            "{target}"
        );
    }
    // a regular file called `lock` is not a link to a process either
    let p = profile();
    fs::write(p.path().join("lock"), "10.1.2.3:+1").unwrap();
    assert_eq!(
        lock_state(p.path(), LOCAL),
        LockState::Held(HeldReason::UnparseableLock)
    );
}

#[test]
fn kill_errors_map_to_lock_state() {
    assert!(pid_is_dead(Err(Errno::SRCH)));
    assert!(!pid_is_dead(Err(Errno::PERM)));
    assert!(!pid_is_dead(Err(Errno::INVAL)));
    assert!(!pid_is_dead(Ok(())));
}

#[test]
fn local_address_is_an_address_and_the_rule_uses_the_one_given() {
    // The lookup may give anything; what matters is that a link to it, with a live pid, is held (not foreign).
    let local = custodio_cli::browser_files::local_address();
    let (mut child, pid) = live_pid();
    let p = profile();
    symlink(format!("{local}:+{pid}"), p.path().join("lock")).unwrap();
    assert_eq!(
        lock_state(p.path(), local),
        LockState::Held(HeldReason::LiveProcess(pid))
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let path = e.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path.clone());
            }
            let bytes = if meta.is_file() {
                fs::read(&path).unwrap()
            } else {
                fs::read_link(&path)
                    .map(|l| l.into_os_string().into_encoded_bytes())
                    .unwrap_or_default()
            };
            out.push((path, bytes, meta.modified().unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn parsing_and_discovery_change_nothing() {
    use custodio_cli::register_discover::{Environment, discover};
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join(".mozilla/firefox");
    // one profile with `.parentlock` and a stale link, one with neither `.parentlock` nor `cert9.db`
    let (a, b) = (root.join("a.default"), root.join("b.default"));
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    for f in ["cert9.db", "key4.db", ".parentlock"] {
        fs::write(a.join(f), f).unwrap();
    }
    fs::write(a.join("pkcs11.txt"), PKCS11_TXT).unwrap();
    symlink(format!("{LOCAL}:+{}", dead_pid()), a.join("lock")).unwrap();
    fs::write(
        root.join("profiles.ini"),
        "[Profile0]\nPath=a.default\nIsRelative=1\n[Profile1]\nPath=b.default\nIsRelative=1\n",
    )
    .unwrap();
    let before = snapshot(home.path());
    let env = Environment {
        home: home.path().to_owned(),
        xdg_config_home: None,
        local_address: LOCAL,
    };
    let found = discover(&env).unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|p| p.lock == LockState::Free));
    read_pkcs11_txt(&a.join("pkcs11.txt")).unwrap();
    assert_eq!(snapshot(home.path()), before);
    assert!(
        !b.join(".parentlock").exists(),
        "probing must not create `.parentlock`"
    );
    assert!(!b.join("cert9.db").exists());
}
