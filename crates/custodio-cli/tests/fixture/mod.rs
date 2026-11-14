//! Fixture homes, real `modutil`/`certutil`, and the built module, for the `register_native` tests.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;

use custodio_cli::register_discover::Environment;
use custodio_cli::register_native::{Entry, MODULE_FILE, Options, Report, parse_entries, run};
use tempfile::TempDir;

pub const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 1, 2, 3);

static BUILT: Once = Once::new();

/// The built module (cargo does not build the `cdylib` for the tests of another package): built here, once, from the
/// current tree. A build that fails fails the test.
pub fn built_module() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
    let target = dir.parent().unwrap().to_path_buf();
    BUILT.call_once(|| {
        let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        build.args(["build", "--quiet", "--locked", "-p", "custodio-pkcs11"]);
        build.arg("--target-dir").arg(&target);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().is_ok_and(|s| s.success()),
            "building the module failed"
        );
    });
    let path = dir.join(MODULE_FILE);
    assert!(path.exists(), "{} was not built", path.display());
    path
}

/// A home directory with profiles, and a library directory whose `libcustodio_pkcs11.so` is the built module.
pub struct Fixture {
    pub dir: TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        let f = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(f.home()).unwrap();
        f
    }

    pub fn home(&self) -> PathBuf {
        fs::canonicalize(self.dir.path()).unwrap().join("home")
    }

    /// A library named like the module under `lib<tag>/`, a link to the built one.
    pub fn module(&self, tag: &str) -> PathBuf {
        let dir = self.dir.path().join(format!("lib{tag}"));
        fs::create_dir_all(&dir).unwrap();
        let path = fs::canonicalize(&dir).unwrap().join(MODULE_FILE);
        if !path.exists() {
            symlink(built_module(), &path).unwrap();
        }
        path
    }

    /// A root with `profiles.ini` naming `names`; each profile is made by `certutil -N`.
    pub fn root(&self, rel: &str, names: &[&str]) -> PathBuf {
        let root = self.home().join(rel);
        fs::create_dir_all(&root).unwrap();
        let mut ini = String::from("[General]\nVersion=2\n");
        for (i, n) in names.iter().enumerate() {
            new_profile(&root.join(n));
            writeln!(ini, "[Profile{i}]\nName=n{i}\nIsRelative=1\nPath={n}\n").unwrap();
        }
        fs::write(root.join("profiles.ini"), ini).unwrap();
        root
    }

    pub fn env(&self) -> Environment {
        Environment {
            home: self.home(),
            xdg_config_home: None,
            nss_config: self.dir.path().join("nss.config"),
            local_address: LOCAL,
        }
    }

    pub fn run(&self, module: &Path, remove: bool) -> Report {
        run(
            &self.env(),
            &Options {
                module: module.to_owned(),
                modutil: OsString::from("modutil"),
                remove,
            },
        )
        .unwrap()
    }

    /// Every file under the home (and the scratch siblings): path to content, links to their target.
    pub fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut all = BTreeMap::new();
        walk(&self.home(), &mut all);
        all
    }

    /// The command binary on this home, with `PATH` and extra environment.
    pub fn command(&self, args: &[&str], path: &Path, env: &[(&str, &str)], root: bool) -> Command {
        let bin = env!("CARGO_BIN_EXE_custodio-cli");
        let mut c = if root {
            // uid 0 in a user namespace: the command sees an effective uid of 0
            let mut c = Command::new("/usr/bin/unshare");
            c.arg("-Ur").arg(bin);
            c
        } else {
            Command::new(bin)
        };
        c.args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", path);
        for (k, v) in env {
            c.env(k, v);
        }
        c
    }

    pub fn binary(&self, args: &[&str], path: &Path, env: &[(&str, &str)]) -> Output {
        self.command(args, path, env, false).output().unwrap()
    }

    /// A directory holding a `modutil` that is this shell `script`.
    pub fn stub(&self, tag: &str, script: &str) -> PathBuf {
        let dir = self.dir.path().join(format!("stub-{tag}"));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("modutil");
        fs::write(&file, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    pub fn marker(&self) -> PathBuf {
        self.dir.path().join("marker")
    }
}

fn walk(dir: &Path, all: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    for p in names {
        let meta = fs::symlink_metadata(&p).unwrap();
        if meta.is_symlink() {
            all.insert(
                p.clone(),
                fs::read_link(&p)
                    .unwrap()
                    .into_os_string()
                    .into_encoded_bytes(),
            );
        } else if meta.is_dir() {
            all.insert(p.clone(), b"<dir>".to_vec());
            walk(&p, all);
        } else {
            all.insert(p.clone(), fs::read(&p).unwrap());
        }
    }
}

pub fn new_profile(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let status = Command::new("certutil")
        .args(["-N", "--empty-password", "-d"])
        .arg(format!("sql:{}", dir.display()))
        .status()
        .unwrap();
    assert!(status.success(), "certutil -N failed");
}

/// The entries of a profile's `pkcs11.txt`.
pub fn entries(profile: &Path) -> Vec<Entry> {
    parse_entries(&fs::read_to_string(profile.join("pkcs11.txt")).unwrap_or_default())
}

/// `modutil -list` of a profile, by the real tool.
pub fn modutil_list(profile: &Path) -> String {
    let out = Command::new("modutil")
        .arg("-dbdir")
        .arg(format!("sql:{}", profile.display()))
        .arg("-list")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "modutil -list failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// How many modules `modutil -list` shows with this library.
pub fn listed(profile: &Path, library: &Path) -> usize {
    modutil_list(profile)
        .matches(&format!("library name: {}", library.display()))
        .count()
}

/// Add the module by hand, as a person would, under `name`.
pub fn add_by_hand(profile: &Path, name: &str, library: &Path) {
    let out = Command::new("modutil")
        .arg("-dbdir")
        .arg(format!("sql:{}", profile.display()))
        .args(["-add", name, "-libfile"])
        .arg(library)
        .arg("-force")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "modutil -add failed");
}

/// Append an entry to `pkcs11.txt` as text: for a library that cannot be loaded (`modutil` would refuse it).
pub fn write_entry(profile: &Path, name: &str, library: &str) {
    let path = profile.join("pkcs11.txt");
    let mut text = fs::read_to_string(&path).unwrap();
    write!(text, "library={library}\nname={name}\n\n").unwrap();
    fs::write(path, text).unwrap();
}

static SERVER_BUILT: Once = Once::new();

/// The real service on a private bus (the test-only server of `custodio-it` runs the service code with a scripted
/// polkit that approves), with the key and certificate of `p256.p12` imported through the service.
pub struct Service {
    pub address: String,
    bus: std::process::Child,
    server: std::process::Child,
    _state: TempDir,
}

impl Service {
    /// Builds the server from the current tree (once), then starts it. A failure to build or start fails the test.
    pub fn start(key: &str) -> Self {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        let exe = std::env::current_exe().unwrap();
        let dir = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
        SERVER_BUILT.call_once(|| {
            let mut build =
                Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
            build.args([
                "build",
                "--quiet",
                "--locked",
                "-p",
                "custodio-it",
                "--example",
                "docs_api_server",
            ]);
            build.arg("--target-dir").arg(dir.parent().unwrap());
            if !cfg!(debug_assertions) {
                build.arg("--release");
            }
            assert!(
                build.status().is_ok_and(|s| s.success()),
                "building the test server failed"
            );
        });
        let server_bin = dir.join("examples/docs_api_server");
        assert!(
            server_bin.exists(),
            "{} was not built",
            server_bin.display()
        );
        let mut bus = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        BufReader::new(bus.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let address = address.trim().to_owned();
        let state = tempfile::tempdir().unwrap();
        fs::create_dir(state.path().join("keys")).unwrap();
        fs::set_permissions(state.path().join("keys"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(state.path().join("ctl")).unwrap();
        fs::write(state.path().join("ctl/mode"), "approve").unwrap();
        let mut server = Command::new(&server_bin)
            .arg(&address)
            .arg(state.path().join("keys"))
            .arg(state.path().join("ctl"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = server.stdout.take().unwrap();
        let service = Self {
            address,
            bus,
            server,
            _state: state,
        };
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), "ready", "the test server did not start");
        service.import(key);
        service
    }

    fn import(&self, key: &str) {
        use custodio_cli::Importer;
        let conn =
            zbus::block_on(zbus::connection::Builder::address(self.address.as_str()).build())
                .unwrap();
        let p12 = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../custodio-it/tests/fixtures/p256.p12"
        ))
        .unwrap();
        let password = secrecy::SecretString::from("test-password".to_owned());
        custodio_cli::bus::DbusImporter::new(conn)
            .import_p12(key, &p12, &password)
            .expect("the import through the service");
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        for child in [&mut self.server, &mut self.bus] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
