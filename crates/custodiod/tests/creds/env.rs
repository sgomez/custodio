//! The environment of the `creds` tests: the real `systemd-creds` daemon without root or PID 1, and the
//! command with an explicit TPM device. `docs/findings/F110.md` ("Dev container") has the recipe.
//!
//! The daemon runs as root of a user namespace (`unshare --map-root-user`, the uids 1-998 mapped from
//! `/etc/subuid`), socket activated (`systemd-socket-activate --fdname=varlink`) on a socket in the
//! test's directory, with its `/var/lib/systemd` bound to a directory on a real file system (a tmpfs
//! gives "no encryption key available"). The test process is a client of that socket as the uid of the
//! namespace's root. A missing tool fails the test: nothing here skips.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use tempfile::TempDir;

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const NAMESPACE: [&str; 4] = [
    "--map-root-user",
    "--map-users=auto",
    "--map-groups=auto",
    "-m",
];

/// Runs the host-secret daemon on `$2` with `/var/lib/systemd` from `$1` (a directory, or `tmpfs`).
const DAEMON: &str = r#"set -e
mount -t tmpfs t /run/systemd
# A host TPM the namespace cannot open fails every Encrypt (ENOTRECOVERABLE) instead of binding to the host.
if [ -d /sys/class/tpmrm ]; then mount -t tmpfs t /sys/class/tpmrm; fi
if [ "$1" = tmpfs ]; then mount -t tmpfs t /var/lib/systemd; else mount --bind "$1" /var/lib/systemd; fi
exec systemd-socket-activate -a --fdname=varlink -l "$2" systemd-creds"#;

/// A directory on a real file system: the host secret on a tmpfs gives "no encryption key available".
/// `/tmp` is one on most hosts, and the mutation run copies the tree there, so the build directory is
/// not a safe choice either: the first candidate that is not a RAM file system is taken.
fn real_file_system() -> TestResult<PathBuf> {
    let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    for candidate in [
        build,
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev/shm/.."),
    ] {
        let Ok(path) = candidate.canonicalize() else {
            continue;
        };
        let kind = Command::new("stat")
            .args(["-f", "-c", "%T"])
            .arg(&path)
            .output()?;
        let kind = String::from_utf8_lossy(&kind.stdout);
        if !matches!(kind.trim(), "tmpfs" | "ramfs" | "") {
            return Ok(path);
        }
    }
    Err("no directory on a real file system for the host secret".into())
}

/// The daemon and the directories around it.
pub struct Daemon {
    pub dir: TempDir,
    /// The socket's own directory, under the temporary directory: the other uids of the namespace must
    /// reach it, and the path to the build directory may not let them (`/home/runner` is `0750` in CI).
    _sock_dir: TempDir,
    pub socket: PathBuf,
    pub lib: PathBuf,
    child: Child,
}

impl Daemon {
    /// A daemon with a host secret on a real file system.
    pub fn start() -> TestResult<Self> {
        Self::spawn(false)
    }

    /// A daemon whose `/var/lib/systemd` is a tmpfs, so it cannot make the host secret.
    pub fn without_host_secret() -> TestResult<Self> {
        Self::spawn(true)
    }

    fn spawn(tmpfs: bool) -> TestResult<Self> {
        let dir = tempfile::Builder::new()
            .prefix("custodio-creds.")
            .tempdir_in(real_file_system()?)?;
        let lib = dir.path().join("lib");
        fs::create_dir(&lib)?;
        let sock_dir = tempfile::Builder::new()
            .prefix("custodio-creds-sock.")
            .tempdir()?;
        fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o755))?;
        let socket = sock_dir.path().join("sock");
        let log = fs::File::create(dir.path().join("daemon.log"))?;
        let child = Command::new("unshare")
            .args(NAMESPACE)
            .args(["bash", "-c", DAEMON, "daemon"])
            .arg(if tmpfs { Path::new("tmpfs") } else { &lib })
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .map_err(|e| format!("cannot run `unshare` (util-linux): {e}"))?;
        let mut daemon = Self {
            dir,
            _sock_dir: sock_dir,
            socket,
            lib,
            child,
        };
        daemon.wait_for_socket()?;
        // Other uids of the namespace connect too (the unit's socket is 0666).
        fs::set_permissions(&daemon.socket, fs::Permissions::from_mode(0o666))?;
        daemon.write_wrapper()?;
        // Let a concurrent fork in another test finish before the script is first run.
        sleep(Duration::from_millis(50));
        Ok(daemon)
    }

    fn wait_for_socket(&mut self) -> TestResult {
        let start = Instant::now();
        while !self.socket.exists() {
            if let Some(status) = self.child.try_wait()? {
                let log = fs::read_to_string(self.dir.path().join("daemon.log"))?;
                return Err(format!("the daemon quit ({status}): {log}").into());
            }
            if start.elapsed() > Duration::from_secs(20) {
                return Err("the daemon's socket did not appear".into());
            }
            sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    /// Replaces the host secret, as a changed host key.
    pub fn replace_host_secret(&self) -> TestResult {
        let path = self.lib.join("credential.secret");
        assert!(path.exists(), "the daemon made no host secret yet");
        fs::remove_file(&path)?;
        let mut bytes = vec![0u8; 4096];
        std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut bytes)?;
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        Ok(())
    }

    /// The command `systemd-creds` as root of a namespace with this daemon's `/var/lib/systemd`,
    /// recording its arguments and environment in `calls.log` first. Returns the script's path.
    pub fn wrapper(&self) -> PathBuf {
        self.dir.path().join("systemd-creds-wrapper")
    }

    /// Written once, when the daemon starts: rewriting a script that other threads may be about to run
    /// races with their `fork` (the child holds the write descriptor: "Text file busy").
    fn write_wrapper(&self) -> TestResult {
        let path = self.wrapper();
        let log = self.dir.path().join("calls.log");
        let script = format!(
            "#!/bin/bash\n{{ printf 'ARG %s\\n' \"$@\"; env; }} >> '{}'\n\
             exec unshare -m --map-root-user bash -c \
             'mount --bind \"$0\" /var/lib/systemd; exec systemd-creds \"$@\"' '{}' \"$@\"\n",
            log.display(),
            self.lib.display()
        );
        fs::write(&path, script)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    pub fn calls_log(&self) -> String {
        fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `argv` as the uid in the namespace (not root), against `socket` by `varlinkctl`.
pub fn varlink_as_uid(
    uid: u32,
    socket: &Path,
    method: &str,
    json: &str,
) -> TestResult<(bool, String)> {
    let out = Command::new("unshare")
        .args(NAMESPACE)
        .arg("setpriv")
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={uid}"))
        .arg("--clear-groups")
        .args(["varlinkctl", "call", "--json=short"])
        .arg(format!("unix:{}", socket.display()))
        .arg(format!("io.systemd.Credentials.{method}"))
        .arg(json)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run `unshare`/`setpriv`/`varlinkctl`: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

/// Every file under `roots` (unreadable ones skipped) that holds `needle`.
pub fn files_holding(roots: &[&Path], needles: &[&[u8]]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
    while let Some(path) = todo.pop() {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                // Build output is not a place the service writes; it is also gigabytes.
                todo.extend(
                    entries
                        .flatten()
                        .filter(|e| e.file_name() != "target" && e.file_name() != ".git")
                        .map(|e| e.path()),
                );
            }
        } else if meta.is_file()
            && meta.len() < 64 << 20
            && let Ok(bytes) = fs::read(&path)
            && needles
                .iter()
                .any(|n| bytes.windows(n.len()).any(|w| w == *n))
        {
            found.push(path);
        }
    }
    found
}
