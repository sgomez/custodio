//! A software TPM (`swtpm`) per test.
//!
//! Every [`Swtpm`] is its own `swtpm` process on a private socket, with fresh state in a new
//! directory of its own, `TPM2_Startup` already done. Tests run in parallel, so nothing here reads
//! or writes the process environment: the TCTI string is handed out ([`Swtpm::tcti`], usable by
//! `tss-esapi` and by `tpm2-tools`), and [`Swtpm::tool`] sets it on the child it runs.
//!
//! `swtpm` cannot be signalled in the dev container (`kill` fails with EPERM, even SIGKILL), so it
//! is stopped over its control socket with `swtpm_ioctl -s`, as `scripts/with-swtpm.sh` does; the
//! signal is the fallback, and the wait is bounded. Dropping an instance stops it and removes its
//! state, also while a panic unwinds. A test binary killed without unwinding (`timeout`, nextest's
//! fail-fast) runs no `Drop`: a guardian shell between it and `swtpm` gets the parent-death signal,
//! which the confined `swtpm` would refuse, and stops it the same way.
//!
//! Starting fails with an error that names the missing tool when `swtpm` or `tpm2-tools` are not
//! installed; tests unwrap it, so they fail instead of skipping.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Tools the fixture runs. Checked up front so a missing one is reported by name.
const REQUIRED_TOOLS: [(&str, &str); 9] = [
    ("swtpm", "swtpm"),
    ("setpriv", "util-linux"),
    ("timeout", "coreutils"),
    ("bash", "bash"),
    ("swtpm_ioctl", "swtpm-tools"),
    ("tpm2_startup", "tpm2-tools"),
    ("tpm2_getcap", "tpm2-tools"),
    ("tpm2_pcrextend", "tpm2-tools"),
    ("tpm2_clear", "tpm2-tools"),
];

/// Runs `swtpm` (`$3...`), writes its pid to the state directory (`$2`) and waits for it. On SIGTERM, the
/// parent-death signal, it stops `swtpm` over the control socket (`$1`) and removes the state directory.
const GUARDIAN: &str = r#"ctrl=$1 dir=$2; shift 2
"$@" & swtpm=$!
echo "$swtpm" > "$dir/swtpm.pid"
trap 'timeout 10 swtpm_ioctl --unix "$ctrl" -s >/dev/null 2>&1; wait "$swtpm"; rm -rf "$dir"; exit 0' TERM
wait "$swtpm""#;
const STOP_GRACE: Duration = Duration::from_secs(2);
const STOP_WAIT: Duration = Duration::from_secs(5);
const START_WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// One software TPM. Dropping it stops `swtpm` and removes its state directory.
#[derive(Debug)]
pub struct Swtpm {
    dir: PathBuf,
    child: Option<Child>,
    pid: u32,
}

fn find_in_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(tool).is_file()))
}

/// Whether a process with this pid exists (a zombie counts: it is not gone until reaped).
#[must_use]
pub fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

impl Swtpm {
    /// Starts a new, independent `swtpm` with fresh state.
    ///
    /// # Errors
    /// A required tool is missing (the message names it and the package), or `swtpm` does not come up.
    pub fn start() -> io::Result<Self> {
        for (tool, package) in REQUIRED_TOOLS {
            if !find_in_path(tool) {
                return Err(io::Error::other(format!(
                    "swtpm fixture: `{tool}` not found in PATH (Debian/Ubuntu: apt install {package})"
                )));
            }
        }
        let dir = std::env::temp_dir().join(format!(
            "custodio-swtpm.{}.{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let mut tpm = Self {
            dir,
            child: None,
            pid: 0,
        };
        // On error `tpm` is dropped here and the directory removed.
        tpm.spawn()?;
        Ok(tpm)
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("swtpm.sock")
    }

    fn ctrl_socket(&self) -> PathBuf {
        self.dir.join("swtpm.sock.ctrl")
    }

    /// Starts the `swtpm` process on the state directory and runs `TPM2_Startup(CLEAR)`.
    fn spawn(&mut self) -> io::Result<()> {
        let sock = self.socket();
        let ctrl = self.ctrl_socket();
        // A stale socket from a previous run would make the readiness wait return too early.
        for stale in [&sock, &ctrl] {
            match fs::remove_file(stale) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        let log = fs::File::create(self.dir.join("swtpm.log"))?;
        // The shell closes every inherited descriptor above stderr first: the TSS libraries open their sockets
        // without close-on-exec, so a `swtpm` forked while another test holds a TCTI connection would keep the
        // client end open for its whole life, and the single-client `swtpm` of that test would never see it close.
        // `setpriv` then execs the guardian with a parent-death signal; the guardian starts `swtpm`.
        let mut child = Command::new("bash")
            .args([
                "-c",
                "for f in /proc/self/fd/*; do n=${f##*/}; [ \"$n\" -gt 2 ] && eval \"exec $n>&-\"; done 2>/dev/null; exec \"$@\"",
                "close-fds",
                "setpriv",
                "--pdeathsig",
                "TERM",
                "bash",
                "-c",
                GUARDIAN,
                "guardian",
            ])
            .arg(&ctrl)
            .arg(&self.dir)
            .args([
                "swtpm",
                "socket",
                "--tpm2",
                "--flags",
                "not-need-init",
            ])
            .arg("--tpmstate")
            .arg(format!("dir={}", self.dir.display()))
            .arg("--server")
            .arg(format!("type=unixio,path={}", sock.display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={}", ctrl.display()))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let pid_file = self.dir.join("swtpm.pid");
        let deadline = Instant::now() + START_WAIT;
        loop {
            if sock.exists()
                && ctrl.exists()
                && let Some(pid) = fs::read_to_string(&pid_file)
                    .ok()
                    .and_then(|p| p.trim().parse().ok())
            {
                self.pid = pid;
                break;
            }
            if let Some(status) = child.try_wait()? {
                let log = fs::read_to_string(self.dir.join("swtpm.log")).unwrap_or_default();
                return Err(io::Error::other(format!(
                    "swtpm exited at start ({status}): {log}"
                )));
            }
            if Instant::now() > deadline {
                self.child = Some(child);
                return Err(io::Error::other("swtpm did not create its sockets in time"));
            }
            sleep(POLL);
        }
        self.child = Some(child);
        let out = self.tool("tpm2_startup", ["-c"])?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "TPM2_Startup failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// Stops the process: over the control socket first, by signal as fallback, with a bounded wait.
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if self.ctrl_socket().exists() {
            // Best effort: the signal below is the fallback.
            let _ = Command::new("timeout")
                .args(["10", "swtpm_ioctl", "--unix"])
                .arg(self.ctrl_socket())
                .arg("-s")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let start = Instant::now();
        let mut signalled = false;
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            let waited = start.elapsed();
            if !signalled && waited > STOP_GRACE {
                let _ = child.kill();
                signalled = true;
            }
            if waited > STOP_WAIT {
                eprintln!(
                    "swtpm fixture: warning: swtpm (pid {}) did not stop",
                    self.pid
                );
                return;
            }
            sleep(POLL);
        }
    }

    /// The TCTI string for this instance, valid for `tss-esapi` (`TctiNameConf::from_str`) and
    /// `tpm2-tools` (`TPM2TOOLS_TCTI`). It stays valid across [`Swtpm::restart`].
    #[must_use]
    pub fn tcti(&self) -> String {
        format!("swtpm:path={}", self.socket().display())
    }

    /// The private state directory (it holds the sockets, the log and the TPM state).
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.dir
    }

    /// The pid of the current `swtpm` process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Runs a `tpm2-tools` command against this instance, without touching the process environment.
    ///
    /// # Errors
    /// The command cannot be started. A non-zero exit is in the returned [`Output`].
    pub fn tool<I, S>(&self, name: &str, args: I) -> io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        // Bounded: a tool that hangs fails the test instead of the run.
        Command::new("timeout")
            .args(["--kill-after=5", "60", name])
            .args(args)
            .env("TPM2TOOLS_TCTI", self.tcti())
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .output()
    }

    /// Like [`Swtpm::tool`], but a non-zero exit is an error carrying stderr; returns stdout.
    ///
    /// # Errors
    /// The command cannot be started or exits non-zero.
    pub fn tool_ok<I, S>(&self, name: &str, args: I) -> io::Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<S> = args.into_iter().collect();
        let shown = args
            .iter()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let out = self.tool(name, args)?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(io::Error::other(format!(
                "{name} {shown} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )))
        }
    }

    /// Extends a PCR of the SHA-256 bank with a digest given as 64 hex digits.
    ///
    /// # Errors
    /// `tpm2_pcrextend` fails.
    pub fn extend_pcr(&self, index: u32, sha256_hex: &str) -> io::Result<()> {
        self.tool_ok("tpm2_pcrextend", [format!("{index}:sha256={sha256_hex}")])
            .map(drop)
    }

    /// Stops `swtpm` and starts it again on the same state, then runs `TPM2_Startup(CLEAR)`:
    /// persistent objects survive, PCRs are reset. The TCTI string stays the same.
    ///
    /// # Errors
    /// `swtpm` does not come up again.
    pub fn restart(&mut self) -> io::Result<()> {
        self.stop();
        self.spawn()
    }

    /// Clears the TPM with `tpm2_clear` (lockout hierarchy, empty auth): persistent objects are
    /// flushed and the owner (storage) seed changes. The endorsement seed does not.
    ///
    /// # Errors
    /// `tpm2_clear` fails.
    pub fn clear(&self) -> io::Result<()> {
        self.tool_ok("tpm2_clear", [""; 0]).map(drop)
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}
