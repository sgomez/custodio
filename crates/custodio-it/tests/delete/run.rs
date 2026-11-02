//! The real `custodio` binary run as a child, with or without a controlling terminal.

// `tests/delete.rs` and `tests/agent.rs` share this module and each uses a part of it.
#![allow(dead_code)]

use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use custodio_cli::ServiceFailure;

use super::rig::{Rig, TestResult, WAIT};

/// Builds the binary (cargo does not build the binary of another package for these tests) and
/// returns `target/<profile>/custodio-cli`, next to the `deps` directory of this test binary.
static BUILT: Once = Once::new();

pub fn binary() -> Result<PathBuf, Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .and_then(|d| d.parent())
        .ok_or("no target dir")?
        .to_path_buf();
    let target = dir.parent().ok_or("no target dir")?.to_path_buf();
    BUILT.call_once(|| {
        let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        build.args(["build", "--quiet", "--locked", "-p", "custodio-cli"]);
        build.arg("--target-dir").arg(&target);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().is_ok_and(|s| s.success()),
            "building custodio-cli failed"
        );
    });
    let path = dir.join("custodio-cli");
    assert!(path.exists(), "{} was not built", path.display());
    Ok(path)
}

/// A running `custodio` and, if it has one, the master end of its controlling terminal.
pub struct Run {
    pub child: Child,
    pub master: Option<File>,
    pub screen: Arc<Mutex<Vec<u8>>>,
    pub stop: Arc<AtomicBool>,
    /// Kept open so the terminal does not report a hang-up before the child opens it.
    pub _slave: Option<OwnedFd>,
}

pub struct Finished {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// What the child gets as standard input.
#[derive(Clone, Copy)]
pub enum Stdin<'a> {
    /// A pipe holding these bytes.
    Pipe(&'a [u8]),
    /// The slave end of the pseudo-terminal (a terminal even without a controlling terminal).
    Tty,
    /// A regular file.
    File,
}

impl Run {
    pub fn start(
        rig: &Rig,
        args: &[&str],
        env: &[(&str, &str)],
        terminal: bool,
        stdin: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        Self::start_with(rig, args, env, terminal, Stdin::Pipe(stdin))
    }

    /// With `terminal`, the child is a session leader whose controlling terminal is a new
    /// pseudo-terminal; without, a session leader with none. Standard input is a pipe holding
    /// `stdin`, standard output and error are pipes: only `/dev/tty` is the terminal.
    pub fn start_with(
        rig: &Rig,
        args: &[&str],
        env: &[(&str, &str)],
        terminal: bool,
        stdin: Stdin<'_>,
    ) -> Result<Self, Box<dyn Error>> {
        Self::start_inner(rig, args, env, terminal, &stdin, false)
    }

    /// Like `start_with`, but `custodio` is a background job of a shell that is the session
    /// leader, so the binary is not the leader and its death hangs nothing up. The shell writes
    /// the pid of `custodio` to `rig.dir/cli.pid`.
    pub fn start_in_shell(
        rig: &Rig,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Result<Self, Box<dyn Error>> {
        Self::start_inner(rig, args, env, true, &Stdin::Tty, true)
    }

    fn start_inner(
        rig: &Rig,
        args: &[&str],
        env: &[(&str, &str)],
        terminal: bool,
        stdin: &Stdin<'_>,
        shell: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let mut master = None;
        let mut slave_fd = -1;
        let mut slave_keep = None;
        if terminal || matches!(*stdin, Stdin::Tty) {
            // SAFETY: plain libc calls on descriptors this function owns.
            unsafe {
                let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
                assert!(m >= 0 && libc::grantpt(m) == 0 && libc::unlockpt(m) == 0);
                let master_file = File::from(OwnedFd::from_raw_fd(m));
                let mut name = [0 as libc::c_char; 128];
                assert_eq!(libc::ptsname_r(m, name.as_mut_ptr(), name.len()), 0);
                let s = libc::open(
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                );
                assert!(s >= 0);
                slave_keep = Some(OwnedFd::from_raw_fd(s));
                slave_fd = s;
                master = Some(master_file);
            }
        }
        // Without `terminal` the slave is not made the controlling terminal below.
        let ctty_fd = if terminal { slave_fd } else { -1 };
        let mut command;
        if shell {
            command = Command::new("sh");
            command
                .arg("-c")
                .arg(r#"exec 3<&0; "$0" "$@" <&3 & echo $! > "$CLI_PIDFILE"; wait"#)
                .arg(binary()?);
        } else {
            command = Command::new(binary()?);
        }
        command
            .args(args)
            .env_clear()
            .env("DBUS_SYSTEM_BUS_ADDRESS", &rig.bus.address)
            .envs(env.iter().copied())
            .stdin(match stdin {
                Stdin::Pipe(_) => Stdio::piped(),
                Stdin::Tty => Stdio::from(slave_keep.as_ref().ok_or("no terminal")?.try_clone()?),
                Stdin::File => Stdio::from(File::open("/dev/null")?),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if shell {
            command.env("CLI_PIDFILE", rig.dir.path().join("cli.pid"));
        }
        // SAFETY: only async-signal-safe calls (`setsid`, `ioctl`) between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if ctty_fd >= 0 && libc::ioctl(ctty_fd, libc::TIOCSCTTY, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        if let Stdin::Pipe(bytes) = stdin {
            let mut pipe = child.stdin.take().ok_or("no stdin")?;
            let _ = pipe.write_all(bytes);
        }
        let screen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        if let Some(master) = &master {
            let mut reader = master.try_clone()?;
            let screen = screen.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 256];
                // Poll, so that a hang-up can make this thread let go of its copy of the master.
                while !stop.load(Ordering::SeqCst) {
                    let mut fd = libc::pollfd {
                        fd: reader.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: one valid `pollfd`.
                    if unsafe { libc::poll(&raw mut fd, 1, 50) } <= 0 {
                        continue;
                    }
                    let Ok(n) = reader.read(&mut buf) else { break };
                    if n == 0 {
                        break;
                    }
                    screen
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend_from_slice(&buf[..n]);
                }
            });
        }
        Ok(Self {
            child,
            master,
            screen,
            stop,
            _slave: slave_keep,
        })
    }

    pub fn screen(&self) -> String {
        String::from_utf8_lossy(&self.screen.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned()
    }

    /// Waits until the terminal output holds `text`.
    pub fn wait_for(&mut self, text: &str) -> TestResult {
        let start = Instant::now();
        while !self.screen().contains(text) {
            if start.elapsed() > WAIT {
                return Err(format!("{text:?} never appeared; screen: {:?}", self.screen()).into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    pub fn send(&mut self, bytes: &[u8]) -> TestResult {
        let master = self.master.as_mut().ok_or("no terminal")?;
        master.write_all(bytes)?;
        Ok(())
    }

    /// Closes the master end: the terminal hangs up.
    pub fn hang_up(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.master = None;
        std::thread::sleep(Duration::from_millis(300));
    }

    pub fn finish(mut self) -> Result<Finished, Box<dyn Error>> {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if start.elapsed() > WAIT {
                let _ = self.child.kill();
                return Err(format!("did not exit; screen: {:?}", self.screen()).into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stdout.take() {
            pipe.read_to_string(&mut stdout)?;
        }
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr)?;
        }
        Ok(Finished {
            status,
            stdout,
            stderr,
        })
    }
}

pub fn delete_args(id: &str) -> [&str; 2] {
    ["delete", id]
}

pub fn message(failure: &ServiceFailure) -> String {
    format!("custodio: {failure}\n")
}
