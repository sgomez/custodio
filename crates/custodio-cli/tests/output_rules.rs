//! Colour and the shape of errors, proven by running the binary with pipes and with pseudo-terminals.

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};

use rustix::fs::{Mode, OFlags, open};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

type Res = Result<(), Box<dyn Error>>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stream {
    Pipe,
    Pty,
}

struct Ran {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// A pseudo-terminal: the master end and the slave end.
fn pty() -> Result<(File, File), Box<dyn Error>> {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let name = ptsname(&master, Vec::new())?;
    let slave: OwnedFd = open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY,
        Mode::empty(),
    )?;
    Ok((File::from(master), File::from(slave)))
}

/// What the terminal driver wrote: `\n` came out as `\r\n`.
fn drain(mut master: File) -> Vec<u8> {
    let mut all = Vec::new();
    // The read ends with an error (EIO) once the slave is closed and the data is read.
    let _ = master.read_to_end(&mut all);
    all.retain(|b| *b != b'\r');
    all
}

fn run(
    args: &[&str],
    out: Stream,
    err: Stream,
    no_color: Option<&str>,
) -> Result<Ran, Box<dyn Error>> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_custodio-cli"));
    cmd.args(args)
        .env("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/custodio")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null());
    if let Some(v) = no_color {
        cmd.env("NO_COLOR", v);
    }
    let mut masters = (None, None);
    match out {
        Stream::Pipe => {
            cmd.stdout(Stdio::piped());
        }
        Stream::Pty => {
            let (m, s) = pty()?;
            cmd.stdout(Stdio::from(s));
            masters.0 = Some(m);
        }
    }
    match err {
        Stream::Pipe => {
            cmd.stderr(Stdio::piped());
        }
        Stream::Pty => {
            let (m, s) = pty()?;
            cmd.stderr(Stdio::from(s));
            masters.1 = Some(m);
        }
    }
    let child = cmd.spawn()?;
    // The parent's copies of the slave ends are in `cmd`: drop it so the masters see the end.
    drop(cmd);
    let done = child.wait_with_output()?;
    Ok(Ran {
        status: done.status.code(),
        stdout: masters.0.map_or(done.stdout, drain),
        stderr: masters.1.map_or(done.stderr, drain),
    })
}

fn has_escape(bytes: &[u8]) -> bool {
    bytes.contains(&0x1b)
}

/// The text without the escape sequences of this tool (bold on and reset).
fn plain(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace("\u{1b}[1m", "")
        .replace("\u{1b}[0m", "")
}

const HELP: [&[&str]; 2] = [&["--help"], &["list", "--help"]];
const USAGE_ERROR: &[&str] = &["list", "extra", "more"];

#[test]
fn two_pipes_have_no_escape_sequence() -> Res {
    for args in HELP.iter().copied().chain([USAGE_ERROR]) {
        let ran = run(args, Stream::Pipe, Stream::Pipe, None)?;
        assert!(
            !has_escape(&ran.stdout) && !has_escape(&ran.stderr),
            "{args:?}"
        );
    }
    Ok(())
}

#[test]
fn a_terminal_without_no_color_gets_colour_and_the_same_words() -> Res {
    for no_color in [None, Some("")] {
        for args in HELP {
            let plain_run = run(args, Stream::Pipe, Stream::Pipe, None)?;
            let ran = run(args, Stream::Pty, Stream::Pty, no_color)?;
            assert_eq!(ran.status, Some(0));
            assert!(has_escape(&ran.stdout), "{args:?} {no_color:?}");
            assert_eq!(plain(&ran.stdout), plain(&plain_run.stdout), "{args:?}");
            assert_eq!(ran.stderr, b"" as &[u8]);
        }
        let plain_run = run(USAGE_ERROR, Stream::Pipe, Stream::Pipe, None)?;
        let ran = run(USAGE_ERROR, Stream::Pty, Stream::Pty, no_color)?;
        assert_eq!(ran.status, Some(2));
        assert!(has_escape(&ran.stderr), "{no_color:?}");
        assert_eq!(plain(&ran.stderr), plain(&plain_run.stderr));
        assert_eq!(ran.stdout, b"" as &[u8]);
    }
    Ok(())
}

#[test]
fn a_non_empty_no_color_turns_colour_off_whatever_its_value() -> Res {
    for value in ["1", "0", "x"] {
        for args in HELP.iter().copied().chain([USAGE_ERROR]) {
            let ran = run(args, Stream::Pty, Stream::Pty, Some(value))?;
            assert!(
                !has_escape(&ran.stdout) && !has_escape(&ran.stderr),
                "{args:?} {value}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_pipe_on_one_stream_decides_for_stderr_and_a_pipe_on_stdout_for_both() -> Res {
    // stdout a terminal, stderr a pipe: colour allowed on stdout only.
    let help = run(&["--help"], Stream::Pty, Stream::Pipe, None)?;
    assert!(has_escape(&help.stdout));
    let usage = run(USAGE_ERROR, Stream::Pty, Stream::Pipe, None)?;
    assert!(!has_escape(&usage.stderr));
    // stdout a pipe, stderr a terminal: no colour on either (acceptance 10).
    let usage = run(USAGE_ERROR, Stream::Pipe, Stream::Pty, None)?;
    assert_eq!(usage.status, Some(2));
    assert!(!has_escape(&usage.stdout) && !has_escape(&usage.stderr));
    let help = run(&["--help"], Stream::Pipe, Stream::Pty, None)?;
    assert!(!has_escape(&help.stdout) && !has_escape(&help.stderr));
    Ok(())
}

/// Every failing run is at least two lines on stderr, a status, and nothing on stdout.
#[test]
fn every_failing_command_prints_what_went_wrong_then_the_next_step() -> Res {
    let cases: [(&[&str], i32); 4] = [
        (&["frobnicate"], 2),
        (&["setup", "browsers", "enable", "--bogus"], 2),
        (&["delete", "some-key"], 1),
        (&["list"], 1),
    ];
    for (args, status) in cases {
        let ran = run(args, Stream::Pipe, Stream::Pipe, None)?;
        let err = String::from_utf8_lossy(&ran.stderr);
        assert_eq!(ran.status, Some(status), "{args:?}: {err}");
        assert_eq!(ran.stdout, b"" as &[u8], "{args:?}");
        assert!(err.lines().count() >= 2, "{args:?}: {err}");
        assert!(err.lines().all(|l| !l.trim().is_empty()), "{args:?}: {err}");
    }
    Ok(())
}
