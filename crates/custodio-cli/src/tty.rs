//! Password prompt on the controlling terminal (`/dev/tty`), with echo off.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};

use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use secrecy::SecretString;

use crate::{PasswordPrompt, read_secret_line};

/// Reads from `/dev/tty`, not from stdin, argv or the environment.
pub struct Terminal;

impl PasswordPrompt for Terminal {
    fn password(&mut self, prompt: &str) -> io::Result<SecretString> {
        prompt_on(
            &mut OpenOptions::new().read(true).write(true).open("/dev/tty")?,
            prompt,
        )
    }
}

/// Writes `prompt` to the terminal `tty`, reads one line with echo off and restores the settings.
fn prompt_on(tty: &mut File, prompt: &str) -> io::Result<SecretString> {
    let saved = tcgetattr(&*tty).map_err(io::Error::from)?;
    let mut silent = saved.clone();
    silent.local_modes.remove(LocalModes::ECHO);
    // Keep the newline echo so the cursor moves on after Enter.
    silent.local_modes.insert(LocalModes::ECHONL);
    tcsetattr(&*tty, OptionalActions::Flush, &silent).map_err(io::Error::from)?;
    let result = ask(tty, prompt);
    let restored = tcsetattr(&*tty, OptionalActions::Flush, &saved).map_err(io::Error::from);
    let password = result?;
    restored?;
    Ok(password)
}

fn ask(tty: &mut File, prompt: &str) -> io::Result<SecretString> {
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    read_secret_line(&mut BufReader::new(&*tty))
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;

    use rustix::fs::{Mode, OFlags, open};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use secrecy::ExposeSecret;

    use super::*;

    /// A pseudo-terminal: the master end and the slave end opened as a `File`.
    fn pty() -> (File, File) {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave: OwnedFd = open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .unwrap();
        (File::from(master), File::from(slave))
    }

    #[test]
    fn reads_a_line_with_echo_off_and_restores_the_terminal() {
        let (mut master, mut slave) = pty();
        let before = tcgetattr(&slave).unwrap().local_modes;
        assert!(before.contains(LocalModes::ECHO));
        let probe = slave.try_clone().unwrap();
        let user = std::thread::spawn(move || {
            let mut seen = [0u8; 8];
            master.read_exact(&mut seen).unwrap();
            let during = tcgetattr(&probe).unwrap().local_modes;
            master.write_all(b"hunter2\n").unwrap();
            // Whatever the terminal echoes back must not contain the password.
            let mut echoed = [0u8; 2];
            master.read_exact(&mut echoed).unwrap();
            (master, seen, during, echoed)
        });
        let password = prompt_on(&mut slave, "Pass: >>").unwrap();
        let (_master, seen, during, echoed) = user.join().unwrap();
        assert_eq!(password.expose_secret(), "hunter2");
        assert_eq!(&seen, b"Pass: >>");
        assert!(!during.contains(LocalModes::ECHO));
        assert_eq!(&echoed, b"\r\n");
        assert_eq!(tcgetattr(&slave).unwrap().local_modes, before);
    }

    #[test]
    fn a_closed_terminal_is_an_error_and_still_restores() {
        let (master, mut slave) = pty();
        drop(master);
        assert!(prompt_on(&mut slave, "Pass: ").is_err());
    }
}
