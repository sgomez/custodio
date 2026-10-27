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
mod tests;
